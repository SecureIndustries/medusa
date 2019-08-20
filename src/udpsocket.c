
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <errno.h>

#include "error.h"
#include "pool.h"
#include "queue.h"
#include "subject-struct.h"
#include "io.h"
#include "io-private.h"
#include "timer.h"
#include "timer-private.h"
#include "udpsocket.h"
#include "udpsocket-private.h"
#include "udpsocket-struct.h"
#include "monitor-private.h"

#define MIN(a, b)                               (((a) < (b)) ? (a) : (b))

#define MEDUSA_UDPSOCKET_USE_POOL               1

#define MEDUSA_UDPSOCKET_DEFAULT_IOVECS         4

enum {
        MEDUSA_UDPSOCKET_FLAG_NONE              = 0x00000000,
        MEDUSA_UDPSOCKET_FLAG_ENABLED           = 0x00000001,
        MEDUSA_UDPSOCKET_FLAG_NONBLOCKING       = 0x00000004,
        MEDUSA_UDPSOCKET_FLAG_REUSEADDR         = 0x00000010,
        MEDUSA_UDPSOCKET_FLAG_REUSEPORT         = 0x00000020,
#define MEDUSA_UDPSOCKET_FLAG_NONE              MEDUSA_UDPSOCKET_FLAG_NONE
#define MEDUSA_UDPSOCKET_FLAG_ENABLED           MEDUSA_UDPSOCKET_FLAG_ENABLED
#define MEDUSA_UDPSOCKET_FLAG_NONBLOCKING       MEDUSA_UDPSOCKET_FLAG_NONBLOCKING
#define MEDUSA_UDPSOCKET_FLAG_REUSEADDR         MEDUSA_UDPSOCKET_FLAG_REUSEADDR
#define MEDUSA_UDPSOCKET_FLAG_REUSEPORT         MEDUSA_UDPSOCKET_FLAG_REUSEPORT
};

#define MEDUSA_UDPSOCKET_FLAG_MASK              0x000000ff
#define MEDUSA_UDPSOCKET_FLAG_SHIFT             0x00000000

#define MEDUSA_UDPSOCKET_ERROR_MASK             0x00000fff
#define MEDUSA_UDPSOCKET_ERROR_SHIFT            0x00000008

#define MEDUSA_UDPSOCKET_STATE_MASK             0x000000ff
#define MEDUSA_UDPSOCKET_STATE_SHIFT            0x00000018

#if defined(MEDUSA_UDPSOCKET_USE_POOL) && (MEDUSA_UDPSOCKET_USE_POOL == 1)
static struct medusa_pool *g_pool;
#endif

static inline void udpsocket_set_flag (struct medusa_udpsocket *udpsocket, unsigned int flag)
{
        udpsocket->flags = (udpsocket->flags & ~(MEDUSA_UDPSOCKET_FLAG_MASK << MEDUSA_UDPSOCKET_FLAG_SHIFT)) |
                           ((flag & MEDUSA_UDPSOCKET_FLAG_MASK) << MEDUSA_UDPSOCKET_FLAG_SHIFT);
}

static inline void udpsocket_add_flag (struct medusa_udpsocket *udpsocket, unsigned int flag)
{
        udpsocket->flags |= ((flag & MEDUSA_UDPSOCKET_FLAG_MASK) << MEDUSA_UDPSOCKET_FLAG_SHIFT);
}

static inline void udpsocket_del_flag (struct medusa_udpsocket *udpsocket, unsigned int flag)
{
        udpsocket->flags &= ~((flag & MEDUSA_UDPSOCKET_FLAG_MASK) << MEDUSA_UDPSOCKET_FLAG_SHIFT);
}

static inline int udpsocket_has_flag (const struct medusa_udpsocket *udpsocket, unsigned int flag)
{
        return !!(udpsocket->flags & ((flag & MEDUSA_UDPSOCKET_FLAG_MASK) << MEDUSA_UDPSOCKET_FLAG_SHIFT));
}

static inline int udpsocket_get_error (const struct medusa_udpsocket *udpsocket)
{
        return (udpsocket->flags >> MEDUSA_UDPSOCKET_ERROR_SHIFT) & MEDUSA_UDPSOCKET_ERROR_MASK;
}

static inline int udpsocket_set_error (struct medusa_udpsocket *udpsocket, int error)
{
        if (error < 0) {
                error = -error;
        }
        if (error & ~MEDUSA_UDPSOCKET_ERROR_MASK) {
                error = EIO;
        }
        udpsocket->flags = (udpsocket->flags & ~(MEDUSA_UDPSOCKET_ERROR_MASK << MEDUSA_UDPSOCKET_ERROR_SHIFT)) |
                           ((error & MEDUSA_UDPSOCKET_ERROR_MASK) << MEDUSA_UDPSOCKET_ERROR_SHIFT);
        return 0;
}

static inline unsigned int udpsocket_get_state (const struct medusa_udpsocket *udpsocket)
{
        return (udpsocket->flags >> MEDUSA_UDPSOCKET_STATE_SHIFT) & MEDUSA_UDPSOCKET_STATE_MASK;
}

static inline int udpsocket_set_state (struct medusa_udpsocket *udpsocket, unsigned int state)
{
        int rc;
        udpsocket_set_error(udpsocket, 0);
        if (state == MEDUSA_UDPSOCKET_STATE_CONNECTING) {
                if (!MEDUSA_IS_ERR_OR_NULL(udpsocket->ctimer)) {
                        rc = medusa_timer_set_enabled_unlocked(udpsocket->ctimer, 1);
                        if (rc < 0) {
                                return rc;
                        }
                }
                if (!MEDUSA_IS_ERR_OR_NULL(udpsocket->rtimer)) {
                        rc = medusa_timer_set_enabled_unlocked(udpsocket->rtimer, 0);
                        if (rc < 0) {
                                return rc;
                        }
                }
        } else if (state == MEDUSA_UDPSOCKET_STATE_CONNECTED) {
                if (!MEDUSA_IS_ERR_OR_NULL(udpsocket->ctimer)) {
                        rc = medusa_timer_set_enabled_unlocked(udpsocket->ctimer, 0);
                        if (rc < 0) {
                                return rc;
                        }
                }
                if (!MEDUSA_IS_ERR_OR_NULL(udpsocket->rtimer)) {
                        rc = medusa_timer_set_enabled_unlocked(udpsocket->rtimer, 1);
                        if (rc < 0) {
                                return rc;
                        }
                }
        } else if (state == MEDUSA_UDPSOCKET_STATE_LISTENING) {
                if (!MEDUSA_IS_ERR_OR_NULL(udpsocket->ctimer)) {
                        rc = medusa_timer_set_enabled_unlocked(udpsocket->ctimer, 0);
                        if (rc < 0) {
                                return rc;
                        }
                }
                if (!MEDUSA_IS_ERR_OR_NULL(udpsocket->rtimer)) {
                        rc = medusa_timer_set_enabled_unlocked(udpsocket->rtimer, 0);
                        if (rc < 0) {
                                return rc;
                        }
                }
        } else if (state == MEDUSA_UDPSOCKET_STATE_DISCONNECTED) {
                if (!MEDUSA_IS_ERR_OR_NULL(udpsocket->ctimer)) {
                        rc = medusa_timer_set_enabled_unlocked(udpsocket->ctimer, 0);
                        if (rc < 0) {
                                return rc;
                        }
                }
                if (!MEDUSA_IS_ERR_OR_NULL(udpsocket->rtimer)) {
                        rc = medusa_timer_set_enabled_unlocked(udpsocket->rtimer, 0);
                        if (rc < 0) {
                                return rc;
                        }
                }
                if (!MEDUSA_IS_ERR_OR_NULL(udpsocket->io)) {
                        medusa_io_destroy_unlocked(udpsocket->io);
                        udpsocket->io = NULL;
                }
        }
        udpsocket->flags = (udpsocket->flags & ~(MEDUSA_UDPSOCKET_STATE_MASK << MEDUSA_UDPSOCKET_STATE_SHIFT)) |
                           ((state & MEDUSA_UDPSOCKET_STATE_MASK) << MEDUSA_UDPSOCKET_STATE_SHIFT);
        return 0;
}

static int udpsocket_ctimer_onevent (struct medusa_timer *timer, unsigned int events, void *context, ...)
{
        int rc;
        struct medusa_udpsocket *udpsocket = (struct medusa_udpsocket *) context;
        (void) timer;
        if (events & MEDUSA_TIMER_EVENT_TIMEOUT) {
                rc = udpsocket_set_state(udpsocket, MEDUSA_UDPSOCKET_STATE_DISCONNECTED);
                if (rc < 0) {
                        return rc;
                }
                return medusa_udpsocket_onevent(udpsocket, MEDUSA_UDPSOCKET_EVENT_CONNECT_TIMEOUT);
        }
        return 0;
}

static int udpsocket_rtimer_onevent (struct medusa_timer *timer, unsigned int events, void *context, ...)
{
        struct medusa_udpsocket *udpsocket = (struct medusa_udpsocket *) context;
        (void) timer;
        if (events & MEDUSA_TIMER_EVENT_TIMEOUT) {
                return medusa_udpsocket_onevent(udpsocket, MEDUSA_UDPSOCKET_EVENT_IN_TIMEOUT);
        }
        return 0;
}

static int udpsocket_io_onevent (struct medusa_io *io, unsigned int events, void *context, ...)
{
        int rc;
        struct medusa_monitor *monitor;
        struct medusa_udpsocket *udpsocket = context;

        monitor = medusa_io_get_monitor(io);
        medusa_monitor_lock(monitor);

        if (events & MEDUSA_IO_EVENT_OUT) {
                if (udpsocket_get_state(udpsocket) == MEDUSA_UDPSOCKET_STATE_DISCONNECTED) {
                } else if (udpsocket_get_state(udpsocket) == MEDUSA_UDPSOCKET_STATE_CONNECTING) {
                        int valopt;
                        socklen_t vallen;
                        vallen = sizeof(valopt);
                        rc = getsockopt(medusa_io_get_fd_unlocked(io), SOL_SOCKET, SO_ERROR, (void *) &valopt, &vallen);
                        if (rc < 0) {
                                goto bail;
                        }
                        if (valopt != 0) {
                                rc = udpsocket_set_state(udpsocket, MEDUSA_UDPSOCKET_STATE_DISCONNECTED);
                                if (rc < 0) {
                                        goto bail;
                                }
                                rc = udpsocket_set_error(udpsocket, valopt);
                                if (rc < 0) {
                                        goto bail;
                                }
                                rc = medusa_udpsocket_onevent_unlocked(udpsocket, MEDUSA_UDPSOCKET_EVENT_ERROR);
                                if (rc < 0) {
                                        goto bail;
                                }
                        } else {
                                rc = medusa_io_del_events_unlocked(io, MEDUSA_IO_EVENT_OUT);
                                if (rc < 0) {
                                        goto bail;
                                }
                                rc = udpsocket_set_state(udpsocket, MEDUSA_UDPSOCKET_STATE_CONNECTED);
                                if (rc < 0) {
                                        goto bail;
                                }
                                rc = medusa_udpsocket_onevent_unlocked(udpsocket, MEDUSA_UDPSOCKET_EVENT_CONNECTED);
                                if (rc < 0) {
                                        goto bail;
                                }
                        }
                } else if (udpsocket_get_state(udpsocket) == MEDUSA_UDPSOCKET_STATE_LISTENING) {
                        rc = medusa_udpsocket_onevent_unlocked(udpsocket, MEDUSA_UDPSOCKET_EVENT_OUT);
                        if (rc < 0) {
                                goto bail;
                        }
                } else if (udpsocket_get_state(udpsocket) == MEDUSA_UDPSOCKET_STATE_CONNECTED) {
                        rc = medusa_udpsocket_onevent_unlocked(udpsocket, MEDUSA_UDPSOCKET_EVENT_OUT);
                        if (rc < 0) {
                                goto bail;
                        }
                } else {
                        goto bail;
                }
        } else if (events & MEDUSA_IO_EVENT_IN) {
                if (udpsocket_get_state(udpsocket) == MEDUSA_UDPSOCKET_STATE_DISCONNECTED) {
                } else if (udpsocket_get_state(udpsocket) == MEDUSA_UDPSOCKET_STATE_LISTENING) {
                        if (!MEDUSA_IS_ERR_OR_NULL(udpsocket->rtimer)) {
                                double interval;
                                interval = medusa_timer_get_interval_unlocked(udpsocket->rtimer);
                                if (interval < 0) {
                                        goto bail;
                                }
                                rc = medusa_timer_set_interval_unlocked(udpsocket->rtimer, interval);
                                if (rc < 0) {
                                        goto bail;
                                }
                        }
                        rc = medusa_udpsocket_onevent_unlocked(udpsocket, MEDUSA_UDPSOCKET_EVENT_IN);
                        if (rc < 0) {
                                goto bail;
                        }
                } else if (udpsocket_get_state(udpsocket) == MEDUSA_UDPSOCKET_STATE_CONNECTED) {
                        if (!MEDUSA_IS_ERR_OR_NULL(udpsocket->rtimer)) {
                                double interval;
                                interval = medusa_timer_get_interval_unlocked(udpsocket->rtimer);
                                if (interval < 0) {
                                        goto bail;
                                }
                                rc = medusa_timer_set_interval_unlocked(udpsocket->rtimer, interval);
                                if (rc < 0) {
                                        goto bail;
                                }
                        }
                        rc = medusa_udpsocket_onevent_unlocked(udpsocket, MEDUSA_UDPSOCKET_EVENT_IN);
                        if (rc < 0) {
                                goto bail;
                        }
                } else {
                        goto bail;
                }
        } else if (events & (MEDUSA_IO_EVENT_ERR | MEDUSA_IO_EVENT_HUP)) {
                rc = udpsocket_set_state(udpsocket, MEDUSA_UDPSOCKET_STATE_DISCONNECTED);
                if (rc < 0) {
                        goto bail;
                }
                rc = udpsocket_set_error(udpsocket, EIO);
                if (rc < 0) {
                        goto bail;
                }
                rc = medusa_udpsocket_onevent_unlocked(udpsocket, MEDUSA_UDPSOCKET_EVENT_ERROR);
                if (rc < 0) {
                        goto bail;
                }
        } else if (events & MEDUSA_IO_EVENT_DESTROY) {
                int fd;
                fd = medusa_io_get_fd_unlocked(io);
                if (fd >= 0) {
                        close(fd);
                }
        }
        medusa_monitor_unlock(monitor);
        return 0;
bail:   medusa_monitor_unlock(monitor);
        return -EIO;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_init_options_default (struct medusa_udpsocket_init_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_udpsocket_init_options));
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_init_unlocked (struct medusa_udpsocket *udpsocket, struct medusa_monitor *monitor, int (*onevent) (struct medusa_udpsocket *udpsocket, unsigned int events, void *context, ...), void *context)
{
        int rc;
        struct medusa_udpsocket_init_options options;
        rc = medusa_udpsocket_init_options_default(&options);
        if (rc < 0) {
                return rc;
        }
        options.monitor = monitor;
        options.onevent = onevent;
        options.context = context;
        return medusa_udpsocket_init_with_options_unlocked(udpsocket, &options);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_init (struct medusa_udpsocket *udpsocket, struct medusa_monitor *monitor, int (*onevent) (struct medusa_udpsocket *udpsocket, unsigned int events, void *context, ...), void *context)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return -EINVAL;
        }
        medusa_monitor_lock(monitor);
        rc = medusa_udpsocket_init_unlocked(udpsocket, monitor, onevent, context);
        medusa_monitor_unlock(monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_init_with_options_unlocked (struct medusa_udpsocket *udpsocket, const struct medusa_udpsocket_init_options *options)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                return -EINVAL;
        }
        memset(udpsocket, 0, sizeof(struct medusa_udpsocket));
        medusa_subject_set_type(&udpsocket->subject, MEDUSA_SUBJECT_TYPE_UDPSOCKET);
        udpsocket->subject.monitor = NULL;
        udpsocket_set_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_NONE);
        rc = udpsocket_set_state(udpsocket, MEDUSA_UDPSOCKET_STATE_DISCONNECTED);
        if (rc < 0 ) {
                return rc;
        }
        udpsocket->onevent = options->onevent;
        udpsocket->context = options->context;
        rc = medusa_udpsocket_set_nonblocking_unlocked(udpsocket, options->nonblocking);
        if (rc < 0) {
                return rc;
        }
        rc = medusa_udpsocket_set_reuseaddr_unlocked(udpsocket, options->reuseaddr);
        if (rc < 0) {
                return rc;
        }
        rc = medusa_udpsocket_set_reuseport_unlocked(udpsocket, options->reuseport);
        if (rc < 0) {
                return rc;
        }
        rc = medusa_udpsocket_set_enabled_unlocked(udpsocket, options->enabled);
        if (rc < 0) {
                return rc;
        }
        rc = medusa_monitor_add_unlocked(options->monitor, &udpsocket->subject);
        if (rc < 0) {
                return rc;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_init_with_options (struct medusa_udpsocket *udpsocket, const struct medusa_udpsocket_init_options *options)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return -EINVAL;
        }
        medusa_monitor_lock(options->monitor);
        rc = medusa_udpsocket_init_with_options_unlocked(udpsocket, options);
        medusa_monitor_unlock(options->monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void medusa_udpsocket_uninit_unlocked (struct medusa_udpsocket *udpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return;
        }
        if (udpsocket->subject.monitor != NULL) {
                if (!MEDUSA_IS_ERR_OR_NULL(udpsocket->io)) {
                        medusa_io_destroy_unlocked(udpsocket->io);
                        udpsocket->io = NULL;
                }
                medusa_monitor_del_unlocked(&udpsocket->subject);
        } else {
                medusa_udpsocket_onevent_unlocked(udpsocket, MEDUSA_UDPSOCKET_EVENT_DESTROY);
        }
}

__attribute__ ((visibility ("default"))) void medusa_udpsocket_uninit (struct medusa_udpsocket *udpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        medusa_udpsocket_uninit_unlocked(udpsocket);
        medusa_monitor_unlock(udpsocket->subject.monitor);
}

__attribute__ ((visibility ("default"))) struct medusa_udpsocket * medusa_udpsocket_create_unlocked (struct medusa_monitor *monitor, int (*onevent) (struct medusa_udpsocket *udpsocket, unsigned int events, void *context, ...), void *context)
{
        int rc;
        struct medusa_udpsocket_init_options options;
        rc = medusa_udpsocket_init_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.monitor = monitor;
        options.onevent = onevent;
        options.context = context;
        return medusa_udpsocket_create_with_options_unlocked(&options);
}

__attribute__ ((visibility ("default"))) struct medusa_udpsocket * medusa_udpsocket_create (struct medusa_monitor *monitor, int (*onevent) (struct medusa_udpsocket *udpsocket, unsigned int events, void *context, ...), void *context)
{
        struct medusa_udpsocket *rc;
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(monitor);
        rc = medusa_udpsocket_create_unlocked(monitor, onevent, context);
        medusa_monitor_unlock(monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_udpsocket * medusa_udpsocket_create_with_options_unlocked (const struct medusa_udpsocket_init_options *options)
{
        int rc;
        struct medusa_udpsocket *udpsocket;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
#if defined(MEDUSA_UDPSOCKET_USE_POOL) && (MEDUSA_UDPSOCKET_USE_POOL == 1)
        udpsocket = medusa_pool_malloc(g_pool);
#else
        udpsocket = malloc(sizeof(struct medusa_udpsocket));
#endif
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(udpsocket, 0, sizeof(struct medusa_udpsocket));
        rc = medusa_udpsocket_init_with_options_unlocked(udpsocket, options);
        if (rc < 0) {
                medusa_udpsocket_destroy_unlocked(udpsocket);
                return MEDUSA_ERR_PTR(rc);
        }
        udpsocket->subject.flags |= MEDUSA_SUBJECT_FLAG_ALLOC;
        return udpsocket;
}

__attribute__ ((visibility ("default"))) struct medusa_udpsocket * medusa_udpsocket_create_with_options (const struct medusa_udpsocket_init_options *options)
{
        struct medusa_udpsocket *rc;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(options->monitor);
        rc = medusa_udpsocket_create_with_options_unlocked(options);
        medusa_monitor_unlock(options->monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void medusa_udpsocket_destroy_unlocked (struct medusa_udpsocket *udpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return;
        }
        medusa_udpsocket_uninit_unlocked(udpsocket);
}

__attribute__ ((visibility ("default"))) void medusa_udpsocket_destroy (struct medusa_udpsocket *udpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        medusa_udpsocket_destroy_unlocked(udpsocket);
        medusa_monitor_unlock(udpsocket->subject.monitor);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_get_state_unlocked (const struct medusa_udpsocket *udpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        return udpsocket_get_state(udpsocket);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_get_state (const struct medusa_udpsocket *udpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_get_state_unlocked(udpsocket);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_get_error_unlocked (const struct medusa_udpsocket *udpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        return udpsocket_get_error(udpsocket);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_get_error (const struct medusa_udpsocket *udpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_get_error_unlocked(udpsocket);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_set_enabled_unlocked (struct medusa_udpsocket *udpsocket, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        if (enabled) {
                udpsocket_add_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_ENABLED);
        } else {
                udpsocket_del_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_ENABLED);
        }
        if (!MEDUSA_IS_ERR_OR_NULL(udpsocket->io)) {
                rc = medusa_io_set_enabled_unlocked(udpsocket->io, enabled);
                if (rc < 0) {
                        return rc;
                }
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_set_enabled (struct medusa_udpsocket *udpsocket, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_set_enabled_unlocked(udpsocket, enabled);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_get_enabled_unlocked (const struct medusa_udpsocket *udpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        return udpsocket_has_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_ENABLED);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_get_enabled (const struct medusa_udpsocket *udpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_get_enabled_unlocked(udpsocket);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_enable (struct medusa_udpsocket *udpsocket)
{
        return medusa_udpsocket_set_enabled(udpsocket, 1);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_disable (struct medusa_udpsocket *udpsocket)
{
        return medusa_udpsocket_set_enabled(udpsocket, 0);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_set_nonblocking_unlocked (struct medusa_udpsocket *udpsocket, int enabled)
{
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        if (enabled) {
                udpsocket_add_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_NONBLOCKING);
        } else {
                udpsocket_del_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_NONBLOCKING);
        }
        if (!MEDUSA_IS_ERR_OR_NULL(udpsocket->io)) {
                int rc;
                int flags;
                flags = fcntl(medusa_io_get_fd_unlocked(udpsocket->io), F_GETFL, 0);
                if (flags < 0) {
                        return -errno;
                }
                flags = (udpsocket_has_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_NONBLOCKING)) ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
                rc = fcntl(medusa_io_get_fd_unlocked(udpsocket->io), F_SETFL, flags);
                if (rc != 0) {
                        return -errno;
                }
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_set_nonblocking (struct medusa_udpsocket *udpsocket, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_set_nonblocking_unlocked(udpsocket, enabled);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_get_nonblocking_unlocked (const struct medusa_udpsocket *udpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        return udpsocket_has_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_NONBLOCKING);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_get_nonblocking (const struct medusa_udpsocket *udpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_get_nonblocking_unlocked(udpsocket);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_set_reuseaddr_unlocked (struct medusa_udpsocket *udpsocket, int enabled)
{
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        if (enabled) {
                udpsocket_add_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_REUSEADDR);
        } else {
                udpsocket_del_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_REUSEADDR);
        }
        if (!MEDUSA_IS_ERR_OR_NULL(udpsocket->io)) {
                int rc;
                int on;
                on = !!enabled;
                rc = setsockopt(medusa_io_get_fd_unlocked(udpsocket->io), SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
                if (rc < 0) {
                        return -errno;
                }
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_set_reuseaddr (struct medusa_udpsocket *udpsocket, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_set_reuseaddr_unlocked(udpsocket, enabled);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_get_reuseaddr_unlocked (const struct medusa_udpsocket *udpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        return udpsocket_has_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_REUSEADDR);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_get_reuseaddr (const struct medusa_udpsocket *udpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_get_reuseaddr_unlocked(udpsocket);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_set_reuseport_unlocked (struct medusa_udpsocket *udpsocket, int enabled)
{
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        if (enabled) {
                udpsocket_add_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_REUSEPORT);
        } else {
                udpsocket_del_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_REUSEPORT);
        }
        if (!MEDUSA_IS_ERR_OR_NULL(udpsocket->io)) {
                int rc;
                int on;
                on = !!enabled;
                rc = setsockopt(medusa_io_get_fd_unlocked(udpsocket->io), SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
                if (rc < 0) {
                        return -errno;
                }
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_set_reuseport (struct medusa_udpsocket *udpsocket, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_set_reuseport_unlocked(udpsocket, enabled);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_get_reuseport_unlocked (const struct medusa_udpsocket *udpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        return udpsocket_has_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_REUSEPORT);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_get_reuseport (const struct medusa_udpsocket *udpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_get_reuseport_unlocked(udpsocket);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_set_read_timeout_unlocked (struct medusa_udpsocket *udpsocket, double timeout)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        if (timeout < 0) {
                if (!MEDUSA_IS_ERR_OR_NULL(udpsocket->rtimer)) {
                        medusa_timer_destroy(udpsocket->rtimer);
                        udpsocket->rtimer = NULL;
                }
        } else {
                if (MEDUSA_IS_ERR_OR_NULL(udpsocket->rtimer)) {
                        udpsocket->rtimer = medusa_timer_create_unlocked(udpsocket->subject.monitor, udpsocket_rtimer_onevent, udpsocket);
                        if (MEDUSA_IS_ERR_OR_NULL(udpsocket->rtimer)) {
                                return MEDUSA_PTR_ERR(udpsocket->rtimer);
                        }
                }
                rc = medusa_timer_set_interval_unlocked(udpsocket->rtimer, timeout);
                if (rc < 0) {
                        return rc;
                }
                rc = medusa_timer_set_singleshot_unlocked(udpsocket->rtimer, 1);
                if (rc < 0) {
                        return rc;
                }
                if (udpsocket_get_state(udpsocket) == MEDUSA_UDPSOCKET_STATE_CONNECTED) {
                        rc = medusa_timer_set_enabled_unlocked(udpsocket->rtimer, 1);
                        if (rc < 0) {
                                return rc;
                        }
                }
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_set_read_timeout (struct medusa_udpsocket *udpsocket, double timeout)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_set_read_timeout_unlocked(udpsocket, timeout);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) double medusa_udpsocket_get_read_timeout_unlocked (const struct medusa_udpsocket *udpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket->rtimer)) {
                return -EINVAL;
        }
        return medusa_timer_get_interval_unlocked(udpsocket->rtimer);
}

__attribute__ ((visibility ("default"))) double medusa_udpsocket_get_read_timeout (const struct medusa_udpsocket *udpsocket)
{
        double rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_get_read_timeout(udpsocket);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_set_connect_timeout_unlocked (struct medusa_udpsocket *udpsocket, double timeout)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        if (timeout < 0) {
                if (!MEDUSA_IS_ERR_OR_NULL(udpsocket->ctimer)) {
                        medusa_timer_destroy(udpsocket->ctimer);
                        udpsocket->ctimer = NULL;
                }
        } else {
                if (MEDUSA_IS_ERR_OR_NULL(udpsocket->ctimer)) {
                        udpsocket->ctimer = medusa_timer_create_unlocked(udpsocket->subject.monitor, udpsocket_ctimer_onevent, udpsocket);
                        if (MEDUSA_IS_ERR_OR_NULL(udpsocket->ctimer)) {
                                return MEDUSA_PTR_ERR(udpsocket->ctimer);
                        }
                }
                rc = medusa_timer_set_interval_unlocked(udpsocket->ctimer, timeout);
                if (rc < 0) {
                        return rc;
                }
                rc = medusa_timer_set_singleshot_unlocked(udpsocket->ctimer, 1);
                if (rc < 0) {
                        return rc;
                }
                if (udpsocket_get_state(udpsocket) == MEDUSA_UDPSOCKET_STATE_CONNECTING) {
                        rc = medusa_timer_set_enabled_unlocked(udpsocket->ctimer, 1);
                        if (rc < 0) {
                                return rc;
                        }
                }
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_set_connect_timeout (struct medusa_udpsocket *udpsocket, double timeout)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_set_connect_timeout_unlocked(udpsocket, timeout);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) double medusa_udpsocket_get_connect_timeout_unlocked (const struct medusa_udpsocket *udpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket->ctimer)) {
                return -EINVAL;
        }
        return medusa_timer_get_interval_unlocked(udpsocket->ctimer);
}

__attribute__ ((visibility ("default"))) double medusa_udpsocket_get_connect_timeout (const struct medusa_udpsocket *udpsocket)
{
        double rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_get_connect_timeout(udpsocket);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_get_fd_unlocked (const struct medusa_udpsocket *udpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        return medusa_io_get_fd_unlocked(udpsocket->io);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_get_fd (const struct medusa_udpsocket *udpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_get_fd_unlocked(udpsocket);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_set_events_unlocked (struct medusa_udpsocket *udpsocket, unsigned int events)
{
        unsigned int io_events;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket->io)) {
                return -EINVAL;
        }
        if ((udpsocket_get_state(udpsocket) != MEDUSA_UDPSOCKET_STATE_LISTENING) &&
            (udpsocket_get_state(udpsocket) != MEDUSA_UDPSOCKET_STATE_CONNECTED)) {
                return -EINVAL;
        }
        io_events = MEDUSA_IO_EVENT_NONE;
        if (events & MEDUSA_UDPSOCKET_EVENT_IN) {
                io_events |= MEDUSA_IO_EVENT_IN;
        }
        if (events & MEDUSA_UDPSOCKET_EVENT_OUT) {
                io_events |= MEDUSA_IO_EVENT_OUT;
        }
        return medusa_io_set_events_unlocked(udpsocket->io, io_events);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_set_events (struct medusa_udpsocket *udpsocket, unsigned int events)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_set_events_unlocked(udpsocket, events);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_add_events_unlocked (struct medusa_udpsocket *udpsocket, unsigned int events)
{
        unsigned int io_events;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket->io)) {
                return -EINVAL;
        }
        if ((udpsocket_get_state(udpsocket) != MEDUSA_UDPSOCKET_STATE_LISTENING) &&
            (udpsocket_get_state(udpsocket) != MEDUSA_UDPSOCKET_STATE_CONNECTED)) {
                return -EINVAL;
        }
        io_events = MEDUSA_IO_EVENT_NONE;
        if (events & MEDUSA_UDPSOCKET_EVENT_IN) {
                io_events |= MEDUSA_IO_EVENT_IN;
        }
        if (events & MEDUSA_UDPSOCKET_EVENT_OUT) {
                io_events |= MEDUSA_IO_EVENT_OUT;
        }
        return medusa_io_add_events_unlocked(udpsocket->io, io_events);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_add_events (struct medusa_udpsocket *udpsocket, unsigned int events)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_add_events_unlocked(udpsocket, events);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_del_events_unlocked (struct medusa_udpsocket *udpsocket, unsigned int events)
{
        unsigned int io_events;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket->io)) {
                return -EINVAL;
        }
        if ((udpsocket_get_state(udpsocket) != MEDUSA_UDPSOCKET_STATE_LISTENING) &&
            (udpsocket_get_state(udpsocket) != MEDUSA_UDPSOCKET_STATE_CONNECTED)) {
                return -EINVAL;
        }
        io_events = MEDUSA_IO_EVENT_NONE;
        if (events & MEDUSA_UDPSOCKET_EVENT_IN) {
                io_events |= MEDUSA_IO_EVENT_IN;
        }
        if (events & MEDUSA_UDPSOCKET_EVENT_OUT) {
                io_events |= MEDUSA_IO_EVENT_OUT;
        }
        return medusa_io_del_events_unlocked(udpsocket->io, io_events);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_del_events (struct medusa_udpsocket *udpsocket, unsigned int events)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_del_events_unlocked(udpsocket, events);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) unsigned int medusa_udpsocket_get_events_unlocked (const struct medusa_udpsocket *udpsocket)
{
        unsigned int events;
        unsigned int io_events;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket->io)) {
                return -EINVAL;
        }
        if ((udpsocket_get_state(udpsocket) != MEDUSA_UDPSOCKET_STATE_LISTENING) &&
            (udpsocket_get_state(udpsocket) != MEDUSA_UDPSOCKET_STATE_CONNECTED)) {
                return -EINVAL;
        }
        events = 0;
        io_events = medusa_io_get_events_unlocked(udpsocket->io);
        if (io_events & MEDUSA_IO_EVENT_IN) {
                events |= MEDUSA_UDPSOCKET_EVENT_IN;
        }
        if (io_events & MEDUSA_IO_EVENT_OUT) {
                events |= MEDUSA_UDPSOCKET_EVENT_OUT;
        }
        return events;
}

__attribute__ ((visibility ("default"))) unsigned int medusa_udpsocket_get_events (const struct medusa_udpsocket *udpsocket)
{
        unsigned int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_get_events_unlocked(udpsocket);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_bind_options_default (struct medusa_udpsocket_bind_options *options)
{
        if (options == NULL) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_udpsocket_bind_options));
        options->protocol = MEDUSA_UDPSOCKET_PROTOCOL_ANY;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_bind_with_options_unlocked (struct medusa_udpsocket *udpsocket, const struct medusa_udpsocket_bind_options *options)
{
        int rc;
        int fd;
        int ret;
        unsigned int protocol;
        const char *address;
        unsigned short port;
        unsigned int length;
        struct sockaddr *sockaddr;
        struct sockaddr_in sockaddr_in;
        struct sockaddr_in6 sockaddr_in6;
        struct medusa_io_init_options io_init_options;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        if (options == NULL) {
                return -EINVAL;
        }
        protocol = options->protocol;
        address  = options->address;
        port     = options->port;
        if (port == 0) {
                return -EINVAL;
        }
        if (udpsocket_get_state(udpsocket) != MEDUSA_UDPSOCKET_STATE_DISCONNECTED) {
                return -EIO;
        }
        if (medusa_io_get_fd_unlocked(udpsocket->io) >= 0) {
                return -EIO;
        }
        rc = udpsocket_set_state(udpsocket, MEDUSA_UDPSOCKET_STATE_BINDING);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_udpsocket_onevent_unlocked(udpsocket, MEDUSA_UDPSOCKET_EVENT_BINDING);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        if (protocol == MEDUSA_UDPSOCKET_PROTOCOL_IPV4) {
ipv4:
                sockaddr_in.sin_family = AF_INET;
                if (address == NULL) {
                        address = "0.0.0.0";
                } else if (strcmp(address, "localhost") == 0) {
                        address = "127.0.0.1";
                } else if (strcmp(address, "loopback") == 0) {
                        address = "127.0.0.1";
                }
                rc = inet_pton(AF_INET, address, &sockaddr_in.sin_addr);
                if (rc == 0) {
                        ret = -EINVAL;
                        goto bail;
                } else if (rc < 0) {
                        ret = -errno;
                        goto bail;
                }
                sockaddr_in.sin_port = htons(port);
                sockaddr = (struct sockaddr *) &sockaddr_in;
                length = sizeof(struct sockaddr_in);
        } else if (protocol == MEDUSA_UDPSOCKET_PROTOCOL_IPV6) {
ipv6:
                sockaddr_in6.sin6_family = AF_INET;
                if (address == NULL) {
                        address = "0.0.0.0";
                } else if (strcmp(address, "localhost") == 0) {
                        address = "127.0.0.1";
                } else if (strcmp(address, "loopback") == 0) {
                        address = "127.0.0.1";
                }
                rc = inet_pton(AF_INET6, address, &sockaddr_in6.sin6_addr);
                if (rc == 0) {
                        ret = -EINVAL;
                        goto bail;
                } else if (rc < 0) {
                        ret = -errno;
                        goto bail;
                }
                sockaddr_in6.sin6_port = htons(port);
                sockaddr = (struct sockaddr *) &sockaddr_in6;
                length = sizeof(struct sockaddr_in6);
        } else if (address == NULL) {
                address = "0.0.0.0";
                goto ipv4;
        } else if (strcmp(address, "localhost") == 0) {
                address = "127.0.0.1";
                goto ipv4;
        } else if (strcmp(address, "loopback") == 0) {
                address = "127.0.0.1";
                goto ipv4;
        } else {
                rc = inet_pton(AF_INET, address, &sockaddr_in.sin_addr);
                if (rc > 0) {
                        goto ipv4;
                }
                rc = inet_pton(AF_INET6, address, &sockaddr_in6.sin6_addr);
                if (rc > 0) {
                        goto ipv6;
                }
                ret = -EIO;
                goto bail;
        }
        fd = socket(sockaddr->sa_family, SOCK_DGRAM, 0);
        if (fd < 0) {
                ret = -errno;
                goto bail;
        }
        rc = medusa_io_init_options_default(&io_init_options);
        if (rc < 0) {
                close(fd);
                ret = rc;
                goto bail;
        }
        io_init_options.monitor = udpsocket->subject.monitor;
        io_init_options.fd      = fd;
        io_init_options.events  = MEDUSA_IO_EVENT_IN;
        io_init_options.onevent = udpsocket_io_onevent;
        io_init_options.context = udpsocket;
        io_init_options.enabled = udpsocket_has_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_ENABLED);
        udpsocket->io = medusa_io_create_with_options_unlocked(&io_init_options);
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket->io)) {
                ret = MEDUSA_PTR_ERR(udpsocket->io);
                goto bail;
        }
        {
                int rc;
                int flags;
                flags = fcntl(fd, F_GETFL, 0);
                if (flags < 0) {
                        ret = -errno;
                        goto bail;
                }
                flags = (udpsocket_has_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_NONBLOCKING)) ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
                rc = fcntl(fd, F_SETFL, flags);
                if (rc != 0) {
                        ret = -errno;
                        goto bail;
                }
        }
        {
                int rc;
                int on;
                on = udpsocket_has_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_REUSEADDR);
                rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
                if (rc < 0) {
                        ret = -errno;
                        goto bail;
                }
        }
        {
                int rc;
                int on;
                on = udpsocket_has_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_REUSEPORT);
                rc = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
                if (rc < 0) {
                        ret = -errno;
                        goto bail;
                }

        }
        rc = bind(fd, sockaddr , length);
        if (rc != 0) {
                ret = -errno;
                goto bail;
        }
        rc = udpsocket_set_state(udpsocket, MEDUSA_UDPSOCKET_STATE_BOUND);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_udpsocket_onevent_unlocked(udpsocket, MEDUSA_UDPSOCKET_EVENT_BOUND);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_io_set_events_unlocked(udpsocket->io, MEDUSA_IO_EVENT_IN);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = udpsocket_set_state(udpsocket, MEDUSA_UDPSOCKET_STATE_LISTENING);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_udpsocket_onevent_unlocked(udpsocket, MEDUSA_UDPSOCKET_EVENT_LISTENING);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        return 0;
bail:   udpsocket_set_state(udpsocket, MEDUSA_UDPSOCKET_STATE_DISCONNECTED);
        medusa_udpsocket_onevent_unlocked(udpsocket, MEDUSA_UDPSOCKET_EVENT_DISCONNECTED);
        return ret;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_bind_with_options (struct medusa_udpsocket *udpsocket, const struct medusa_udpsocket_bind_options *options)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_bind_with_options_unlocked(udpsocket, options);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_bind_unlocked (struct medusa_udpsocket *udpsocket, unsigned int protocol, const char *address, unsigned short port)
{
        int rc;
        struct medusa_udpsocket_bind_options options;
        rc = medusa_udpsocket_bind_options_default(&options);
        if (rc < 0) {
                return rc;
        }
        options.protocol = protocol;
        options.address  = address;
        options.port     = port;
        return medusa_udpsocket_bind_with_options_unlocked(udpsocket, &options);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_bind (struct medusa_udpsocket *udpsocket, unsigned int protocol, const char *address, unsigned short port)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_bind_unlocked(udpsocket, protocol, address, port);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_connect_options_default (struct medusa_udpsocket_connect_options *options)
{
        if (options == NULL) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_udpsocket_connect_options));
        options->protocol = MEDUSA_UDPSOCKET_PROTOCOL_ANY;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_connect_with_options_unlocked (struct medusa_udpsocket *udpsocket, const struct medusa_udpsocket_connect_options *options)
{
        int rc;
        int fd;
        int ret;
        unsigned int protocol;
        const char *address;
        unsigned short port;
        struct addrinfo hints;
        struct addrinfo *result;
        struct addrinfo *res;
        struct medusa_io_init_options io_init_options;
        result = NULL;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        if (options == NULL) {
                return -EINVAL;
        }
        protocol = options->protocol;
        address  = options->address;
        port     = options->port;
        if (address == NULL) {
                return -EINVAL;
        }
        if (port == 0) {
                return -EINVAL;
        }
        if (udpsocket_get_state(udpsocket) != MEDUSA_UDPSOCKET_STATE_DISCONNECTED) {
                return -EINVAL;
        }
        if (medusa_io_get_fd_unlocked(udpsocket->io) >= 0) {
                return -EINVAL;
        }
        rc = udpsocket_set_state(udpsocket, MEDUSA_UDPSOCKET_STATE_RESOLVING);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_udpsocket_onevent_unlocked(udpsocket, MEDUSA_UDPSOCKET_EVENT_RESOLVING);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        memset(&hints, 0, sizeof(struct addrinfo));
        if (protocol == MEDUSA_UDPSOCKET_PROTOCOL_IPV4) {
                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_DGRAM;
        } else if (protocol == MEDUSA_UDPSOCKET_PROTOCOL_IPV6) {
                hints.ai_family = AF_INET6;
                hints.ai_socktype = SOCK_DGRAM;
        } else {
                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_DGRAM;
        }
        rc = getaddrinfo(address, NULL, &hints, &result);
        if (rc != 0) {
                ret = -EIO;
                goto bail;
        }
        rc = udpsocket_set_state(udpsocket, MEDUSA_UDPSOCKET_STATE_RESOLVED);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_udpsocket_onevent_unlocked(udpsocket, MEDUSA_UDPSOCKET_EVENT_RESOLVED);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = udpsocket_set_state(udpsocket, MEDUSA_UDPSOCKET_STATE_CONNECTING);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_udpsocket_onevent_unlocked(udpsocket, MEDUSA_UDPSOCKET_EVENT_CONNECTING);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = -1;
        for (res = result; res; res = res->ai_next) {
                void *ptr;
                char str[INET6_ADDRSTRLEN];
                struct sockaddr_in *sockaddr_in;
                struct sockaddr_in6 *sockaddr_in6;
                switch (res->ai_family) {
                        case AF_INET:
                                sockaddr_in = (struct sockaddr_in *) res->ai_addr;
                                sockaddr_in->sin_port = htons(port);
                                ptr = &sockaddr_in->sin_addr;
                                break;
                        case AF_INET6:
                                sockaddr_in6 = (struct sockaddr_in6 *) res->ai_addr;
                                sockaddr_in6->sin6_port = htons(port);
                                ptr = &sockaddr_in6->sin6_addr;
                                break;
                        default:
                                ret = -EIO;
                                goto bail;
                }
                if (inet_ntop(res->ai_family, ptr, str, sizeof(str)) == NULL) {
                        continue;
                }
                fd = socket(res->ai_family, SOCK_DGRAM, 0);
                if (fd < 0) {
                        ret = -errno;
                        goto bail;
                }
                rc = medusa_io_init_options_default(&io_init_options);
                if (rc < 0) {
                        close(fd);
                        ret = rc;
                        goto bail;
                }
                io_init_options.monitor = udpsocket->subject.monitor;
                io_init_options.fd      = fd;
                io_init_options.events  = MEDUSA_IO_EVENT_IN;
                io_init_options.onevent = udpsocket_io_onevent;
                io_init_options.context = udpsocket;
                io_init_options.enabled = udpsocket_has_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_ENABLED);
                udpsocket->io = medusa_io_create_with_options_unlocked(&io_init_options);
                if (MEDUSA_IS_ERR_OR_NULL(udpsocket->io)) {
                        ret = MEDUSA_PTR_ERR(udpsocket->io);
                        goto bail;
                }
                {
                        int rc;
                        int flags;
                        flags = fcntl(fd, F_GETFL, 0);
                        if (flags < 0) {
                                ret = -errno;
                                goto bail;
                        }
                        flags = (udpsocket_has_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_NONBLOCKING)) ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
                        rc = fcntl(fd, F_SETFL, flags);
                        if (rc != 0) {
                                ret = -errno;
                                goto bail;
                        }
                }
                {
                        int rc;
                        int on;
                        on = udpsocket_has_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_REUSEADDR);
                        rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
                        if (rc < 0) {
                                ret = -errno;
                                goto bail;
                        }
                }
                {
                        int rc;
                        int on;
                        on = udpsocket_has_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_REUSEPORT);
                        rc = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
                        if (rc < 0) {
                                ret = -errno;
                                goto bail;
                        }

                }
                rc = connect(fd, res->ai_addr, res->ai_addrlen);
                if (rc != 0) {
                        if (errno != EINPROGRESS &&
                            errno != EALREADY) {
                                medusa_io_destroy_unlocked(udpsocket->io);
                                udpsocket->io = NULL;
                                continue;
                        } else {
                                rc = -errno;
                        }
                }
                break;
        }
        if ((res == NULL) ||
            (rc != 0 &&
             rc != -EINPROGRESS &&
             rc != -EALREADY)) {
                ret = rc;
                goto bail;
        }
        if (rc == 0) {
                rc = udpsocket_set_state(udpsocket, MEDUSA_UDPSOCKET_STATE_CONNECTED);
                if (rc < 0) {
                        ret = rc;
                        goto bail;
                }
                rc = medusa_udpsocket_onevent_unlocked(udpsocket, MEDUSA_UDPSOCKET_EVENT_CONNECTED);
                if (rc < 0) {
                        ret = rc;
                        goto bail;
                }
        } else {
                rc = medusa_io_add_events_unlocked(udpsocket->io, MEDUSA_IO_EVENT_OUT);
                if (rc < 0) {
                        ret = rc;
                        goto bail;
                }
        }
        freeaddrinfo(result);
        return 0;
bail:   if (result != NULL) {
                freeaddrinfo(result);
        }
        udpsocket_set_state(udpsocket, MEDUSA_UDPSOCKET_STATE_DISCONNECTED);
        medusa_udpsocket_onevent_unlocked(udpsocket, MEDUSA_UDPSOCKET_EVENT_DISCONNECTED);
        return ret;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_connect_with_options (struct medusa_udpsocket *udpsocket, const struct medusa_udpsocket_connect_options *options)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_connect_with_options_unlocked(udpsocket, options);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_connect_unlocked (struct medusa_udpsocket *udpsocket, unsigned int protocol, const char *address, unsigned short port)
{
        int rc;
        struct medusa_udpsocket_connect_options options;
        rc = medusa_udpsocket_connect_options_default(&options);
        if (rc < 0) {
                return rc;
        }
        options.protocol = protocol;
        options.address  = address;
        options.port     = port;
        return medusa_udpsocket_connect_with_options_unlocked(udpsocket, &options);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_connect (struct medusa_udpsocket *udpsocket, unsigned int protocol, const char *address, unsigned short port)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_connect_unlocked(udpsocket, protocol, address, port);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_attach_options_default (struct medusa_udpsocket_attach_options *options)
{
        if (options == NULL) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_udpsocket_attach_options));
        options->fd = -1;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_attach_with_options_unlocked (struct medusa_udpsocket *udpsocket, const struct medusa_udpsocket_attach_options *options)
{
        int rc;
        int fd;
        int ret;
        struct medusa_io_init_options io_init_options;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        if (options == NULL) {
                return -EINVAL;
        }
        fd = options->fd;
        if (fd < 0) {
                return -EINVAL;
        }
        if (udpsocket_get_state(udpsocket) != MEDUSA_UDPSOCKET_STATE_DISCONNECTED) {
                return -EINVAL;
        }
        if (medusa_io_get_fd_unlocked(udpsocket->io) >= 0) {
                return -EINVAL;
        }
        rc = medusa_io_init_options_default(&io_init_options);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        io_init_options.monitor = udpsocket->subject.monitor;
        io_init_options.fd      = fd;
        io_init_options.events  = MEDUSA_IO_EVENT_IN;
        io_init_options.onevent = udpsocket_io_onevent;
        io_init_options.context = udpsocket;
        io_init_options.enabled = udpsocket_has_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_ENABLED);
        udpsocket->io = medusa_io_create_with_options_unlocked(&io_init_options);
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket->io)) {
                ret = MEDUSA_PTR_ERR(udpsocket->io);
                goto bail;
        }
        {
                int rc;
                int flags;
                flags = fcntl(fd, F_GETFL, 0);
                if (flags < 0) {
                        ret = -errno;
                        goto bail;
                }
                flags = (udpsocket_has_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_NONBLOCKING)) ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
                rc = fcntl(fd, F_SETFL, flags);
                if (rc != 0) {
                        ret = -errno;
                        goto bail;
                }
        }
        {
                int rc;
                int on;
                on = udpsocket_has_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_REUSEADDR);
                rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
                if (rc < 0) {
                        ret = -errno;
                        goto bail;
                }
        }
        {
                int rc;
                int on;
                on = udpsocket_has_flag(udpsocket, MEDUSA_UDPSOCKET_FLAG_REUSEPORT);
                rc = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
                if (rc < 0) {
                        ret = -errno;
                        goto bail;
                }

        }
        rc = udpsocket_set_state(udpsocket, MEDUSA_UDPSOCKET_STATE_CONNECTED);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_udpsocket_onevent_unlocked(udpsocket, MEDUSA_UDPSOCKET_EVENT_CONNECTED);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        return 0;
bail:   udpsocket_set_state(udpsocket, MEDUSA_UDPSOCKET_STATE_DISCONNECTED);
        medusa_udpsocket_onevent_unlocked(udpsocket, MEDUSA_UDPSOCKET_EVENT_DISCONNECTED);
        return ret;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_attach_with_options (struct medusa_udpsocket *udpsocket, const struct medusa_udpsocket_attach_options *options)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_attach_with_options_unlocked(udpsocket, options);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_attach_unlocked (struct medusa_udpsocket *udpsocket, int fd)
{
        int rc;
        struct medusa_udpsocket_attach_options options;
        rc = medusa_udpsocket_attach_options_default(&options);
        if (rc < 0) {
                return rc;
        }
        options.fd = fd;
        return medusa_udpsocket_attach_with_options_unlocked(udpsocket, &options);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_attach (struct medusa_udpsocket *udpsocket, int fd)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_attach_unlocked(udpsocket, fd);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_onevent_unlocked (struct medusa_udpsocket *udpsocket, unsigned int events)
{
        int ret;
        struct medusa_monitor *monitor;
        ret = 0;
        monitor = udpsocket->subject.monitor;
        if (udpsocket->onevent != NULL) {
                if ((medusa_subject_is_active(&udpsocket->subject)) ||
                    (events & MEDUSA_UDPSOCKET_EVENT_DESTROY)) {
                        medusa_monitor_unlock(monitor);
                        ret = udpsocket->onevent(udpsocket, events, udpsocket->context);
                        medusa_monitor_lock(monitor);
                }
        }
        if (events & MEDUSA_UDPSOCKET_EVENT_DESTROY) {
                if (!MEDUSA_IS_ERR_OR_NULL(udpsocket->ctimer)) {
                        medusa_timer_destroy_unlocked(udpsocket->ctimer);
                        udpsocket->ctimer = NULL;
                }
                if (!MEDUSA_IS_ERR_OR_NULL(udpsocket->rtimer)) {
                        medusa_timer_destroy_unlocked(udpsocket->rtimer);
                        udpsocket->rtimer = NULL;
                }
                if (!MEDUSA_IS_ERR_OR_NULL(udpsocket->io)) {
                        medusa_io_destroy_unlocked(udpsocket->io);
                        udpsocket->io = NULL;
                }
                if (udpsocket->subject.flags & MEDUSA_SUBJECT_FLAG_ALLOC) {
#if defined(MEDUSA_UDPSOCKET_USE_POOL) && (MEDUSA_UDPSOCKET_USE_POOL == 1)
                        medusa_pool_free(udpsocket);
#else
                        free(udpsocket);
#endif
                } else {
                        memset(udpsocket, 0, sizeof(struct medusa_udpsocket));
                }
        }
        return ret;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_set_userdata_unlocked (struct medusa_udpsocket *udpsocket, void *userdata)
{
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        udpsocket->userdata = userdata;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_set_userdata (struct medusa_udpsocket *udpsocket, void *userdata)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_set_userdata_unlocked(udpsocket, userdata);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void * medusa_udpsocket_get_userdata_unlocked (struct medusa_udpsocket *udpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return udpsocket->userdata;
}

__attribute__ ((visibility ("default"))) void * medusa_udpsocket_get_userdata (struct medusa_udpsocket *udpsocket)
{
        void *rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_get_userdata_unlocked(udpsocket);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_set_userdata_ptr_unlocked (struct medusa_udpsocket *udpsocket, void *userdata)
{
        return medusa_udpsocket_set_userdata_unlocked(udpsocket, userdata);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_set_userdata_ptr (struct medusa_udpsocket *udpsocket, void *userdata)
{
        return medusa_udpsocket_set_userdata(udpsocket, userdata);
}

__attribute__ ((visibility ("default"))) void * medusa_udpsocket_get_userdata_ptr_unlocked (struct medusa_udpsocket *udpsocket)
{
        return medusa_udpsocket_get_userdata_unlocked(udpsocket);
}

__attribute__ ((visibility ("default"))) void * medusa_udpsocket_get_userdata_ptr (struct medusa_udpsocket *udpsocket)
{
        return medusa_udpsocket_get_userdata(udpsocket);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_set_userdata_int_unlocked (struct medusa_udpsocket *udpsocket, int userdata)
{
        return medusa_udpsocket_set_userdata_unlocked(udpsocket, (void *) (intptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_set_userdata_int (struct medusa_udpsocket *udpsocket, int userdata)
{
        return medusa_udpsocket_set_userdata(udpsocket, (void *) (intptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_get_userdata_int_unlocked (struct medusa_udpsocket *udpsocket)
{
        return (int) (intptr_t) medusa_udpsocket_get_userdata_unlocked(udpsocket);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_get_userdata_int (struct medusa_udpsocket *udpsocket)
{
        return (int) (intptr_t) medusa_udpsocket_get_userdata(udpsocket);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_set_userdata_uint_unlocked (struct medusa_udpsocket *udpsocket, unsigned int userdata)
{
        return medusa_udpsocket_set_userdata_unlocked(udpsocket, (void *) (uintptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_set_userdata_uint (struct medusa_udpsocket *udpsocket, unsigned int userdata)
{
        return medusa_udpsocket_set_userdata(udpsocket, (void *) (uintptr_t) userdata);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_udpsocket_get_userdata_uint_unlocked (struct medusa_udpsocket *udpsocket)
{
        return (unsigned int) (intptr_t) medusa_udpsocket_get_userdata_unlocked(udpsocket);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_udpsocket_get_userdata_uint (struct medusa_udpsocket *udpsocket)
{
        return (unsigned int) (uintptr_t) medusa_udpsocket_get_userdata(udpsocket);
}

__attribute__ ((visibility ("default"))) int medusa_udpsocket_onevent (struct medusa_udpsocket *udpsocket, unsigned int events)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_onevent_unlocked(udpsocket, events);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_udpsocket_get_monitor_unlocked (struct medusa_udpsocket *udpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return udpsocket->subject.monitor;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_udpsocket_get_monitor (struct medusa_udpsocket *udpsocket)
{
        struct medusa_monitor *rc;
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(udpsocket->subject.monitor);
        rc = medusa_udpsocket_get_monitor_unlocked(udpsocket);
        medusa_monitor_unlock(udpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) const char * medusa_udpsocket_state_string (unsigned int state)
{
        if (state == MEDUSA_UDPSOCKET_STATE_UNKNOWN)                    return "MEDUSA_UDPSOCKET_STATE_UNKNOWN";
        if (state == MEDUSA_UDPSOCKET_STATE_DISCONNECTED)               return "MEDUSA_UDPSOCKET_STATE_DISCONNECTED";
        if (state == MEDUSA_UDPSOCKET_STATE_BINDING)                    return "MEDUSA_UDPSOCKET_STATE_BINDING";
        if (state == MEDUSA_UDPSOCKET_STATE_BOUND)                      return "MEDUSA_UDPSOCKET_STATE_BOUND";
        if (state == MEDUSA_UDPSOCKET_STATE_LISTENING)                  return "MEDUSA_UDPSOCKET_STATE_LISTENING";
        if (state == MEDUSA_UDPSOCKET_STATE_RESOLVING)                  return "MEDUSA_UDPSOCKET_STATE_RESOLVING";
        if (state == MEDUSA_UDPSOCKET_STATE_RESOLVED)                   return "MEDUSA_UDPSOCKET_STATE_RESOLVED";
        if (state == MEDUSA_UDPSOCKET_STATE_CONNECTING)                 return "MEDUSA_UDPSOCKET_STATE_CONNECTING";
        if (state == MEDUSA_UDPSOCKET_STATE_CONNECTED)                  return "MEDUSA_UDPSOCKET_STATE_CONNECTED";
        return "MEDUSA_UDPSOCKET_STATE_UNKNOWN";
}

__attribute__ ((visibility ("default"))) const char * medusa_udpsocket_event_string (unsigned int events)
{
        if (events == MEDUSA_UDPSOCKET_EVENT_BINDING)                   return "MEDUSA_UDPSOCKET_EVENT_BINDING";
        if (events == MEDUSA_UDPSOCKET_EVENT_BOUND)                     return "MEDUSA_UDPSOCKET_EVENT_BOUND";
        if (events == MEDUSA_UDPSOCKET_EVENT_LISTENING)                 return "MEDUSA_UDPSOCKET_EVENT_LISTENING";
        if (events == MEDUSA_UDPSOCKET_EVENT_RESOLVING)                 return "MEDUSA_UDPSOCKET_EVENT_RESOLVING";
        if (events == MEDUSA_UDPSOCKET_EVENT_RESOLVE_TIMEOUT)           return "MEDUSA_UDPSOCKET_EVENT_RESOLVE_TIMEOUT";
        if (events == MEDUSA_UDPSOCKET_EVENT_RESOLVED)                  return "MEDUSA_UDPSOCKET_EVENT_RESOLVED";
        if (events == MEDUSA_UDPSOCKET_EVENT_CONNECTING)                return "MEDUSA_UDPSOCKET_EVENT_CONNECTING";
        if (events == MEDUSA_UDPSOCKET_EVENT_CONNECT_TIMEOUT)           return "MEDUSA_UDPSOCKET_EVENT_CONNECT_TIMEOUT";
        if (events == MEDUSA_UDPSOCKET_EVENT_CONNECTED)                 return "MEDUSA_UDPSOCKET_EVENT_CONNECTED";
        if (events == MEDUSA_UDPSOCKET_EVENT_IN)                        return "MEDUSA_UDPSOCKET_EVENT_IN";
        if (events == MEDUSA_UDPSOCKET_EVENT_IN_TIMEOUT)                return "MEDUSA_UDPSOCKET_EVENT_IN_TIMEOUT";
        if (events == MEDUSA_UDPSOCKET_EVENT_OUT)                       return "MEDUSA_UDPSOCKET_EVENT_OUT";
        if (events == MEDUSA_UDPSOCKET_EVENT_DISCONNECTED)              return "MEDUSA_UDPSOCKET_EVENT_DISCONNECTED";
        if (events == MEDUSA_UDPSOCKET_EVENT_ERROR)                     return "MEDUSA_UDPSOCKET_EVENT_ERROR";
        if (events == MEDUSA_UDPSOCKET_EVENT_DESTROY)                   return "MEDUSA_UDPSOCKET_EVENT_DESTROY";
        return "MEDUSA_UDPSOCKET_EVENT_UNKNOWN";
}

__attribute__ ((constructor)) static void udpsocket_constructor (void)
{
#if defined(MEDUSA_UDPSOCKET_USE_POOL) && (MEDUSA_UDPSOCKET_USE_POOL == 1)
        g_pool = medusa_pool_create("medusa-udpsocket", sizeof(struct medusa_udpsocket), 0, 0, MEDUSA_POOL_FLAG_DEFAULT | MEDUSA_POOL_FLAG_THREAD_SAFE, NULL, NULL, NULL);
#endif
}

__attribute__ ((destructor)) static void udpsocket_destructor (void)
{
#if defined(MEDUSA_UDPSOCKET_USE_POOL) && (MEDUSA_UDPSOCKET_USE_POOL == 1)
        if (g_pool != NULL) {
                medusa_pool_destroy(g_pool);
        }
#endif
}
