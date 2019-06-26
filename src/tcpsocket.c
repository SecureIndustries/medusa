
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
#include <netinet/tcp.h>
#include <netdb.h>
#include <errno.h>

#include "error.h"
#include "pool.h"
#include "queue.h"
#include "buffer.h"
#include "subject-struct.h"
#include "io.h"
#include "io-private.h"
#include "timer.h"
#include "timer-private.h"
#include "tcpsocket.h"
#include "tcpsocket-private.h"
#include "tcpsocket-struct.h"
#include "monitor-private.h"

#define MIN(a, b)                               (((a) < (b)) ? (a) : (b))

#define MEDUSA_TCPSOCKET_USE_POOL               1

#define MEDUSA_TCPSOCKET_DEFAULT_BACKLOG        128
#define MEDUSA_TCPSOCKET_DEFAULT_IOVECS         4

enum {
        MEDUSA_TCPSOCKET_FLAG_NONE              = 0x00000000,
        MEDUSA_TCPSOCKET_FLAG_ENABLED           = 0x00000001,
        MEDUSA_TCPSOCKET_FLAG_BUFFERED          = 0x00000002,
        MEDUSA_TCPSOCKET_FLAG_NONBLOCKING       = 0x00000004,
        MEDUSA_TCPSOCKET_FLAG_NODELAY           = 0x00000008,
        MEDUSA_TCPSOCKET_FLAG_REUSEADDR         = 0x00000010,
        MEDUSA_TCPSOCKET_FLAG_REUSEPORT         = 0x00000020,
        MEDUSA_TCPSOCKET_FLAG_BACKLOG           = 0x00000040
#define MEDUSA_TCPSOCKET_FLAG_NONE              MEDUSA_TCPSOCKET_FLAG_NONE
#define MEDUSA_TCPSOCKET_FLAG_ENABLED           MEDUSA_TCPSOCKET_FLAG_ENABLED
#define MEDUSA_TCPSOCKET_FLAG_BUFFERED          MEDUSA_TCPSOCKET_FLAG_BUFFERED
#define MEDUSA_TCPSOCKET_FLAG_NONBLOCKING       MEDUSA_TCPSOCKET_FLAG_NONBLOCKING
#define MEDUSA_TCPSOCKET_FLAG_NODELAY           MEDUSA_TCPSOCKET_FLAG_NODELAY
#define MEDUSA_TCPSOCKET_FLAG_REUSEADDR         MEDUSA_TCPSOCKET_FLAG_REUSEADDR
#define MEDUSA_TCPSOCKET_FLAG_REUSEPORT         MEDUSA_TCPSOCKET_FLAG_REUSEPORT
#define MEDUSA_TCPSOCKET_FLAG_BACKLOG           MEDUSA_TCPSOCKET_FLAG_BACKLOG
};

#define MEDUSA_TCPSOCKET_FLAG_MASK              0x000000ff
#define MEDUSA_TCPSOCKET_FLAG_SHIFT             0x00000000

#define MEDUSA_TCPSOCKET_ERROR_MASK             0x00000fff
#define MEDUSA_TCPSOCKET_ERROR_SHIFT            0x00000008

#define MEDUSA_TCPSOCKET_STATE_MASK             0x000000ff
#define MEDUSA_TCPSOCKET_STATE_SHIFT            0x00000018

#if defined(MEDUSA_TCPSOCKET_USE_POOL) && (MEDUSA_TCPSOCKET_USE_POOL == 1)
static struct medusa_pool *g_pool;
#endif

static inline void tcpsocket_set_flag (struct medusa_tcpsocket *tcpsocket, unsigned int flag)
{
        tcpsocket->flags = (tcpsocket->flags & ~(MEDUSA_TCPSOCKET_FLAG_MASK << MEDUSA_TCPSOCKET_FLAG_SHIFT)) |
                           ((flag & MEDUSA_TCPSOCKET_FLAG_MASK) << MEDUSA_TCPSOCKET_FLAG_SHIFT);
}

static inline void tcpsocket_add_flag (struct medusa_tcpsocket *tcpsocket, unsigned int flag)
{
        tcpsocket->flags |= ((flag & MEDUSA_TCPSOCKET_FLAG_MASK) << MEDUSA_TCPSOCKET_FLAG_SHIFT);
}

static inline void tcpsocket_del_flag (struct medusa_tcpsocket *tcpsocket, unsigned int flag)
{
        tcpsocket->flags &= ~((flag & MEDUSA_TCPSOCKET_FLAG_MASK) << MEDUSA_TCPSOCKET_FLAG_SHIFT);
}

static inline int tcpsocket_has_flag (const struct medusa_tcpsocket *tcpsocket, unsigned int flag)
{
        return !!(tcpsocket->flags & ((flag & MEDUSA_TCPSOCKET_FLAG_MASK) << MEDUSA_TCPSOCKET_FLAG_SHIFT));
}

static inline unsigned int tcpsocket_get_buffered (const struct medusa_tcpsocket *tcpsocket)
{
        return tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_BUFFERED);
}

static inline int tcpsocket_get_error (const struct medusa_tcpsocket *tcpsocket)
{
        return (tcpsocket->flags >> MEDUSA_TCPSOCKET_ERROR_SHIFT) & MEDUSA_TCPSOCKET_ERROR_MASK;
}

static inline int tcpsocket_set_error (struct medusa_tcpsocket *tcpsocket, int error)
{
        if (error < 0) {
                error = -error;
        }
        if (error & ~MEDUSA_TCPSOCKET_ERROR_MASK) {
                error = EIO;
        }
        tcpsocket->flags = (tcpsocket->flags & ~(MEDUSA_TCPSOCKET_ERROR_MASK << MEDUSA_TCPSOCKET_ERROR_SHIFT)) |
                           ((error & MEDUSA_TCPSOCKET_ERROR_MASK) << MEDUSA_TCPSOCKET_ERROR_SHIFT);
        return 0;
}

static inline unsigned int tcpsocket_get_state (const struct medusa_tcpsocket *tcpsocket)
{
        return (tcpsocket->flags >> MEDUSA_TCPSOCKET_STATE_SHIFT) & MEDUSA_TCPSOCKET_STATE_MASK;
}

static inline int tcpsocket_set_state (struct medusa_tcpsocket *tcpsocket, unsigned int state)
{
        int rc;
        tcpsocket_set_error(tcpsocket, 0);
        if (state == MEDUSA_TCPSOCKET_STATE_CONNECTING) {
                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->ctimer)) {
                        rc = medusa_timer_set_enabled_unlocked(tcpsocket->ctimer, 1);
                        if (rc < 0) {
                                return rc;
                        }
                }
                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->rtimer)) {
                        rc = medusa_timer_set_enabled_unlocked(tcpsocket->rtimer, 0);
                        if (rc < 0) {
                                return rc;
                        }
                }
        } else if (state == MEDUSA_TCPSOCKET_STATE_CONNECTED) {
                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->ctimer)) {
                        rc = medusa_timer_set_enabled_unlocked(tcpsocket->ctimer, 0);
                        if (rc < 0) {
                                return rc;
                        }
                }
                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->rtimer)) {
                        rc = medusa_timer_set_enabled_unlocked(tcpsocket->rtimer, 1);
                        if (rc < 0) {
                                return rc;
                        }
                }
        } else if (state == MEDUSA_TCPSOCKET_STATE_LISTENING) {
                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->ctimer)) {
                        rc = medusa_timer_set_enabled_unlocked(tcpsocket->ctimer, 0);
                        if (rc < 0) {
                                return rc;
                        }
                }
                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->rtimer)) {
                        rc = medusa_timer_set_enabled_unlocked(tcpsocket->rtimer, 0);
                        if (rc < 0) {
                                return rc;
                        }
                }
        } else if (state == MEDUSA_TCPSOCKET_STATE_DISCONNECTED) {
                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->ctimer)) {
                        rc = medusa_timer_set_enabled_unlocked(tcpsocket->ctimer, 0);
                        if (rc < 0) {
                                return rc;
                        }
                }
                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->rtimer)) {
                        rc = medusa_timer_set_enabled_unlocked(tcpsocket->rtimer, 0);
                        if (rc < 0) {
                                return rc;
                        }
                }
                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                        medusa_io_destroy_unlocked(tcpsocket->io);
                        tcpsocket->io = NULL;
                }
        }
        tcpsocket->flags = (tcpsocket->flags & ~(MEDUSA_TCPSOCKET_STATE_MASK << MEDUSA_TCPSOCKET_STATE_SHIFT)) |
                           ((state & MEDUSA_TCPSOCKET_STATE_MASK) << MEDUSA_TCPSOCKET_STATE_SHIFT);
        return 0;
}

static int tcpsocket_ctimer_onevent (struct medusa_timer *timer, unsigned int events, void *context, ...)
{
        int rc;
        struct medusa_tcpsocket *tcpsocket = (struct medusa_tcpsocket *) context;
        (void) timer;
        if (events & MEDUSA_TIMER_EVENT_TIMEOUT) {
                rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                if (rc < 0) {
                        return rc;
                }
                return medusa_tcpsocket_onevent(tcpsocket, MEDUSA_TCPSOCKET_EVENT_CONNECT_TIMEOUT);
        }
        return 0;
}

static int tcpsocket_rtimer_onevent (struct medusa_timer *timer, unsigned int events, void *context, ...)
{
        struct medusa_tcpsocket *tcpsocket = (struct medusa_tcpsocket *) context;
        (void) timer;
        if (events & MEDUSA_TIMER_EVENT_TIMEOUT) {
                return medusa_tcpsocket_onevent(tcpsocket, MEDUSA_TCPSOCKET_EVENT_BUFFERED_READ_TIMEOUT);
        }
        return 0;
}

static int tcpsocket_wbuffer_commit (struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->wbuffer)) {
                return -EINVAL;
        }
        if (tcpsocket_get_buffered(tcpsocket) <= 0) {
                return -EINVAL;
        }
        if ((tcpsocket_get_state(tcpsocket) == MEDUSA_TCPSOCKET_STATE_CONNECTED) &&
            (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->io))) {
                int rc;
                int64_t blength;
                blength = medusa_buffer_get_length(tcpsocket->wbuffer);
                if (blength < 0) {
                        return blength;
                } else if (blength == 0) {
                        rc = medusa_io_del_events_unlocked(tcpsocket->io, MEDUSA_IO_EVENT_OUT);
                        if (rc < 0) {
                                return rc;
                        }
                } else {
                        rc = medusa_io_add_events_unlocked(tcpsocket->io, MEDUSA_IO_EVENT_OUT);
                        if (rc < 0) {
                                return rc;
                        }
                }
                rc = medusa_io_add_events_unlocked(tcpsocket->io, MEDUSA_IO_EVENT_IN);
                if (rc < 0) {
                        return rc;
                }
        }
        return 0;
}

static int tcpsocket_wbuffer_onevent (struct medusa_buffer *buffer, unsigned int events, void *context, ...)
{
        struct medusa_tcpsocket *tcpsocket = (struct medusa_tcpsocket *) context;
        (void) buffer;
        if (events & MEDUSA_BUFFER_EVENT_WRITE) {
                return tcpsocket_wbuffer_commit(tcpsocket);
        }
        return 0;
}

static int tcpsocket_io_onevent (struct medusa_io *io, unsigned int events, void *context, ...)
{
        int rc;
        struct medusa_monitor *monitor;
        struct medusa_tcpsocket *tcpsocket = context;

        monitor = medusa_io_get_monitor(io);
        medusa_monitor_lock(monitor);

        if (events & MEDUSA_IO_EVENT_OUT) {
                if (tcpsocket_get_state(tcpsocket) == MEDUSA_TCPSOCKET_STATE_DISCONNECTED) {
                } else if (tcpsocket_get_state(tcpsocket) == MEDUSA_TCPSOCKET_STATE_CONNECTING) {
                        int valopt;
                        socklen_t vallen;
                        vallen = sizeof(valopt);
                        rc = getsockopt(medusa_io_get_fd_unlocked(io), SOL_SOCKET, SO_ERROR, (void *) &valopt, &vallen);
                        if (rc < 0) {
                                goto bail;
                        }
                        if (valopt != 0) {
                                rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                                if (rc < 0) {
                                        goto bail;
                                }
                                rc = tcpsocket_set_error(tcpsocket, valopt);
                                if (rc < 0) {
                                        goto bail;
                                }
                                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_ERROR);
                                if (rc < 0) {
                                        goto bail;
                                }
                        } else {
                                rc = medusa_io_del_events_unlocked(io, MEDUSA_IO_EVENT_OUT);
                                if (rc < 0) {
                                        goto bail;
                                }
                                rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_CONNECTED);
                                if (rc < 0) {
                                        goto bail;
                                }
                                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_CONNECTED);
                                if (rc < 0) {
                                        goto bail;
                                }
                        }
                } else if (tcpsocket_get_state(tcpsocket) == MEDUSA_TCPSOCKET_STATE_CONNECTED) {
                        if (!tcpsocket_get_buffered(tcpsocket)) {
                                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_OUT);
                                if (rc < 0) {
                                        goto bail;
                                }
                        } else {
                                int64_t blength;
                                int64_t wlength;
                                int64_t clength;
                                int64_t niovecs;
                                struct iovec iovec;
                                while (1) {
                                        niovecs = medusa_buffer_queryv(tcpsocket->wbuffer, 0, -1, &iovec, 1);
                                        if (niovecs < 0) {
                                                goto bail;
                                        }
                                        if (niovecs == 0) {
                                                break;
                                        }
                                        wlength = send(medusa_io_get_fd_unlocked(io), iovec.iov_base, iovec.iov_len, 0);
                                        if (wlength < 0) {
                                                if (errno == EINTR) {
                                                        break;
                                                } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                                        break;
                                                } else if (errno == ECONNRESET) {
                                                        rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DISCONNECTED);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                        break;
                                                } else if (errno == ETIMEDOUT) {
                                                        rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                        rc = tcpsocket_set_error(tcpsocket, errno);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_ERROR);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                        break;
                                                } else {
                                                        goto bail;
                                                }
                                        } else if (wlength == 0) {
                                                rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                                                if (rc < 0) {
                                                        goto bail;
                                                }
                                                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DISCONNECTED);
                                                if (rc < 0) {
                                                        goto bail;
                                                }
                                                break;
                                        } else {
                                                clength = medusa_buffer_choke(tcpsocket->wbuffer, 0, wlength);
                                                if (clength < 0) {
                                                        goto bail;
                                                }
                                                if (clength != wlength) {
                                                        goto bail;
                                                }
                                                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_BUFFERED_WRITE);
                                                if (rc < 0) {
                                                        goto bail;
                                                }
                                        }
                                        break;
                                }
                                blength = medusa_buffer_get_length(tcpsocket->wbuffer);
                                if (blength < 0) {
                                        goto bail;
                                }
                                if (blength == 0) {
                                        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_BUFFERED_WRITE_FINISHED);
                                        if (rc < 0) {
                                                goto bail;
                                        }
                                }
                        }
                } else {
                        goto bail;
                }
        } else if (events & MEDUSA_IO_EVENT_IN) {
                if (tcpsocket_get_state(tcpsocket) == MEDUSA_TCPSOCKET_STATE_DISCONNECTED) {
                } else if (tcpsocket_get_state(tcpsocket) == MEDUSA_TCPSOCKET_STATE_LISTENING) {
                        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_CONNECTION);
                        if (rc < 0) {
                                goto bail;
                        }
                } else if (tcpsocket_get_state(tcpsocket) == MEDUSA_TCPSOCKET_STATE_CONNECTED) {
                        if (!tcpsocket_get_buffered(tcpsocket)) {
                                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->rtimer)) {
                                        double interval;
                                        interval = medusa_timer_get_interval_unlocked(tcpsocket->rtimer);
                                        if (interval < 0) {
                                                goto bail;
                                        }
                                        rc = medusa_timer_set_interval_unlocked(tcpsocket->rtimer, interval);
                                        if (rc < 0) {
                                                goto bail;
                                        }
                                }
                                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_IN);
                                if (rc < 0) {
                                        goto bail;
                                }
                        } else {
                                int n;
                                int64_t clength;
                                int64_t niovecs;
                                struct iovec iovec;
                                n = 4096;
                                rc = ioctl(medusa_io_get_fd_unlocked(io), FIONREAD, &n);
                                if (rc < 0) {
                                        n = 4096;
                                }
                                if (n < 0) {
                                        goto bail;
                                }
                                while (1) {
                                        niovecs = medusa_buffer_reservev(tcpsocket->rbuffer, n, &iovec, 1);
                                        if (niovecs < 0) {
                                                goto bail;
                                        }
                                        if (niovecs == 0) {
                                                if (n == 0) {
                                                        rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DISCONNECTED);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                } else {
                                                        rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                        rc = tcpsocket_set_error(tcpsocket, EIO);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_ERROR);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                }
                                                break;
                                        }
                                        rc = recv(medusa_io_get_fd_unlocked(io), iovec.iov_base, iovec.iov_len, 0);
                                        if (rc < 0) {
                                                if (errno == EINTR) {
                                                        break;
                                                } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                                        break;
                                                } else if (errno == ECONNRESET) {
                                                        rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DISCONNECTED);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                        break;
                                                } else if (errno == ECONNREFUSED || errno == ETIMEDOUT) {
                                                        rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                        rc = tcpsocket_set_error(tcpsocket, errno);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_ERROR);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                        break;
                                                } else {
                                                        goto bail;
                                                }
                                        } else if (rc == 0) {
                                                rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                                                if (rc < 0) {
                                                        goto bail;
                                                }
                                                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DISCONNECTED);
                                                if (rc < 0) {
                                                        goto bail;
                                                }
                                                break;
                                        } else {
                                                iovec.iov_len = rc;
                                                clength = medusa_buffer_commitv(tcpsocket->rbuffer, &iovec, 1);
                                                if (clength < 0) {
                                                        goto bail;
                                                }
                                                if (clength != 1) {
                                                        goto bail;
                                                }
                                                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->rtimer)) {
                                                        double interval;
                                                        interval = medusa_timer_get_interval_unlocked(tcpsocket->rtimer);
                                                        if (interval < 0) {
                                                                goto bail;
                                                        }
                                                        rc = medusa_timer_set_interval_unlocked(tcpsocket->rtimer, interval);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                }
                                                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_BUFFERED_READ);
                                                if (rc < 0) {
                                                        goto bail;
                                                }
                                        }
                                        break;
                                 }
                        }
                } else {
                        goto bail;
                }
        } else if (events & (MEDUSA_IO_EVENT_ERR | MEDUSA_IO_EVENT_HUP)) {
                rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                if (rc < 0) {
                        goto bail;
                }
                rc = tcpsocket_set_error(tcpsocket, EIO);
                if (rc < 0) {
                        goto bail;
                }
                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_ERROR);
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

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_init_options_default (struct medusa_tcpsocket_init_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_tcpsocket_init_options));
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_init_unlocked (struct medusa_tcpsocket *tcpsocket, struct medusa_monitor *monitor, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...), void *context)
{
        int rc;
        struct medusa_tcpsocket_init_options options;
        rc = medusa_tcpsocket_init_options_default(&options);
        if (rc < 0) {
                return rc;
        }
        options.monitor = monitor;
        options.onevent = onevent;
        options.context = context;
        return medusa_tcpsocket_init_with_options_unlocked(tcpsocket, &options);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_init (struct medusa_tcpsocket *tcpsocket, struct medusa_monitor *monitor, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...), void *context)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return -EINVAL;
        }
        medusa_monitor_lock(monitor);
        rc = medusa_tcpsocket_init_unlocked(tcpsocket, monitor, onevent, context);
        medusa_monitor_unlock(monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_init_with_options_unlocked (struct medusa_tcpsocket *tcpsocket, const struct medusa_tcpsocket_init_options *options)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
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
        memset(tcpsocket, 0, sizeof(struct medusa_tcpsocket));
        medusa_subject_set_type(&tcpsocket->subject, MEDUSA_SUBJECT_TYPE_TCPSOCKET);
        tcpsocket->subject.monitor = NULL;
        tcpsocket_set_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_NONE);
        rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
        if (rc < 0 ) {
                return rc;
        }
        tcpsocket->onevent = options->onevent;
        tcpsocket->context = options->context;
        rc = medusa_tcpsocket_set_nonblocking_unlocked(tcpsocket, options->nonblocking);
        if (rc < 0) {
                return rc;
        }
        rc = medusa_tcpsocket_set_nodelay_unlocked(tcpsocket, options->nodelay);
        if (rc < 0) {
                return rc;
        }
        rc = medusa_tcpsocket_set_reuseaddr_unlocked(tcpsocket, options->reuseaddr);
        if (rc < 0) {
                return rc;
        }
        rc = medusa_tcpsocket_set_reuseport_unlocked(tcpsocket, options->reuseport);
        if (rc < 0) {
                return rc;
        }
        rc = medusa_tcpsocket_set_backlog_unlocked(tcpsocket, options->backlog);
        if (rc < 0) {
                return rc;
        }
        rc = medusa_tcpsocket_set_buffered_unlocked(tcpsocket, options->buffered);
        if (rc < 0) {
                return rc;
        }
        rc = medusa_tcpsocket_set_enabled_unlocked(tcpsocket, options->enabled);
        if (rc < 0) {
                return rc;
        }
        rc = medusa_monitor_add_unlocked(options->monitor, &tcpsocket->subject);
        if (rc < 0) {
                return rc;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_init_with_options (struct medusa_tcpsocket *tcpsocket, const struct medusa_tcpsocket_init_options *options)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return -EINVAL;
        }
        medusa_monitor_lock(options->monitor);
        rc = medusa_tcpsocket_init_with_options_unlocked(tcpsocket, options);
        medusa_monitor_unlock(options->monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void medusa_tcpsocket_uninit_unlocked (struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return;
        }
        if (tcpsocket->subject.monitor != NULL) {
                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                        medusa_io_destroy_unlocked(tcpsocket->io);
                        tcpsocket->io = NULL;
                }
                medusa_monitor_del_unlocked(&tcpsocket->subject);
        } else {
                medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DESTROY);
        }
}

__attribute__ ((visibility ("default"))) void medusa_tcpsocket_uninit (struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        medusa_tcpsocket_uninit_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_create_unlocked (struct medusa_monitor *monitor, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...), void *context)
{
        int rc;
        struct medusa_tcpsocket_init_options options;
        rc = medusa_tcpsocket_init_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.monitor = monitor;
        options.onevent = onevent;
        options.context = context;
        return medusa_tcpsocket_create_with_options_unlocked(&options);
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_create (struct medusa_monitor *monitor, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...), void *context)
{
        struct medusa_tcpsocket *rc;
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(monitor);
        rc = medusa_tcpsocket_create_unlocked(monitor, onevent, context);
        medusa_monitor_unlock(monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_create_with_options_unlocked (const struct medusa_tcpsocket_init_options *options)
{
        int rc;
        struct medusa_tcpsocket *tcpsocket;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
#if defined(MEDUSA_TCPSOCKET_USE_POOL) && (MEDUSA_TCPSOCKET_USE_POOL == 1)
        tcpsocket = medusa_pool_malloc(g_pool);
#else
        tcpsocket = malloc(sizeof(struct medusa_tcpsocket));
#endif
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(tcpsocket, 0, sizeof(struct medusa_tcpsocket));
        rc = medusa_tcpsocket_init_with_options_unlocked(tcpsocket, options);
        if (rc < 0) {
                medusa_tcpsocket_destroy_unlocked(tcpsocket);
                return MEDUSA_ERR_PTR(rc);
        }
        tcpsocket->subject.flags |= MEDUSA_SUBJECT_FLAG_ALLOC;
        return tcpsocket;
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_create_with_options (const struct medusa_tcpsocket_init_options *options)
{
        struct medusa_tcpsocket *rc;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(options->monitor);
        rc = medusa_tcpsocket_create_with_options_unlocked(options);
        medusa_monitor_unlock(options->monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void medusa_tcpsocket_destroy_unlocked (struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return;
        }
        medusa_tcpsocket_uninit_unlocked(tcpsocket);
}

__attribute__ ((visibility ("default"))) void medusa_tcpsocket_destroy (struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        medusa_tcpsocket_destroy_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_state_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        return tcpsocket_get_state(tcpsocket);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_state (const struct medusa_tcpsocket *tcpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_get_state_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_error_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        return tcpsocket_get_error(tcpsocket);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_error (const struct medusa_tcpsocket *tcpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_get_error_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_enabled_unlocked (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (enabled) {
                tcpsocket_add_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_ENABLED);
        } else {
                tcpsocket_del_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_ENABLED);
        }
        if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                rc = medusa_io_set_enabled_unlocked(tcpsocket->io, enabled);
                if (rc < 0) {
                        return rc;
                }
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_enabled (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_set_enabled_unlocked(tcpsocket, enabled);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_enabled_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        return tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_ENABLED);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_enabled (const struct medusa_tcpsocket *tcpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_get_enabled_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_enable (struct medusa_tcpsocket *tcpsocket)
{
        return medusa_tcpsocket_set_enabled(tcpsocket, 1);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_disable (struct medusa_tcpsocket *tcpsocket)
{
        return medusa_tcpsocket_set_enabled(tcpsocket, 0);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_buffered_unlocked (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (enabled) {
                tcpsocket_add_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_BUFFERED);
                if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->wbuffer)) {
                        struct medusa_buffer_init_options buffer_init_options;
                        rc = medusa_buffer_init_options_default(&buffer_init_options);
                        if (rc != 0) {
                                return rc;
                        }
                        buffer_init_options.onevent = tcpsocket_wbuffer_onevent;
                        buffer_init_options.context = tcpsocket;
                        tcpsocket->wbuffer = medusa_buffer_create_with_options(&buffer_init_options);
                        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->wbuffer)) {
                                return MEDUSA_PTR_ERR(tcpsocket->wbuffer);
                        }
                } else {
                        rc = medusa_buffer_reset(tcpsocket->wbuffer);
                        if (rc != 0) {
                                return rc;
                        }
                }
                if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->rbuffer)) {
                        tcpsocket->rbuffer = medusa_buffer_create(MEDUSA_BUFFER_TYPE_DEFAULT);
                        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->rbuffer)) {
                                return MEDUSA_PTR_ERR(tcpsocket->rbuffer);
                        }
                } else {
                        rc = medusa_buffer_reset(tcpsocket->rbuffer);
                        if (rc != 0) {
                                return rc;
                        }
                }
        } else {
                tcpsocket_del_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_BUFFERED);
                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->wbuffer)) {
                        medusa_buffer_destroy(tcpsocket->wbuffer);
                        tcpsocket->wbuffer = NULL;
                }
                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->rbuffer)) {
                        medusa_buffer_destroy(tcpsocket->rbuffer);
                        tcpsocket->rbuffer = NULL;
                }
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_buffered (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_set_buffered_unlocked(tcpsocket, enabled);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_buffered_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        return tcpsocket_get_buffered(tcpsocket);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_buffered (const struct medusa_tcpsocket *tcpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_get_buffered_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_nonblocking_unlocked (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (enabled) {
                tcpsocket_add_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_NONBLOCKING);
        } else {
                tcpsocket_del_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_NONBLOCKING);
        }
        if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                int rc;
                int flags;
                flags = fcntl(medusa_io_get_fd_unlocked(tcpsocket->io), F_GETFL, 0);
                if (flags < 0) {
                        return -errno;
                }
                flags = (tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_NONBLOCKING)) ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
                rc = fcntl(medusa_io_get_fd_unlocked(tcpsocket->io), F_SETFL, flags);
                if (rc != 0) {
                        return -errno;
                }
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_nonblocking (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_set_nonblocking_unlocked(tcpsocket, enabled);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_nonblocking_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        return tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_NONBLOCKING);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_nonblocking (const struct medusa_tcpsocket *tcpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_get_nonblocking_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_nodelay_unlocked (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (enabled) {
                tcpsocket_add_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_NODELAY);
        } else {
                tcpsocket_del_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_NODELAY);
        }
        if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                int rc;
                int on;
                on = !!tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_NODELAY);
                rc = setsockopt(medusa_io_get_fd_unlocked(tcpsocket->io), SOL_TCP, TCP_NODELAY, &on, sizeof(on));
                if (rc != 0) {
                        return -errno;
                }
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_nodelay (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_set_nodelay_unlocked(tcpsocket, enabled);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_nodelay_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        return tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_NODELAY);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_nodelay (const struct medusa_tcpsocket *tcpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_get_nodelay_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_reuseaddr_unlocked (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (enabled) {
                tcpsocket_add_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_REUSEADDR);
        } else {
                tcpsocket_del_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_REUSEADDR);
        }
        if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                int rc;
                int on;
                on = !!enabled;
                rc = setsockopt(medusa_io_get_fd_unlocked(tcpsocket->io), SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
                if (rc < 0) {
                        return -errno;
                }
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_reuseaddr (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_set_reuseaddr_unlocked(tcpsocket, enabled);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_reuseaddr_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        return tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_REUSEADDR);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_reuseaddr (const struct medusa_tcpsocket *tcpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_get_reuseaddr_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_reuseport_unlocked (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (enabled) {
                tcpsocket_add_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_REUSEPORT);
        } else {
                tcpsocket_del_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_REUSEPORT);
        }
        if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                int rc;
                int on;
                on = !!enabled;
                rc = setsockopt(medusa_io_get_fd_unlocked(tcpsocket->io), SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
                if (rc < 0) {
                        return -errno;
                }
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_reuseport (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_set_reuseport_unlocked(tcpsocket, enabled);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_reuseport_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        return tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_REUSEPORT);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_reuseport (const struct medusa_tcpsocket *tcpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_get_reuseport_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_backlog_unlocked (struct medusa_tcpsocket *tcpsocket, int backlog)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_DISCONNECTED &&
            tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_LISTENING) {
                return -EINVAL;
        }
        tcpsocket->backlog = backlog;
        tcpsocket_add_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_BACKLOG);
        if (tcpsocket_get_state(tcpsocket) == MEDUSA_TCPSOCKET_STATE_LISTENING) {
                rc = listen(medusa_io_get_fd_unlocked(tcpsocket->io), backlog);
                if (rc != 0) {
                        return -errno;
                }
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_backlog (struct medusa_tcpsocket *tcpsocket, int backlog)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_set_backlog_unlocked(tcpsocket, backlog);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_backlog_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_BACKLOG)) {
                return tcpsocket->backlog;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_backlog (const struct medusa_tcpsocket *tcpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_get_backlog_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_read_timeout_unlocked (struct medusa_tcpsocket *tcpsocket, double timeout)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (timeout < 0) {
                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->rtimer)) {
                        medusa_timer_destroy(tcpsocket->rtimer);
                        tcpsocket->rtimer = NULL;
                }
        } else {
                if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->rtimer)) {
                        tcpsocket->rtimer = medusa_timer_create_unlocked(tcpsocket->subject.monitor, tcpsocket_rtimer_onevent, tcpsocket);
                        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->rtimer)) {
                                return MEDUSA_PTR_ERR(tcpsocket->rtimer);
                        }
                }
                rc = medusa_timer_set_interval_unlocked(tcpsocket->rtimer, timeout);
                if (rc < 0) {
                        return rc;
                }
                rc = medusa_timer_set_singleshot_unlocked(tcpsocket->rtimer, 1);
                if (rc < 0) {
                        return rc;
                }
                if (tcpsocket_get_state(tcpsocket) == MEDUSA_TCPSOCKET_STATE_CONNECTED) {
                        rc = medusa_timer_set_enabled_unlocked(tcpsocket->rtimer, 1);
                        if (rc < 0) {
                                return rc;
                        }
                }
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_read_timeout (struct medusa_tcpsocket *tcpsocket, double timeout)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_set_read_timeout_unlocked(tcpsocket, timeout);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) double medusa_tcpsocket_get_read_timeout_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->rtimer)) {
                return -EINVAL;
        }
        return medusa_timer_get_interval_unlocked(tcpsocket->rtimer);
}

__attribute__ ((visibility ("default"))) double medusa_tcpsocket_get_read_timeout (const struct medusa_tcpsocket *tcpsocket)
{
        double rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_get_read_timeout(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_connect_timeout_unlocked (struct medusa_tcpsocket *tcpsocket, double timeout)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (timeout < 0) {
                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->ctimer)) {
                        medusa_timer_destroy(tcpsocket->ctimer);
                        tcpsocket->ctimer = NULL;
                }
        } else {
                if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->ctimer)) {
                        tcpsocket->ctimer = medusa_timer_create_unlocked(tcpsocket->subject.monitor, tcpsocket_ctimer_onevent, tcpsocket);
                        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->ctimer)) {
                                return MEDUSA_PTR_ERR(tcpsocket->ctimer);
                        }
                }
                rc = medusa_timer_set_interval_unlocked(tcpsocket->ctimer, timeout);
                if (rc < 0) {
                        return rc;
                }
                rc = medusa_timer_set_singleshot_unlocked(tcpsocket->ctimer, 1);
                if (rc < 0) {
                        return rc;
                }
                if (tcpsocket_get_state(tcpsocket) == MEDUSA_TCPSOCKET_STATE_CONNECTING) {
                        rc = medusa_timer_set_enabled_unlocked(tcpsocket->ctimer, 1);
                        if (rc < 0) {
                                return rc;
                        }
                }
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_connect_timeout (struct medusa_tcpsocket *tcpsocket, double timeout)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_set_connect_timeout_unlocked(tcpsocket, timeout);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) double medusa_tcpsocket_get_connect_timeout_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->ctimer)) {
                return -EINVAL;
        }
        return medusa_timer_get_interval_unlocked(tcpsocket->ctimer);
}

__attribute__ ((visibility ("default"))) double medusa_tcpsocket_get_connect_timeout (const struct medusa_tcpsocket *tcpsocket)
{
        double rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_get_connect_timeout(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_fd_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        return medusa_io_get_fd_unlocked(tcpsocket->io);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_fd (const struct medusa_tcpsocket *tcpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_get_fd_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_buffer * medusa_tcpsocket_get_read_buffer_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return tcpsocket->rbuffer;
}

__attribute__ ((visibility ("default"))) struct medusa_buffer * medusa_tcpsocket_get_read_buffer (const struct medusa_tcpsocket *tcpsocket)
{
        struct medusa_buffer *buffer;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        buffer = medusa_tcpsocket_get_read_buffer_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return buffer;
}

__attribute__ ((visibility ("default"))) struct medusa_buffer * medusa_tcpsocket_get_write_buffer_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return tcpsocket->wbuffer;
}

__attribute__ ((visibility ("default"))) struct medusa_buffer * medusa_tcpsocket_get_write_buffer (const struct medusa_tcpsocket *tcpsocket)
{
        struct medusa_buffer *buffer;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        buffer = medusa_tcpsocket_get_write_buffer_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return buffer;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_events_unlocked (struct medusa_tcpsocket *tcpsocket, unsigned int events)
{
        unsigned int io_events;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                return -EINVAL;
        }
        if ((tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_LISTENING) &&
            (tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_CONNECTED)) {
                return -EINVAL;
        }
        io_events = MEDUSA_IO_EVENT_NONE;
        if (events & MEDUSA_TCPSOCKET_EVENT_IN) {
                io_events |= MEDUSA_IO_EVENT_IN;
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_OUT) {
                io_events |= MEDUSA_IO_EVENT_OUT;
        }
        return medusa_io_set_events_unlocked(tcpsocket->io, io_events);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_events (struct medusa_tcpsocket *tcpsocket, unsigned int events)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_set_events_unlocked(tcpsocket, events);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_add_events_unlocked (struct medusa_tcpsocket *tcpsocket, unsigned int events)
{
        unsigned int io_events;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                return -EINVAL;
        }
        if ((tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_LISTENING) &&
            (tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_CONNECTED)) {
                return -EINVAL;
        }
        if (tcpsocket_get_buffered(tcpsocket)) {
                return -EINVAL;
        }
        io_events = MEDUSA_IO_EVENT_NONE;
        if (events & MEDUSA_TCPSOCKET_EVENT_IN) {
                io_events |= MEDUSA_IO_EVENT_IN;
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_OUT) {
                io_events |= MEDUSA_IO_EVENT_OUT;
        }
        return medusa_io_add_events_unlocked(tcpsocket->io, io_events);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_add_events (struct medusa_tcpsocket *tcpsocket, unsigned int events)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_add_events_unlocked(tcpsocket, events);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_del_events_unlocked (struct medusa_tcpsocket *tcpsocket, unsigned int events)
{
        unsigned int io_events;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                return -EINVAL;
        }
        if ((tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_LISTENING) &&
            (tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_CONNECTED)) {
                return -EINVAL;
        }
        if (tcpsocket_get_buffered(tcpsocket)) {
                return -EINVAL;
        }
        io_events = MEDUSA_IO_EVENT_NONE;
        if (events & MEDUSA_TCPSOCKET_EVENT_IN) {
                io_events |= MEDUSA_IO_EVENT_IN;
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_OUT) {
                io_events |= MEDUSA_IO_EVENT_OUT;
        }
        return medusa_io_del_events_unlocked(tcpsocket->io, io_events);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_del_events (struct medusa_tcpsocket *tcpsocket, unsigned int events)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_del_events_unlocked(tcpsocket, events);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) unsigned int medusa_tcpsocket_get_events_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        unsigned int events;
        unsigned int io_events;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                return -EINVAL;
        }
        if ((tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_LISTENING) &&
            (tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_CONNECTED)) {
                return -EINVAL;
        }
        events = 0;
        io_events = medusa_io_get_events_unlocked(tcpsocket->io);
        if (io_events & MEDUSA_IO_EVENT_IN) {
                events |= MEDUSA_TCPSOCKET_EVENT_IN;
        }
        if (io_events & MEDUSA_IO_EVENT_OUT) {
                events |= MEDUSA_TCPSOCKET_EVENT_OUT;
        }
        return events;
}

__attribute__ ((visibility ("default"))) unsigned int medusa_tcpsocket_get_events (const struct medusa_tcpsocket *tcpsocket)
{
        unsigned int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_get_events_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_bind_unlocked (struct medusa_tcpsocket *tcpsocket, unsigned int protocol, const char *address, unsigned short port)
{
        int rc;
        int fd;
        int ret;
        unsigned int length;
        struct sockaddr *sockaddr;
        struct sockaddr_in sockaddr_in;
        struct sockaddr_in6 sockaddr_in6;
        struct medusa_io_init_options io_init_options;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (port == 0) {
                return -EINVAL;
        }
        if (tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_DISCONNECTED) {
                return -EIO;
        }
        if (medusa_io_get_fd_unlocked(tcpsocket->io) >= 0) {
                return -EIO;
        }
        rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_BINDING);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_BINDING);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        if (protocol == MEDUSA_TCPSOCKET_PROTOCOL_IPV4) {
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
        } else if (protocol == MEDUSA_TCPSOCKET_PROTOCOL_IPV6) {
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
        fd = socket(sockaddr->sa_family, SOCK_STREAM, 0);
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
        io_init_options.monitor = tcpsocket->subject.monitor;
        io_init_options.fd      = fd;
        io_init_options.events  = MEDUSA_IO_EVENT_IN;
        io_init_options.onevent = tcpsocket_io_onevent;
        io_init_options.context = tcpsocket;
        io_init_options.enabled = tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_ENABLED);
        tcpsocket->io = medusa_io_create_with_options_unlocked(&io_init_options);
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                ret = MEDUSA_PTR_ERR(tcpsocket->io);
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
                flags = (tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_NONBLOCKING)) ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
                rc = fcntl(fd, F_SETFL, flags);
                if (rc != 0) {
                        ret = -errno;
                        goto bail;
                }
        }
        {
                int rc;
                int on;
                on = !!tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_NODELAY);
                rc = setsockopt(fd, SOL_TCP, TCP_NODELAY, &on, sizeof(on));
                if (rc != 0) {
                        ret = -errno;
                        goto bail;
                }
        }
        {
                int rc;
                int on;
                on = tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_REUSEADDR);
                rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
                if (rc < 0) {
                        ret = -errno;
                        goto bail;
                }
        }
        {
                int rc;
                int on;
                on = tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_REUSEPORT);
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
        rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_BOUND);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_BOUND);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        if (tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_BACKLOG)) {
                rc = listen(fd, tcpsocket->backlog);
                if (rc != 0) {
                        ret = -errno;
                        goto bail;
                }
        }
        rc = medusa_io_set_events_unlocked(tcpsocket->io, MEDUSA_IO_EVENT_IN);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_LISTENING);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_LISTENING);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        return 0;
bail:   tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
        medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DISCONNECTED);
        return ret;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_bind (struct medusa_tcpsocket *tcpsocket, unsigned int protocol, const char *address, unsigned short port)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_bind_unlocked(tcpsocket, protocol, address, port);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_connect_unlocked (struct medusa_tcpsocket *tcpsocket, unsigned int protocol, const char *address, unsigned short port)
{
        int rc;
        int fd;
        int ret;
        struct addrinfo hints;
        struct addrinfo *result;
        struct addrinfo *res;
        struct medusa_io_init_options io_init_options;
        result = NULL;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (address == NULL) {
                return -EINVAL;
        }
        if (port == 0) {
                return -EINVAL;
        }
        if (tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_DISCONNECTED) {
                return -EINVAL;
        }
        if (medusa_io_get_fd_unlocked(tcpsocket->io) >= 0) {
                return -EINVAL;
        }
        rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_RESOLVING);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_RESOLVING);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        memset(&hints, 0, sizeof(struct addrinfo));
        if (protocol == MEDUSA_TCPSOCKET_PROTOCOL_IPV4) {
                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_STREAM;
        } else if (protocol == MEDUSA_TCPSOCKET_PROTOCOL_IPV6) {
                hints.ai_family = AF_INET6;
                hints.ai_socktype = SOCK_STREAM;
        } else {
                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_STREAM;
        }
        rc = getaddrinfo(address, NULL, &hints, &result);
        if (rc != 0) {
                ret = -EIO;
                goto bail;
        }
        rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_RESOLVED);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_RESOLVED);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_CONNECTING);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_CONNECTING);
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
                fd = socket(res->ai_family, SOCK_STREAM, 0);
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
                io_init_options.monitor = tcpsocket->subject.monitor;
                io_init_options.fd      = fd;
                io_init_options.events  = MEDUSA_IO_EVENT_IN;
                io_init_options.onevent = tcpsocket_io_onevent;
                io_init_options.context = tcpsocket;
                io_init_options.enabled = tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_ENABLED);
                tcpsocket->io = medusa_io_create_with_options_unlocked(&io_init_options);
                if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                        ret = MEDUSA_PTR_ERR(tcpsocket->io);
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
                        flags = (tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_NONBLOCKING)) ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
                        rc = fcntl(fd, F_SETFL, flags);
                        if (rc != 0) {
                                ret = -errno;
                                goto bail;
                        }
                }
                {
                        int rc;
                        int on;
                        on = !!tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_NODELAY);
                        rc = setsockopt(fd, SOL_TCP, TCP_NODELAY, &on, sizeof(on));
                        if (rc != 0) {
                                ret = -errno;
                                goto bail;
                        }
                }
                {
                        int rc;
                        int on;
                        on = tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_REUSEADDR);
                        rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
                        if (rc < 0) {
                                ret = -errno;
                                goto bail;
                        }
                }
                {
                        int rc;
                        int on;
                        on = tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_REUSEPORT);
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
                                medusa_io_destroy_unlocked(tcpsocket->io);
                                tcpsocket->io = NULL;
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
                rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_CONNECTED);
                if (rc < 0) {
                        ret = rc;
                        goto bail;
                }
                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_CONNECTED);
                if (rc < 0) {
                        ret = rc;
                        goto bail;
                }
        } else {
                rc = medusa_io_add_events_unlocked(tcpsocket->io, MEDUSA_IO_EVENT_OUT);
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
        tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
        medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DISCONNECTED);
        return ret;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_connect (struct medusa_tcpsocket *tcpsocket, unsigned int protocol, const char *address, unsigned short port)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_connect_unlocked(tcpsocket, protocol, address, port);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_attach_unlocked (struct medusa_tcpsocket *tcpsocket, int fd)
{
        int rc;
        int ret;
        struct medusa_io_init_options io_init_options;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (fd < 0) {
                return -EINVAL;
        }
        if (tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_DISCONNECTED) {
                return -EINVAL;
        }
        if (medusa_io_get_fd_unlocked(tcpsocket->io) >= 0) {
                return -EINVAL;
        }
        rc = medusa_io_init_options_default(&io_init_options);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        io_init_options.monitor = tcpsocket->subject.monitor;
        io_init_options.fd      = fd;
        io_init_options.events  = MEDUSA_IO_EVENT_IN;
        io_init_options.onevent = tcpsocket_io_onevent;
        io_init_options.context = tcpsocket;
        io_init_options.enabled = tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_ENABLED);
        tcpsocket->io = medusa_io_create_with_options_unlocked(&io_init_options);
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                ret = MEDUSA_PTR_ERR(tcpsocket->io);
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
                flags = (tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_NONBLOCKING)) ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
                rc = fcntl(fd, F_SETFL, flags);
                if (rc != 0) {
                        ret = -errno;
                        goto bail;
                }
        }
        {
                int rc;
                int on;
                on = !!tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_NODELAY);
                rc = setsockopt(fd, SOL_TCP, TCP_NODELAY, &on, sizeof(on));
                if (rc != 0) {
                        ret = -errno;
                        goto bail;
                }
        }
        {
                int rc;
                int on;
                on = tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_REUSEADDR);
                rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
                if (rc < 0) {
                        ret = -errno;
                        goto bail;
                }
        }
        {
                int rc;
                int on;
                on = tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_REUSEPORT);
                rc = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
                if (rc < 0) {
                        ret = -errno;
                        goto bail;
                }

        }
        rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_CONNECTED);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_CONNECTED);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        return 0;
bail:   tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
        medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DISCONNECTED);
        return ret;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_attach (struct medusa_tcpsocket *tcpsocket, int fd)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (fd < 0) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_attach_unlocked(tcpsocket, fd);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_accept_options_default (struct medusa_tcpsocket_accept_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_tcpsocket_accept_options));
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_accept_init_unlocked (struct medusa_tcpsocket *accepted, struct medusa_tcpsocket *tcpsocket, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...), void *context)
{
        int rc;
        struct medusa_tcpsocket_accept_options options;
        rc = medusa_tcpsocket_accept_options_default(&options);
        if (rc < 0) {
                return rc;
        }
        options.onevent   = onevent;
        options.context   = context;
        return medusa_tcpsocket_accept_init_with_options_unlocked(accepted, tcpsocket, &options);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_accept_init (struct medusa_tcpsocket *accepted, struct medusa_tcpsocket *tcpsocket, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...), void *context)
{
        int rc;
        struct medusa_monitor *monitor;
        monitor = medusa_tcpsocket_get_monitor(tcpsocket);
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return -EINVAL;
        }
        medusa_monitor_lock(monitor);
        rc = medusa_tcpsocket_accept_init_unlocked(accepted, tcpsocket, onevent, context);
        medusa_monitor_unlock(monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_accept_init_with_options_unlocked (struct medusa_tcpsocket *accepted, struct medusa_tcpsocket *tcpsocket, const struct medusa_tcpsocket_accept_options *options)
{
        int fd;
        int rc;
        struct medusa_io_init_options io_init_options;
        struct medusa_tcpsocket_init_options accepted_options;
        if (MEDUSA_IS_ERR_OR_NULL(accepted)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                return -EINVAL;
        }
        fd = accept(medusa_io_get_fd_unlocked(tcpsocket->io), NULL, NULL);
        if (fd < 0) {
                return -errno;
        }
        rc = medusa_tcpsocket_init_options_default(&accepted_options);
        if (rc < 0) {
                close(fd);
                return rc;
        }
        accepted_options.monitor     = medusa_tcpsocket_get_monitor_unlocked(tcpsocket);
        accepted_options.onevent     = options->onevent;
        accepted_options.context     = options->context;
        accepted_options.nonblocking = options->nonblocking;
        accepted_options.nodelay     = options->nodelay;
        accepted_options.enabled     = options->enabled;
        accepted_options.buffered    = options->buffered;
        rc = medusa_tcpsocket_init_with_options_unlocked(accepted, &accepted_options);
        if (rc < 0) {
                close(fd);
                return rc;
        }
        io_init_options.monitor = accepted->subject.monitor;
        io_init_options.fd      = fd;
        io_init_options.events  = MEDUSA_IO_EVENT_IN;
        io_init_options.onevent = tcpsocket_io_onevent;
        io_init_options.context = accepted;
        io_init_options.enabled = tcpsocket_has_flag(accepted, MEDUSA_TCPSOCKET_FLAG_ENABLED);
        accepted->io = medusa_io_create_with_options_unlocked(&io_init_options);
        if (MEDUSA_IS_ERR_OR_NULL(accepted->io)) {
                rc = MEDUSA_PTR_ERR(accepted->io);
                medusa_tcpsocket_destroy_unlocked(accepted);
                return rc;
        }
        {
                int rc;
                int flags;
                flags = fcntl(fd, F_GETFL, 0);
                if (flags < 0) {
                        medusa_tcpsocket_destroy_unlocked(accepted);
                        return -errno;
                }
                flags = (tcpsocket_has_flag(accepted, MEDUSA_TCPSOCKET_FLAG_NONBLOCKING)) ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
                rc = fcntl(fd, F_SETFL, flags);
                if (rc != 0) {
                        medusa_tcpsocket_destroy_unlocked(accepted);
                        return -errno;
                }
        }
        {
                int rc;
                int on;
                on = !!tcpsocket_has_flag(accepted, MEDUSA_TCPSOCKET_FLAG_NODELAY);
                rc = setsockopt(fd, SOL_TCP, TCP_NODELAY, &on, sizeof(on));
                if (rc != 0) {
                        medusa_tcpsocket_destroy_unlocked(accepted);
                        return -errno;
                }
        }
        rc = tcpsocket_set_state(accepted, MEDUSA_TCPSOCKET_STATE_CONNECTED);
        if (rc < 0) {
                medusa_tcpsocket_destroy_unlocked(accepted);
                return rc;
        }
        rc = medusa_tcpsocket_onevent_unlocked(accepted, MEDUSA_TCPSOCKET_EVENT_CONNECTED);
        if (rc < 0) {
                medusa_tcpsocket_destroy_unlocked(accepted);
                return rc;
        }
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_accept_unlocked (struct medusa_tcpsocket *tcpsocket, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...), void *context)
{
        int rc;
        struct medusa_tcpsocket_accept_options options;
        rc = medusa_tcpsocket_accept_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.onevent   = onevent;
        options.context   = context;
        return medusa_tcpsocket_accept_with_options_unlocked(tcpsocket, &options);
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_accept (struct medusa_tcpsocket *tcpsocket, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...), void *context)
{
        struct medusa_tcpsocket *rc;
        struct medusa_monitor *monitor;
        monitor = medusa_tcpsocket_get_monitor(tcpsocket);
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(monitor);
        rc = medusa_tcpsocket_accept_unlocked(tcpsocket, onevent, context);
        medusa_monitor_unlock(monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_accept_with_options_unlocked (struct medusa_tcpsocket *tcpsocket, const struct medusa_tcpsocket_accept_options *options)
{
        int fd;
        int rc;
        struct medusa_tcpsocket *accepted;
        struct medusa_io_init_options io_init_options;
        struct medusa_tcpsocket_init_options accepted_options;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        fd = accept(medusa_io_get_fd_unlocked(tcpsocket->io), NULL, NULL);
        if (fd < 0) {
                return MEDUSA_ERR_PTR(-errno);
        }
        rc = medusa_tcpsocket_init_options_default(&accepted_options);
        if (rc < 0) {
                close(fd);
                return MEDUSA_ERR_PTR(rc);
        }
        accepted_options.monitor     = medusa_tcpsocket_get_monitor_unlocked(tcpsocket);
        accepted_options.onevent     = options->onevent;
        accepted_options.context     = options->context;
        accepted_options.nonblocking = options->nonblocking;
        accepted_options.nodelay     = options->nodelay;
        accepted_options.enabled     = options->enabled;
        accepted_options.buffered    = options->buffered;
        accepted = medusa_tcpsocket_create_with_options_unlocked(&accepted_options);
        if (MEDUSA_IS_ERR_OR_NULL(accepted)) {
                close(fd);
                return MEDUSA_ERR_PTR(MEDUSA_PTR_ERR(accepted));
        }
        io_init_options.monitor = accepted->subject.monitor;
        io_init_options.fd      = fd;
        io_init_options.events  = MEDUSA_IO_EVENT_IN;
        io_init_options.onevent = tcpsocket_io_onevent;
        io_init_options.context = accepted;
        io_init_options.enabled = tcpsocket_has_flag(accepted, MEDUSA_TCPSOCKET_FLAG_ENABLED);
        accepted->io = medusa_io_create_with_options_unlocked(&io_init_options);
        if (MEDUSA_IS_ERR_OR_NULL(accepted->io)) {
                rc = MEDUSA_PTR_ERR(accepted->io);
                medusa_tcpsocket_destroy_unlocked(accepted);
                return MEDUSA_ERR_PTR(rc);
        }
        {
                int rc;
                int flags;
                flags = fcntl(fd, F_GETFL, 0);
                if (flags < 0) {
                        medusa_tcpsocket_destroy_unlocked(accepted);
                        return MEDUSA_ERR_PTR(-errno);
                }
                flags = (tcpsocket_has_flag(accepted, MEDUSA_TCPSOCKET_FLAG_NONBLOCKING)) ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
                rc = fcntl(fd, F_SETFL, flags);
                if (rc != 0) {
                        medusa_tcpsocket_destroy_unlocked(accepted);
                        return MEDUSA_ERR_PTR(-errno);
                }
        }
        {
                int rc;
                int on;
                on = !!tcpsocket_has_flag(accepted, MEDUSA_TCPSOCKET_FLAG_NODELAY);
                rc = setsockopt(fd, SOL_TCP, TCP_NODELAY, &on, sizeof(on));
                if (rc != 0) {
                        medusa_tcpsocket_destroy_unlocked(accepted);
                        return MEDUSA_ERR_PTR(-errno);
                }
        }
        rc = tcpsocket_set_state(accepted, MEDUSA_TCPSOCKET_STATE_CONNECTED);
        if (rc < 0) {
                medusa_tcpsocket_destroy_unlocked(accepted);
                return MEDUSA_ERR_PTR(rc);
        }
        rc = medusa_tcpsocket_onevent_unlocked(accepted, MEDUSA_TCPSOCKET_EVENT_CONNECTED);
        if (rc < 0) {
                medusa_tcpsocket_destroy_unlocked(accepted);
                return MEDUSA_ERR_PTR(rc);
        }
        return accepted;
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_accept_with_options (struct medusa_tcpsocket *tcpsocket, const struct medusa_tcpsocket_accept_options *options)
{
        struct medusa_tcpsocket *rc;
        struct medusa_monitor *monitor;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        monitor = medusa_tcpsocket_get_monitor(tcpsocket);
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(monitor);
        rc = medusa_tcpsocket_accept_with_options_unlocked(tcpsocket, options);
        medusa_monitor_unlock(monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_onevent_unlocked (struct medusa_tcpsocket *tcpsocket, unsigned int events)
{
        int ret;
        struct medusa_monitor *monitor;
        ret = 0;
        monitor = tcpsocket->subject.monitor;
        if (tcpsocket->onevent != NULL) {
                if ((medusa_subject_is_active(&tcpsocket->subject)) ||
                    (events & MEDUSA_TCPSOCKET_EVENT_DESTROY)) {
                        medusa_monitor_unlock(monitor);
                        ret = tcpsocket->onevent(tcpsocket, events, tcpsocket->context);
                        medusa_monitor_lock(monitor);
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_DESTROY) {
                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->ctimer)) {
                        medusa_timer_destroy_unlocked(tcpsocket->ctimer);
                        tcpsocket->ctimer = NULL;
                }
                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->rtimer)) {
                        medusa_timer_destroy_unlocked(tcpsocket->rtimer);
                        tcpsocket->rtimer = NULL;
                }
                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                        medusa_io_destroy_unlocked(tcpsocket->io);
                        tcpsocket->io = NULL;
                }
                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->wbuffer)) {
                        medusa_buffer_destroy(tcpsocket->wbuffer);
                        tcpsocket->wbuffer = NULL;
                }
                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->rbuffer)) {
                        medusa_buffer_destroy(tcpsocket->rbuffer);
                        tcpsocket->rbuffer = NULL;
                }
                if (tcpsocket->subject.flags & MEDUSA_SUBJECT_FLAG_ALLOC) {
#if defined(MEDUSA_TCPSOCKET_USE_POOL) && (MEDUSA_TCPSOCKET_USE_POOL == 1)
                        medusa_pool_free(tcpsocket);
#else
                        free(tcpsocket);
#endif
                } else {
                        memset(tcpsocket, 0, sizeof(struct medusa_tcpsocket));
                }
        } else {
                if ((tcpsocket_get_state(tcpsocket) == MEDUSA_TCPSOCKET_STATE_CONNECTED) &&
                    (tcpsocket_get_buffered(tcpsocket) > 0) &&
                    (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->io))) {
                        int rc;
                        int64_t blength;
                        blength = medusa_buffer_get_length(tcpsocket->wbuffer);
                        if (blength < 0) {
                                ret = blength;
                                goto out;
                        } else if (blength == 0) {
                                rc = medusa_io_del_events_unlocked(tcpsocket->io, MEDUSA_IO_EVENT_OUT);
                                if (rc < 0) {
                                        ret = rc;
                                        goto out;
                                }
                        } else {
                                rc = medusa_io_add_events_unlocked(tcpsocket->io, MEDUSA_IO_EVENT_OUT);
                                if (rc < 0) {
                                        ret = rc;
                                        goto out;
                                }
                        }
                        rc = medusa_io_add_events_unlocked(tcpsocket->io, MEDUSA_IO_EVENT_IN);
                        if (rc < 0) {
                                ret = rc;
                                goto out;
                        }
                }
        }
out:    return ret;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_userdata_unlocked (struct medusa_tcpsocket *tcpsocket, void *userdata)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        tcpsocket->userdata = userdata;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_userdata (struct medusa_tcpsocket *tcpsocket, void *userdata)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_set_userdata_unlocked(tcpsocket, userdata);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void * medusa_tcpsocket_get_userdata_unlocked (struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return tcpsocket->userdata;
}

__attribute__ ((visibility ("default"))) void * medusa_tcpsocket_get_userdata (struct medusa_tcpsocket *tcpsocket)
{
        void *rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_get_userdata_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, events);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_tcpsocket_get_monitor_unlocked (struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return tcpsocket->subject.monitor;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_tcpsocket_get_monitor (struct medusa_tcpsocket *tcpsocket)
{
        struct medusa_monitor *rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_get_monitor_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) const char * medusa_tcpsocket_state_string (unsigned int state)
{
        if (state == MEDUSA_TCPSOCKET_STATE_UNKNOWN)                    return "MEDUSA_TCPSOCKET_STATE_UNKNOWN";
        if (state == MEDUSA_TCPSOCKET_STATE_DISCONNECTED)               return "MEDUSA_TCPSOCKET_STATE_DISCONNECTED";
        if (state == MEDUSA_TCPSOCKET_STATE_BINDING)                    return "MEDUSA_TCPSOCKET_STATE_BINDING";
        if (state == MEDUSA_TCPSOCKET_STATE_BOUND)                      return "MEDUSA_TCPSOCKET_STATE_BOUND";
        if (state == MEDUSA_TCPSOCKET_STATE_LISTENING)                  return "MEDUSA_TCPSOCKET_STATE_LISTENING";
        if (state == MEDUSA_TCPSOCKET_STATE_RESOLVING)                  return "MEDUSA_TCPSOCKET_STATE_RESOLVING";
        if (state == MEDUSA_TCPSOCKET_STATE_RESOLVED)                   return "MEDUSA_TCPSOCKET_STATE_RESOLVED";
        if (state == MEDUSA_TCPSOCKET_STATE_CONNECTING)                 return "MEDUSA_TCPSOCKET_STATE_CONNECTING";
        if (state == MEDUSA_TCPSOCKET_STATE_CONNECTED)                  return "MEDUSA_TCPSOCKET_STATE_CONNECTED";
        return "MEDUSA_TCPSOCKET_STATE_UNKNOWN";
}

__attribute__ ((visibility ("default"))) const char * medusa_tcpsocket_event_string (unsigned int events)
{
        if (events == MEDUSA_TCPSOCKET_EVENT_BINDING)                   return "MEDUSA_TCPSOCKET_EVENT_BINDING";
        if (events == MEDUSA_TCPSOCKET_EVENT_BOUND)                     return "MEDUSA_TCPSOCKET_EVENT_BOUND";
        if (events == MEDUSA_TCPSOCKET_EVENT_LISTENING)                 return "MEDUSA_TCPSOCKET_EVENT_LISTENING";
        if (events == MEDUSA_TCPSOCKET_EVENT_CONNECTION)                return "MEDUSA_TCPSOCKET_EVENT_CONNECTION";
        if (events == MEDUSA_TCPSOCKET_EVENT_RESOLVING)                 return "MEDUSA_TCPSOCKET_EVENT_RESOLVING";
        if (events == MEDUSA_TCPSOCKET_EVENT_RESOLVE_TIMEOUT)           return "MEDUSA_TCPSOCKET_EVENT_RESOLVE_TIMEOUT";
        if (events == MEDUSA_TCPSOCKET_EVENT_RESOLVED)                  return "MEDUSA_TCPSOCKET_EVENT_RESOLVED";
        if (events == MEDUSA_TCPSOCKET_EVENT_CONNECTING)                return "MEDUSA_TCPSOCKET_EVENT_CONNECTING";
        if (events == MEDUSA_TCPSOCKET_EVENT_CONNECT_TIMEOUT)           return "MEDUSA_TCPSOCKET_EVENT_CONNECT_TIMEOUT";
        if (events == MEDUSA_TCPSOCKET_EVENT_CONNECTED)                 return "MEDUSA_TCPSOCKET_EVENT_CONNECTED";
        if (events == MEDUSA_TCPSOCKET_EVENT_IN)                        return "MEDUSA_TCPSOCKET_EVENT_IN";
        if (events == MEDUSA_TCPSOCKET_EVENT_OUT)                       return "MEDUSA_TCPSOCKET_EVENT_OUT";
        if (events == MEDUSA_TCPSOCKET_EVENT_BUFFERED_READ)             return "MEDUSA_TCPSOCKET_EVENT_BUFFERED_READ";
        if (events == MEDUSA_TCPSOCKET_EVENT_BUFFERED_READ_TIMEOUT)     return "MEDUSA_TCPSOCKET_EVENT_BUFFERED_READ_TIMEOUT";
        if (events == MEDUSA_TCPSOCKET_EVENT_BUFFERED_WRITE)            return "MEDUSA_TCPSOCKET_EVENT_BUFFERED_WRITE";
        if (events == MEDUSA_TCPSOCKET_EVENT_BUFFERED_WRITE_TIMEOUT)    return "MEDUSA_TCPSOCKET_EVENT_BUFFERED_WRITE_TIMEOUT";
        if (events == MEDUSA_TCPSOCKET_EVENT_BUFFERED_WRITE_FINISHED)   return "MEDUSA_TCPSOCKET_EVENT_BUFFERED_WRITE_FINISHED";
        if (events == MEDUSA_TCPSOCKET_EVENT_DISCONNECTED)              return "MEDUSA_TCPSOCKET_EVENT_DISCONNECTED";
        if (events == MEDUSA_TCPSOCKET_EVENT_ERROR)                     return "MEDUSA_TCPSOCKET_EVENT_ERROR";
        if (events == MEDUSA_TCPSOCKET_EVENT_DESTROY)                   return "MEDUSA_TCPSOCKET_EVENT_DESTROY";
        return "MEDUSA_TCPSOCKET_EVENT_UNKNOWN";
}

__attribute__ ((constructor)) static void tcpsocket_constructor (void)
{
#if defined(MEDUSA_TCPSOCKET_USE_POOL) && (MEDUSA_TCPSOCKET_USE_POOL == 1)
        g_pool = medusa_pool_create("medusa-tcpsocket", sizeof(struct medusa_tcpsocket), 0, 0, MEDUSA_POOL_FLAG_DEFAULT | MEDUSA_POOL_FLAG_THREAD_SAFE, NULL, NULL, NULL);
#endif
}

__attribute__ ((destructor)) static void tcpsocket_destructor (void)
{
#if defined(MEDUSA_TCPSOCKET_USE_POOL) && (MEDUSA_TCPSOCKET_USE_POOL == 1)
        if (g_pool != NULL) {
                medusa_pool_destroy(g_pool);
        }
#endif
}
