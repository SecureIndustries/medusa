
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
#include <netdb.h>
#include <errno.h>

#include "error.h"
#include "pool.h"
#include "queue.h"
#include "buffer.h"
#include "subject-struct.h"
#include "io.h"
#include "io-private.h"
#include "io-struct.h"
#include "tcpsocket.h"
#include "tcpsocket-private.h"
#include "tcpsocket-struct.h"
#include "monitor-private.h"

#define MIN(a, b)                               (((a) < (b)) ? (a) : (b))

#define MEDUSA_TCPSOCKET_USE_POOL               1
#define MEDUSA_TCPSOCKET_USE_READV              1
#define MEDUSA_TCPSOCKET_USE_WRITEV             1

#define MEDUSA_TCPSOCKET_DEFAULT_BACKLOG        128
#define MEDUSA_TCPSOCKET_DEFAULT_IOVECS         4

enum {
        MEDUSA_TCPSOCKET_FLAG_NONE              = 0x00000000,
        MEDUSA_TCPSOCKET_FLAG_NONBLOCKING       = 0x00000001,
        MEDUSA_TCPSOCKET_FLAG_REUSEADDR         = 0x00000002,
        MEDUSA_TCPSOCKET_FLAG_REUSEPORT         = 0x00000004,
        MEDUSA_TCPSOCKET_FLAG_BACKLOG           = 0x00000008,
#define MEDUSA_TCPSOCKET_FLAG_NONE              MEDUSA_TCPSOCKET_FLAG_NONE
#define MEDUSA_TCPSOCKET_FLAG_NONBLOCKING       MEDUSA_TCPSOCKET_FLAG_NONBLOCKING
#define MEDUSA_TCPSOCKET_FLAG_REUSEADDR         MEDUSA_TCPSOCKET_FLAG_REUSEADDR
#define MEDUSA_TCPSOCKET_FLAG_REUSEPORT         MEDUSA_TCPSOCKET_FLAG_REUSEPORT
#define MEDUSA_TCPSOCKET_FLAG_BACKLOG           MEDUSA_TCPSOCKET_FLAG_BACKLOG
};

#define MEDUSA_TCPSOCKET_FLAG_MASK              0xff
#define MEDUSA_TCPSOCKET_FLAG_SHIFT             0x00

#define MEDUSA_TCPSOCKET_STATE_MASK             0xff
#define MEDUSA_TCPSOCKET_STATE_SHIFT            0x18

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

static inline unsigned int tcpsocket_has_flag (const struct medusa_tcpsocket *tcpsocket, unsigned int flag)
{
        return (tcpsocket->flags & ((flag & MEDUSA_TCPSOCKET_FLAG_MASK) << MEDUSA_TCPSOCKET_FLAG_SHIFT));
}

static inline unsigned int tcpsocket_get_state (const struct medusa_tcpsocket *tcpsocket)
{
        return (tcpsocket->flags >> MEDUSA_TCPSOCKET_STATE_SHIFT) & MEDUSA_TCPSOCKET_STATE_MASK;
}

static inline void tcpsocket_set_state (struct medusa_tcpsocket *tcpsocket, unsigned int state)
{
        if (state == MEDUSA_TCPSOCKET_STATE_DISCONNECTED) {
                medusa_io_set_enabled_unlocked(&tcpsocket->io, 0);
                if (tcpsocket->io.fd >= 0) {
                        close(tcpsocket->io.fd);
                        tcpsocket->io.fd = -1;
                }
        }
        tcpsocket->flags = (tcpsocket->flags & ~(MEDUSA_TCPSOCKET_STATE_MASK << MEDUSA_TCPSOCKET_STATE_SHIFT)) |
                           ((state & MEDUSA_TCPSOCKET_STATE_MASK) << MEDUSA_TCPSOCKET_STATE_SHIFT);
}

static int medusa_tcpsocket_io_onevent (struct medusa_io *io, unsigned int events, void *context, ...)
{
        int rc;
        int niovecs;
        int64_t length;
        unsigned int tevents;
        struct medusa_monitor *monitor;
        struct medusa_tcpsocket *tcpsocket = (struct medusa_tcpsocket *) io;

        (void) context;

        monitor = tcpsocket->io.subject.monitor;
        medusa_monitor_lock(monitor);

        tevents = 0;

        if (events & MEDUSA_IO_EVENT_OUT) {
                if (tcpsocket_get_state(tcpsocket) == MEDUSA_TCPSOCKET_STATE_CONNECTING) {
                        int valopt;
                        socklen_t vallen;
                        vallen = sizeof(valopt);
                        rc = getsockopt(tcpsocket->io.fd, SOL_SOCKET, SO_ERROR, (void*) &valopt, &vallen);
                        if (rc < 0) {
                                goto bail;
                        }
                        if (valopt != 0) {
                                tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                                tevents |= MEDUSA_TCPSOCKET_EVENT_DISCONNECTED;
                        } else {
                                tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_CONNECTED);
                                tevents |= MEDUSA_TCPSOCKET_EVENT_CONNECTED;
                                length = medusa_buffer_get_length(tcpsocket->wbuffer);
                                if (length > 0) {
                                        rc = medusa_io_add_events_unlocked(&tcpsocket->io, MEDUSA_IO_EVENT_OUT);
                                        if (rc < 0) {
                                                goto bail;
                                        }
                                } else if (length == 0) {
                                        rc = medusa_io_del_events_unlocked(&tcpsocket->io, MEDUSA_IO_EVENT_OUT);
                                        if (rc < 0) {
                                                goto bail;
                                        }
                                } else {
                                        goto bail;
                                }
                        }
                } else if (tcpsocket_get_state(tcpsocket) == MEDUSA_TCPSOCKET_STATE_CONNECTED) {
                        length = medusa_buffer_get_length(tcpsocket->wbuffer);
                        if (length <= 0) {
                                goto bail;
                        }
#if defined(MEDUSA_TCPSOCKET_USE_WRITEV) && (MEDUSA_TCPSOCKET_USE_WRITEV == 1)
                        niovecs = medusa_buffer_peek(tcpsocket->wbuffer, 0, -1, NULL, 0);
                        if (niovecs <= 0) {
                                goto bail;
                        }
                        if (niovecs > tcpsocket->niovecs) {
                                struct iovec *tmp;
                                tmp = realloc(tcpsocket->iovecs, sizeof(struct iovec) * niovecs);
                                if (tmp == NULL) {
                                        tmp = malloc(sizeof(struct iovec) * niovecs);
                                        if (tmp == NULL) {
                                                goto bail;
                                        }
                                        if (tcpsocket->iovecs != NULL) {
                                                free(tcpsocket->iovecs);
                                        }
                                }
                                tcpsocket->iovecs = tmp;
                                tcpsocket->niovecs = niovecs;
                        }
                        niovecs = medusa_buffer_peek(tcpsocket->wbuffer, 0, -1, tcpsocket->iovecs, tcpsocket->niovecs);
                        if (niovecs <= 0) {
                                goto bail;
                        }
                        if (niovecs > tcpsocket->niovecs) {
                                goto bail;
                        }
                        rc = writev(tcpsocket->io.fd, tcpsocket->iovecs, niovecs);
                        if (rc < 0) {
                                if (errno == EINTR) {
                                } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                } else {
                                        goto bail;
                                }
                        } else if (rc == 0) {
                                tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                                tevents |= MEDUSA_TCPSOCKET_EVENT_DISCONNECTED;
                        } else {
                                rc = medusa_buffer_choke(tcpsocket->wbuffer, rc);
                                if (rc < 0) {
                                        goto bail;
                                }
                                tevents |= MEDUSA_TCPSOCKET_EVENT_WRITTEN;
                        }
#else
                        struct iovec iovec;
                        while (1) {
                                niovecs = medusa_buffer_peek(tcpsocket->wbuffer, 0, -1, &iovec, 1);
                                if (niovecs < 0) {
                                        goto bail;
                                }
                                if (niovecs == 0) {
                                        break;
                                }
                                rc = send(tcpsocket->io.fd, iovec.iov_base, iovec.iov_len, 0);
                                if (rc < 0) {
                                        if (errno == EINTR) {
                                                break;
                                        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                                break;
                                        }
                                        goto bail;
                                } else if (rc == 0) {
                                        tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                                        tevents |= MEDUSA_TCPSOCKET_EVENT_DISCONNECTED;
                                        break;
                                } else {
                                        rc = medusa_buffer_choke(tcpsocket->wbuffer, rc);
                                        if (rc < 0) {
                                                goto bail;
                                        }
                                        tevents |= MEDUSA_TCPSOCKET_EVENT_WRITTEN;
                                }
                                break;
                        }
#endif
                        length = medusa_buffer_get_length(tcpsocket->wbuffer);
                        if (length <= 0) {
                                tevents |= MEDUSA_TCPSOCKET_EVENT_WRITE_FINISHED;
                                rc = medusa_io_del_events_unlocked(&tcpsocket->io, MEDUSA_IO_EVENT_OUT);
                                if (rc < 0) {
                                        goto bail;
                                }
                        }
                } else {
                        goto bail;
                }
        }
        if (events & MEDUSA_IO_EVENT_IN) {
                if (tcpsocket_get_state(tcpsocket) == MEDUSA_TCPSOCKET_STATE_LISTENING) {
                        tevents |= MEDUSA_TCPSOCKET_EVENT_CONNECTION;
                } else if (tcpsocket_get_state(tcpsocket) == MEDUSA_TCPSOCKET_STATE_CONNECTED) {
                        int n;
                        n = 4096;
                        rc = ioctl(tcpsocket->io.fd, FIONREAD, &n);
                        if (rc < 0) {
                                n = 4096;
                        }
                        if (n < 0) {
                                goto bail;
                        }
#if defined(MEDUSA_TCPSOCKET_USE_READV) && (MEDUSA_TCPSOCKET_USE_READV == 1)
                        niovecs = medusa_buffer_reserve(tcpsocket->rbuffer, n, NULL, 0);
                        if (niovecs < 0) {
                                goto bail;
                        }
                        if (niovecs > tcpsocket->niovecs) {
                                struct iovec *tmp;
                                tmp = realloc(tcpsocket->iovecs, sizeof(struct iovec) * niovecs);
                                if (tmp == NULL) {
                                        tmp = malloc(sizeof(struct iovec) * niovecs);
                                        if (tmp == NULL) {
                                                goto bail;
                                        }
                                        if (tcpsocket->iovecs != NULL) {
                                                free(tcpsocket->iovecs);
                                        }
                                }
                                tcpsocket->iovecs = tmp;
                                tcpsocket->niovecs = niovecs;
                        }
                        niovecs = medusa_buffer_reserve(tcpsocket->rbuffer, n, tcpsocket->iovecs, tcpsocket->niovecs);
                        if (niovecs < 0) {
                                goto bail;
                        }
                        if (niovecs > tcpsocket->niovecs) {
                                goto bail;
                        }
                        rc = readv(tcpsocket->io.fd, tcpsocket->iovecs, niovecs);
                        if (rc < 0) {
                                if (errno == EINTR) {
                                } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                } else if (errno == ECONNRESET || errno == ECONNREFUSED || errno == ETIMEDOUT) {
                                        tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                                        tevents |= MEDUSA_TCPSOCKET_EVENT_DISCONNECTED;
                                } else {
                                        goto bail;
                                }
                        } else if (rc == 0) {
                                tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                                tevents |= MEDUSA_TCPSOCKET_EVENT_DISCONNECTED;
                        } else {
                                rc = medusa_buffer_commit(tcpsocket->rbuffer, tcpsocket->iovecs, niovecs);
                                if (rc < 0) {
                                        goto bail;
                                }
                                if (rc != niovecs) {
                                        goto bail;
                                }
                                tevents |= MEDUSA_TCPSOCKET_EVENT_READ;
                        }
#else
                        struct iovec iovec;
                        while (1) {
                                niovecs = medusa_buffer_reserve(tcpsocket->rbuffer, n, &iovec, 1);
                                if (niovecs < 0) {
                                        goto bail;
                                }
                                if (niovecs == 0) {
                                        tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                                        tevents |= MEDUSA_TCPSOCKET_EVENT_DISCONNECTED;
                                        break;
                                }
                                rc = recv(tcpsocket->io.fd, iovec.iov_base, iovec.iov_len, 0);
                                if (rc < 0) {
                                        if (errno == EINTR) {
                                                break;
                                        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                                break;
                                        } else if (errno == ECONNRESET || errno == ECONNREFUSED || errno == ETIMEDOUT) {
                                                tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                                                tevents |= MEDUSA_TCPSOCKET_EVENT_DISCONNECTED;
                                                break;
                                        } else {
                                                goto bail;
                                        }
                                } else if (rc == 0) {
                                        tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                                        tevents |= MEDUSA_TCPSOCKET_EVENT_DISCONNECTED;
                                        break;
                                } else {
                                        iovec.iov_len = rc;
                                        rc = medusa_buffer_commit(tcpsocket->rbuffer, &iovec, 1);
                                        if (rc < 0) {
                                                goto bail;
                                        }
                                        tevents |= MEDUSA_TCPSOCKET_EVENT_READ;
                                }
                                break;
                        }
#endif
                } else {
                        goto bail;
                }
        }
        if (events & MEDUSA_IO_EVENT_DESTROY) {
                tevents |= MEDUSA_TCPSOCKET_EVENT_DESTROY;
        }
        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, tevents);
        if (rc < 0) {
                goto bail;
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
        return medusa_tcpsocket_init_with_options(tcpsocket, &options);
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
        tcpsocket->io.fd = -1;
        tcpsocket->io.onevent = medusa_tcpsocket_io_onevent;
        tcpsocket->io.context = options->context;
        medusa_io_set_events(&tcpsocket->io, MEDUSA_IO_EVENT_IN);
        medusa_io_set_enabled(&tcpsocket->io, 0);
        tcpsocket->io.subject.flags = MEDUSA_SUBJECT_TYPE_IO | MEDUSA_SUBJECT_TYPE_TCPSOCKET;
        tcpsocket->io.subject.monitor = NULL;
        tcpsocket_set_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_NONE);
        tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
        tcpsocket->onevent = options->onevent;
        tcpsocket->rbuffer = medusa_buffer_create(MEDUSA_BUFFER_TYPE_CHUNKED);
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->rbuffer)) {
                return MEDUSA_PTR_ERR(tcpsocket->rbuffer);
        }
        tcpsocket->wbuffer = medusa_buffer_create(MEDUSA_BUFFER_TYPE_CHUNKED);
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->wbuffer)) {
                return MEDUSA_PTR_ERR(tcpsocket->wbuffer);
        }
        rc = medusa_monitor_add_unlocked(options->monitor, &tcpsocket->io.subject);
        if (rc < 0) {
                return rc;
        }
        rc = medusa_tcpsocket_set_nonblocking_unlocked(tcpsocket, options->nonblocking);
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
        rc = medusa_tcpsocket_set_enabled_unlocked(tcpsocket, options->enabled);
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
        if ((tcpsocket->io.subject.flags & MEDUSA_SUBJECT_TYPE_TCPSOCKET) == 0) {
                return;
        }
        if (tcpsocket->io.subject.monitor != NULL) {
                medusa_monitor_del_unlocked(&tcpsocket->io.subject);
        } else {
                medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DESTROY);
        }
}

__attribute__ ((visibility ("default"))) void medusa_tcpsocket_uninit (struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        medusa_tcpsocket_uninit_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
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
        tcpsocket->io.subject.flags |= MEDUSA_SUBJECT_FLAG_ALLOC;
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
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        medusa_tcpsocket_destroy_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_tcpsocket_get_state_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_TCPSOCKET_STATE_UNKNWON;
        }
        return tcpsocket_get_state(tcpsocket);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_tcpsocket_get_state (const struct medusa_tcpsocket *tcpsocket)
{
        unsigned int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_TCPSOCKET_STATE_UNKNWON;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_get_state_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_enabled_unlocked (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        return medusa_io_set_enabled_unlocked(&tcpsocket->io, enabled);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_enabled (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_TCPSOCKET_STATE_UNKNWON;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_set_enabled_unlocked(tcpsocket, enabled);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_enabled_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        return medusa_io_get_enabled(&tcpsocket->io);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_enabled (const struct medusa_tcpsocket *tcpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_TCPSOCKET_STATE_UNKNWON;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_get_enabled_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_nonblocking_unlocked (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (tcpsocket->io.fd >= 0) {
                int rc;
                int flags;
                flags = fcntl(tcpsocket->io.fd, F_GETFL, 0);
                if (flags < 0) {
                        return -errno;
                }
                flags = enabled ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
                rc = fcntl(tcpsocket->io.fd, F_SETFL, flags);
                if (rc != 0) {
                        return -errno;
                }
        }
        if (enabled) {
                tcpsocket_add_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_NONBLOCKING);
        } else {
                tcpsocket_del_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_NONBLOCKING);
        }
        return medusa_monitor_mod_unlocked(&tcpsocket->io.subject);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_nonblocking (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_TCPSOCKET_STATE_UNKNWON;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_set_nonblocking_unlocked(tcpsocket, enabled);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_nonblocking_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        return !!tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_NONBLOCKING);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_nonblocking (const struct medusa_tcpsocket *tcpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_TCPSOCKET_STATE_UNKNWON;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_get_nonblocking_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_reuseaddr_unlocked (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (tcpsocket->io.fd >= 0) {
                int rc;
                int on;
                on = !!enabled;
                rc = setsockopt(tcpsocket->io.fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
                if (rc < 0) {
                        return -errno;
                }
        }
        if (enabled) {
                tcpsocket_add_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_REUSEADDR);
        } else {
                tcpsocket_del_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_REUSEADDR);
        }
        return medusa_monitor_mod_unlocked(&tcpsocket->io.subject);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_reuseaddr (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_TCPSOCKET_STATE_UNKNWON;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_set_reuseaddr_unlocked(tcpsocket, enabled);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_reuseaddr_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        return !!tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_REUSEADDR);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_reuseaddr (const struct medusa_tcpsocket *tcpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_TCPSOCKET_STATE_UNKNWON;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_get_reuseaddr_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_reuseport_unlocked (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (tcpsocket->io.fd >= 0) {
                int rc;
                int on;
                on = !!enabled;
                rc = setsockopt(tcpsocket->io.fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
                if (rc < 0) {
                        return -errno;
                }
        }
        if (enabled) {
                tcpsocket_add_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_REUSEPORT);
        } else {
                tcpsocket_del_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_REUSEPORT);
        }
        return medusa_monitor_mod_unlocked(&tcpsocket->io.subject);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_reuseport (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_TCPSOCKET_STATE_UNKNWON;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_set_reuseport_unlocked(tcpsocket, enabled);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_reuseport_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        return !!tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_REUSEPORT);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_reuseport (const struct medusa_tcpsocket *tcpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_TCPSOCKET_STATE_UNKNWON;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_get_reuseport_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
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
        if (tcpsocket_get_state(tcpsocket) == MEDUSA_TCPSOCKET_STATE_LISTENING) {
                rc = listen(tcpsocket->io.fd, backlog);
                if (rc != 0) {
                        return -errno;
                }
        }
        tcpsocket->backlog = backlog;
        tcpsocket_add_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_BACKLOG);
        return medusa_monitor_mod_unlocked(&tcpsocket->io.subject);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_backlog (struct medusa_tcpsocket *tcpsocket, int backlog)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_TCPSOCKET_STATE_UNKNWON;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_set_backlog_unlocked(tcpsocket, backlog);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
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
                return MEDUSA_TCPSOCKET_STATE_UNKNWON;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_get_backlog_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_fd_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        return tcpsocket->io.fd;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_fd (const struct medusa_tcpsocket *tcpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_TCPSOCKET_STATE_UNKNWON;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_get_fd_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_bind_unlocked (struct medusa_tcpsocket *tcpsocket, unsigned int protocol, const char *address, unsigned short port)
{
        int rc;
        int ret;
        unsigned int length;
        struct sockaddr *sockaddr;
        struct sockaddr_in sockaddr_in;
        struct sockaddr_in6 sockaddr_in6;
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
                return -EIO;
        }
        if (tcpsocket->io.fd >= 0) {
                return -EIO;
        }
        tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_BINDING);
        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_BINDING);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        if (protocol == MEDUSA_TCPSOCKET_PROTOCOL_IPV4) {
ipv4:
                sockaddr_in.sin_family = AF_INET;
                if (address == NULL) {
                        sockaddr_in.sin_addr.s_addr = INADDR_ANY;
                } else {
                        rc = inet_pton(AF_INET, address, &sockaddr_in.sin_addr);
                        if (rc == 0) {
                                ret = -EINVAL;
                                goto bail;
                        } else if (rc < 0) {
                                ret = -errno;
                                goto bail;
                        }
                }
                sockaddr_in.sin_port = htons(port);
                sockaddr = (struct sockaddr *) &sockaddr_in;
                length = sizeof(struct sockaddr_in);
        } else if (protocol == MEDUSA_TCPSOCKET_PROTOCOL_IPV6) {
ipv6:
                sockaddr_in6.sin6_family = AF_INET;
                if (address == NULL) {
                        sockaddr_in6.sin6_addr = in6addr_any;
                } else {
                        rc = inet_pton(AF_INET6, address, &sockaddr_in6.sin6_addr);
                        if (rc == 0) {
                                ret = -EINVAL;
                                goto bail;
                        } else if (rc < 0) {
                                ret = -errno;
                                goto bail;
                        }
                }
                sockaddr_in6.sin6_port = htons(port);
                sockaddr = (struct sockaddr *) &sockaddr_in6;
                length = sizeof(struct sockaddr_in6);
        } else if (address == NULL) {
                sockaddr_in.sin_family = AF_INET;
                if (address == NULL) {
                        sockaddr_in.sin_addr.s_addr = INADDR_ANY;
                } else {
                        rc = inet_pton(AF_INET, address, &sockaddr_in.sin_addr);
                        if (rc == 0) {
                                ret = -EINVAL;
                                goto bail;
                        } else if (rc < 0) {
                                ret = -errno;
                                goto bail;
                        }
                }
                sockaddr_in.sin_port = htons(port);
                sockaddr = (struct sockaddr *) &sockaddr_in;
                length = sizeof(struct sockaddr_in);
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
        tcpsocket->io.fd = socket(sockaddr->sa_family, SOCK_STREAM, 0);
        if (tcpsocket->io.fd < 0) {
                ret = -errno;
                goto bail;
        }
        {
                int rc;
                int flags;
                flags = fcntl(tcpsocket->io.fd, F_GETFL, 0);
                if (flags < 0) {
                        ret = -errno;
                        goto bail;
                }
                flags = (!!tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_NONBLOCKING)) ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
                rc = fcntl(tcpsocket->io.fd, F_SETFL, flags);
                if (rc != 0) {
                        ret = -errno;
                        goto bail;
                }
        }
        {
                int rc;
                int on;
                on = !!tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_REUSEADDR);
                rc = setsockopt(tcpsocket->io.fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
                if (rc < 0) {
                        ret = -errno;
                        goto bail;
                }
        }
        {
                int rc;
                int on;
                on = !!tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_REUSEPORT);
                rc = setsockopt(tcpsocket->io.fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
                if (rc < 0) {
                        ret = -errno;
                        goto bail;
                }

        }
        rc = bind(tcpsocket->io.fd, sockaddr , length);
        if (rc != 0) {
                ret = -errno;
                goto bail;
        }
        tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_BOUND);
        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_BOUND);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        if (tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_BACKLOG)) {
                rc = listen(tcpsocket->io.fd, tcpsocket->backlog);
                if (rc != 0) {
                        ret = -errno;
                        goto bail;
                }
        }
        rc = medusa_io_set_events_unlocked(&tcpsocket->io, MEDUSA_IO_EVENT_IN);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_LISTENING);
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
                return MEDUSA_TCPSOCKET_STATE_UNKNWON;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_bind_unlocked(tcpsocket, protocol, address, port);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_connect_unlocked (struct medusa_tcpsocket *tcpsocket, unsigned int protocol, const char *address, unsigned short port)
{
        int rc;
        int ret;
        struct addrinfo hints;
        struct addrinfo *result;
        struct addrinfo *res;
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
        if (tcpsocket->io.fd >= 0) {
                return -EINVAL;
        }
        tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_RESOLVING);
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
        tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_RESOLVED);
        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_RESOLVED);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_CONNECTING);
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
                tcpsocket->io.fd = socket(res->ai_family, SOCK_STREAM, 0);
                if (tcpsocket->io.fd < 0) {
                        ret = -errno;
                        goto bail;
                }
                {
                        int rc;
                        int flags;
                        flags = fcntl(tcpsocket->io.fd, F_GETFL, 0);
                        if (flags < 0) {
                                ret = -errno;
                                goto bail;
                        }
                        flags = (!!tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_NONBLOCKING)) ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
                        rc = fcntl(tcpsocket->io.fd, F_SETFL, flags);
                        if (rc != 0) {
                                ret = -errno;
                                goto bail;
                        }
                }
                {
                        int rc;
                        int on;
                        on = !!tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_REUSEADDR);
                        rc = setsockopt(tcpsocket->io.fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
                        if (rc < 0) {
                                ret = -errno;
                                goto bail;
                        }
                }
                {
                        int rc;
                        int on;
                        on = !!tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_REUSEPORT);
                        rc = setsockopt(tcpsocket->io.fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
                        if (rc < 0) {
                                ret = -errno;
                                goto bail;
                        }

                }
                rc = connect(tcpsocket->io.fd, res->ai_addr, res->ai_addrlen);
                if (rc != 0) {
                        if (errno != EINPROGRESS &&
                            errno != EALREADY) {
                                close(tcpsocket->io.fd);
                                tcpsocket->io.fd = -1;
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
                tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_CONNECTED);
                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_CONNECTED);
                if (rc < 0) {
                        ret = rc;
                        goto bail;
                }
        } else {
                rc = medusa_io_add_events_unlocked(&tcpsocket->io, MEDUSA_IO_EVENT_OUT);
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
                return MEDUSA_TCPSOCKET_STATE_UNKNWON;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_connect_unlocked(tcpsocket, protocol, address, port);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
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
        options.tcpsocket = tcpsocket;
        options.onevent   = onevent;
        options.context   = context;
        return medusa_tcpsocket_accept_init_with_options_unlocked(accepted, &options);
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

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_accept_init_with_options_unlocked (struct medusa_tcpsocket *accepted, const struct medusa_tcpsocket_accept_options *options)
{
        int fd;
        int rc;
        struct medusa_tcpsocket_init_options accepted_options;
        if (MEDUSA_IS_ERR_OR_NULL(accepted)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                return -EINVAL;
        }
        fd = accept(options->tcpsocket->io.fd, NULL, NULL);
        if (fd < 0) {
                return -errno;
        }
        rc = medusa_tcpsocket_init_options_default(&accepted_options);
        if (rc < 0) {
                close(fd);
                return rc;
        }
        accepted_options.monitor     = medusa_tcpsocket_get_monitor_unlocked(options->tcpsocket);
        accepted_options.onevent     = options->onevent;
        accepted_options.context     = options->context;
        accepted_options.nonblocking = options->nonblocking;
        accepted_options.enabled     = options->enabled;
        rc = medusa_tcpsocket_init_with_options_unlocked(accepted, &accepted_options);
        if (rc < 0) {
                close(fd);
                return rc;
        }
        accepted->io.fd = fd;
        tcpsocket_set_state(accepted, MEDUSA_TCPSOCKET_STATE_CONNECTED);
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
        options.tcpsocket = tcpsocket;
        options.onevent   = onevent;
        options.context   = context;
        return medusa_tcpsocket_accept_with_options_unlocked(&options);
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

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_accept_with_options_unlocked (const struct medusa_tcpsocket_accept_options *options)
{
        int fd;
        int rc;
        struct medusa_tcpsocket *accepted;
        struct medusa_tcpsocket_init_options accepted_options;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        fd = accept(options->tcpsocket->io.fd, NULL, NULL);
        if (fd < 0) {
                return MEDUSA_ERR_PTR(-errno);
        }
        rc = medusa_tcpsocket_init_options_default(&accepted_options);
        if (rc < 0) {
                close(fd);
                return MEDUSA_ERR_PTR(rc);
        }
        accepted_options.monitor     = medusa_tcpsocket_get_monitor_unlocked(options->tcpsocket);
        accepted_options.onevent     = options->onevent;
        accepted_options.context     = options->context;
        accepted_options.nonblocking = options->nonblocking;
        accepted_options.enabled     = options->enabled;
        accepted = medusa_tcpsocket_create_with_options_unlocked(&accepted_options);
        if (MEDUSA_IS_ERR_OR_NULL(accepted)) {
                close(fd);
                return MEDUSA_ERR_PTR(MEDUSA_PTR_ERR(accepted));
        }
        accepted->io.fd = fd;
        tcpsocket_set_state(accepted, MEDUSA_TCPSOCKET_STATE_CONNECTED);
        rc = medusa_tcpsocket_onevent_unlocked(accepted, MEDUSA_TCPSOCKET_EVENT_CONNECTED);
        if (rc < 0) {
                medusa_tcpsocket_destroy_unlocked(accepted);
                return MEDUSA_ERR_PTR(rc);
        }
        return accepted;
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_accept_with_options (const struct medusa_tcpsocket_accept_options *options)
{
        struct medusa_tcpsocket *rc;
        struct medusa_monitor *monitor;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        monitor = medusa_tcpsocket_get_monitor(options->tcpsocket);
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(monitor);
        rc = medusa_tcpsocket_accept_with_options_unlocked(options);
        medusa_monitor_unlock(monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_read_unlocked (struct medusa_tcpsocket *tcpsocket, void *data, int64_t size)
{
        int rc;
        int64_t length;
        int i;
        int niovecs;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (size < 0) {
                return -EINVAL;
        }
        if (size == 0) {
                return 0;
        }
        if (data == NULL) {
                return -EINVAL;
        }
        length = medusa_buffer_get_length(tcpsocket->rbuffer);
        if (length < 0) {
                return length;
        }
        if (length == 0) {
                return 0;
        }
        niovecs = medusa_buffer_peek(tcpsocket->rbuffer, 0, size, NULL, 0);
        if (niovecs < 0) {
                return niovecs;
        }
        if (niovecs == 0) {
                return 0;
        }
        if (niovecs > tcpsocket->niovecs) {
                struct iovec *tmp;
                tmp = realloc(tcpsocket->iovecs, sizeof(struct iovec) * niovecs);
                if (tmp == NULL) {
                        tmp = malloc(sizeof(struct iovec) * niovecs);
                        if (tmp == NULL) {
                                return -ENOMEM;
                        }
                        if (tcpsocket->iovecs != NULL) {
                                free(tcpsocket->iovecs);
                        }
                }
                tcpsocket->iovecs = tmp;
                tcpsocket->niovecs = niovecs;
        }
        niovecs = medusa_buffer_peek(tcpsocket->rbuffer, 0, size, tcpsocket->iovecs, niovecs);
        if (niovecs < 0) {
                return niovecs;
        }
        if (niovecs == 0) {
                return -EIO;
        }
        for (length = 0, i = 0; i < niovecs; i++) {
                memcpy(data + length, tcpsocket->iovecs[i].iov_base, tcpsocket->iovecs[i].iov_len);
                length += tcpsocket->iovecs[i].iov_len;
        }
        rc = medusa_buffer_choke(tcpsocket->rbuffer, length);
        if (rc < 0) {
                return rc;
        }
        return length;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_read (struct medusa_tcpsocket *tcpsocket, void *data, int64_t size)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_read_unlocked(tcpsocket, data, size);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int64_t medusa_tcpsocket_get_read_length_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->rbuffer)) {
                return -EIO;
        }
        return medusa_buffer_get_length(tcpsocket->rbuffer);
}

__attribute__ ((visibility ("default"))) int64_t medusa_tcpsocket_get_read_length (const struct medusa_tcpsocket *tcpsocket)
{
        int64_t rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_get_read_length_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_read_buffer_unlocked (struct medusa_tcpsocket *tcpsocket, struct medusa_buffer *buffer)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->rbuffer)) {
                medusa_buffer_destroy(tcpsocket->rbuffer);
        }
        tcpsocket->rbuffer = buffer;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_read_buffer (struct medusa_tcpsocket *tcpsocket, struct medusa_buffer *buffer)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_set_read_buffer_unlocked(tcpsocket, buffer);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_buffer * medusa_tcpsocket_get_read_buffer_unlocked (struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return tcpsocket->rbuffer;
}

__attribute__ ((visibility ("default"))) struct medusa_buffer * medusa_tcpsocket_get_read_buffer (struct medusa_tcpsocket *tcpsocket)
{
        struct medusa_buffer *rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_get_read_buffer_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_write_unlocked (struct medusa_tcpsocket *tcpsocket, const void *data, int64_t size)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (size < 0) {
                return -EINVAL;
        }
        if (size == 0) {
                return 0;
        }
        if (data == NULL) {
                return -EINVAL;
        }
        size = medusa_buffer_append(tcpsocket->wbuffer, data, size);
        if (size < 0) {
                return size;
        }
        if (size > 0) {
                rc = medusa_io_add_events_unlocked(&tcpsocket->io, MEDUSA_IO_EVENT_OUT);
                if (rc < 0) {
                        return rc;
                }
        }
        return size;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_write (struct medusa_tcpsocket *tcpsocket, const void *data, int64_t size)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_write_unlocked(tcpsocket, data, size);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_writev_unlocked (struct medusa_tcpsocket *tcpsocket, const struct iovec *iovecs, int niovecs)
{
        int rc;
        int64_t size;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (niovecs < 0) {
                return -EINVAL;
        }
        if (niovecs == 0) {
                return 0;
        }
        if (MEDUSA_IS_ERR_OR_NULL(iovecs)) {
                return -EINVAL;
        }
        size = medusa_buffer_appendv(tcpsocket->wbuffer, iovecs, niovecs);
        if (size < 0) {
                return size;
        }
        if (size > 0) {
                rc = medusa_io_add_events_unlocked(&tcpsocket->io, MEDUSA_IO_EVENT_OUT);
                if (rc < 0) {
                        return rc;
                }
        }
        return size;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_writev (struct medusa_tcpsocket *tcpsocket, const struct iovec *iovecs, int niovecs)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_writev_unlocked(tcpsocket, iovecs, niovecs);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_printf_unlocked (struct medusa_tcpsocket *tcpsocket, const char *format, ...)
{
        int rc;
        va_list va;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(format)) {
                return -EINVAL;
        }
        va_start(va, format);
        rc = medusa_tcpsocket_vprintf_unlocked(tcpsocket, format, va);
        va_end(va);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_printf (struct medusa_tcpsocket *tcpsocket, const char *format, ...)
{
        int rc;
        va_list va;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(format)) {
                return -EINVAL;
        }
        va_start(va, format);
        rc = medusa_tcpsocket_vprintf(tcpsocket, format, va);
        va_end(va);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_vprintf_unlocked (struct medusa_tcpsocket *tcpsocket, const char *format, va_list va)
{
        int rc;
        int size;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->wbuffer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(format)) {
                return -EINVAL;
        }
        size = medusa_buffer_vprintf(tcpsocket->wbuffer, format, va);
        if (size < 0) {
                return size;
        }
        if (size > 0) {
                rc = medusa_io_add_events_unlocked(&tcpsocket->io, MEDUSA_IO_EVENT_OUT);
                if (rc < 0) {
                        return rc;
                }
        }
        return size;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_vprintf (struct medusa_tcpsocket *tcpsocket, const char *format, va_list va)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_vprintf_unlocked(tcpsocket, format, va);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int64_t medusa_tcpsocket_get_write_length_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->wbuffer)) {
                return -EIO;
        }
        return medusa_buffer_get_length(tcpsocket->wbuffer);
}

__attribute__ ((visibility ("default"))) int64_t medusa_tcpsocket_get_write_length (const struct medusa_tcpsocket *tcpsocket)
{
        int64_t rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_get_write_length_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_write_buffer_unlocked (struct medusa_tcpsocket *tcpsocket, struct medusa_buffer *buffer)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->wbuffer)) {
                medusa_buffer_destroy(tcpsocket->wbuffer);
        }
        tcpsocket->wbuffer = buffer;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_write_buffer (struct medusa_tcpsocket *tcpsocket, struct medusa_buffer *buffer)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_set_write_buffer_unlocked(tcpsocket, buffer);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_buffer * medusa_tcpsocket_get_write_buffer_unlocked (struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return tcpsocket->wbuffer;
}

__attribute__ ((visibility ("default"))) struct medusa_buffer * medusa_tcpsocket_get_write_buffer (struct medusa_tcpsocket *tcpsocket)
{
        struct medusa_buffer *rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_get_write_buffer_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_onevent_unlocked (struct medusa_tcpsocket *tcpsocket, unsigned int events)
{
        int rc;
        unsigned int type;
        struct medusa_monitor *monitor;
        rc = 0;
        type = tcpsocket->io.subject.flags & MEDUSA_SUBJECT_TYPE_MASK;
        monitor = tcpsocket->io.subject.monitor;
        if (tcpsocket->onevent != NULL) {
                medusa_monitor_unlock(monitor);
                rc = tcpsocket->onevent(tcpsocket, events, tcpsocket->io.context);
                medusa_monitor_lock(monitor);
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_DESTROY) {
                if (type == (MEDUSA_SUBJECT_TYPE_IO | MEDUSA_SUBJECT_TYPE_TCPSOCKET)) {
                        if (tcpsocket->rbuffer != NULL) {
                                medusa_buffer_destroy(tcpsocket->rbuffer);
                                tcpsocket->rbuffer = NULL;
                        }
                        if (tcpsocket->wbuffer != NULL) {
                                medusa_buffer_destroy(tcpsocket->wbuffer);
                                tcpsocket->wbuffer = NULL;
                        }
                        if (tcpsocket->iovecs != NULL) {
                                free(tcpsocket->iovecs);
                        }
                        if (tcpsocket->io.fd >= 0) {
                                close(tcpsocket->io.fd);
                                tcpsocket->io.fd = -1;
                        }
                        if (tcpsocket->io.subject.flags & MEDUSA_SUBJECT_FLAG_ALLOC) {
#if defined(MEDUSA_TCPSOCKET_USE_POOL) && (MEDUSA_TCPSOCKET_USE_POOL == 1)
                                medusa_pool_free(tcpsocket);
#else
                                free(tcpsocket);
#endif
                        } else {
                                memset(tcpsocket, 0, sizeof(struct medusa_tcpsocket));
                        }
                }
        }
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, events);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_tcpsocket_get_monitor_unlocked (struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return tcpsocket->io.subject.monitor;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_tcpsocket_get_monitor (struct medusa_tcpsocket *tcpsocket)
{
        struct medusa_monitor *rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(tcpsocket->io.subject.monitor);
        rc = medusa_tcpsocket_get_monitor_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->io.subject.monitor);
        return rc;
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
