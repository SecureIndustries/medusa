
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <errno.h>

#if defined(MEDUSA_TCPSOCKET_OPENSSL_ENABLE) && (MEDUSA_TCPSOCKET_OPENSSL_ENABLE == 1)
#include <openssl/ssl.h>
#include <openssl/err.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define TLS_ST_OK SSL_ST_OK
#endif

#endif

#include "error.h"
#include "pool.h"
#include "queue.h"
#include "iovec.h"
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
#define MAX(a, b)                               (((a) > (b)) ? (a) : (b))

#define MEDUSA_TCPSOCKET_USE_POOL               1

#define MEDUSA_TCPSOCKET_DEFAULT_BACKLOG        128
#define MEDUSA_TCPSOCKET_DEFAULT_IOVECS         4

enum {
        MEDUSA_TCPSOCKET_FLAG_NONE              = (1 <<  0),
        MEDUSA_TCPSOCKET_FLAG_BIND              = (1 <<  1),
        MEDUSA_TCPSOCKET_FLAG_ACCEPT            = (1 <<  2),
        MEDUSA_TCPSOCKET_FLAG_CONNECT           = (1 <<  3),
        MEDUSA_TCPSOCKET_FLAG_ATTACH            = (1 <<  4),
        MEDUSA_TCPSOCKET_FLAG_ENABLED           = (1 <<  5),
        MEDUSA_TCPSOCKET_FLAG_BUFFERED          = (1 <<  6),
        MEDUSA_TCPSOCKET_FLAG_NONBLOCKING       = (1 <<  7),
        MEDUSA_TCPSOCKET_FLAG_NODELAY           = (1 <<  8),
        MEDUSA_TCPSOCKET_FLAG_REUSEADDR         = (1 <<  9),
        MEDUSA_TCPSOCKET_FLAG_REUSEPORT         = (1 << 10),
        MEDUSA_TCPSOCKET_FLAG_BACKLOG           = (1 << 11),
        MEDUSA_TCPSOCKET_FLAG_CLODESTROY        = (1 << 12),
        MEDUSA_TCPSOCKET_FLAG_SSL               = (1 << 13),
        MEDUSA_TCPSOCKET_FLAG_SSL_CTX_EXTERNAL  = (1 << 14),
        MEDUSA_TCPSOCKET_FLAG_SSL_EXTERNAL      = (1 << 15),
        MEDUSA_TCPSOCKET_FLAG_SSL_STATE_OK      = (1 << 16)
#define MEDUSA_TCPSOCKET_FLAG_NONE              MEDUSA_TCPSOCKET_FLAG_NONE
#define MEDUSA_TCPSOCKET_FLAG_BIND              MEDUSA_TCPSOCKET_FLAG_BIND
#define MEDUSA_TCPSOCKET_FLAG_ACCEPT            MEDUSA_TCPSOCKET_FLAG_ACCEPT
#define MEDUSA_TCPSOCKET_FLAG_CONNECT           MEDUSA_TCPSOCKET_FLAG_CONNECT
#define MEDUSA_TCPSOCKET_FLAG_ATTACH            MEDUSA_TCPSOCKET_FLAG_ATTACH
#define MEDUSA_TCPSOCKET_FLAG_ENABLED           MEDUSA_TCPSOCKET_FLAG_ENABLED
#define MEDUSA_TCPSOCKET_FLAG_BUFFERED          MEDUSA_TCPSOCKET_FLAG_BUFFERED
#define MEDUSA_TCPSOCKET_FLAG_NONBLOCKING       MEDUSA_TCPSOCKET_FLAG_NONBLOCKING
#define MEDUSA_TCPSOCKET_FLAG_NODELAY           MEDUSA_TCPSOCKET_FLAG_NODELAY
#define MEDUSA_TCPSOCKET_FLAG_REUSEADDR         MEDUSA_TCPSOCKET_FLAG_REUSEADDR
#define MEDUSA_TCPSOCKET_FLAG_REUSEPORT         MEDUSA_TCPSOCKET_FLAG_REUSEPORT
#define MEDUSA_TCPSOCKET_FLAG_BACKLOG           MEDUSA_TCPSOCKET_FLAG_BACKLOG
#define MEDUSA_TCPSOCKET_FLAG_CLODESTROY        MEDUSA_TCPSOCKET_FLAG_CLODESTROY
#define MEDUSA_TCPSOCKET_FLAG_SSL               MEDUSA_TCPSOCKET_FLAG_SSL
#define MEDUSA_TCPSOCKET_FLAG_SSL_CTX_EXTERNAL  MEDUSA_TCPSOCKET_FLAG_SSL_CTX_EXTERNAL
#define MEDUSA_TCPSOCKET_FLAG_SSL_EXTERNAL      MEDUSA_TCPSOCKET_FLAG_SSL_EXTERNAL
#define MEDUSA_TCPSOCKET_FLAG_SSL_STATE_OK      MEDUSA_TCPSOCKET_FLAG_SSL_STATE_OK
};

#if defined(MEDUSA_TCPSOCKET_USE_POOL) && (MEDUSA_TCPSOCKET_USE_POOL == 1)
static struct medusa_pool *g_pool;
#endif

static inline void tcpsocket_set_flag (struct medusa_tcpsocket *tcpsocket, unsigned int flag)
{
        tcpsocket->flags = flag;
}

static inline void tcpsocket_add_flag (struct medusa_tcpsocket *tcpsocket, unsigned int flag)
{
        tcpsocket->flags |= flag;
}

static inline void tcpsocket_del_flag (struct medusa_tcpsocket *tcpsocket, unsigned int flag)
{
        tcpsocket->flags &= ~flag;
}

static inline int tcpsocket_has_flag (const struct medusa_tcpsocket *tcpsocket, unsigned int flag)
{
        return !!(tcpsocket->flags & flag);
}

static inline int tcpsocket_get_buffered (const struct medusa_tcpsocket *tcpsocket)
{
        return tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_BUFFERED);
}

static inline int tcpsocket_set_state (struct medusa_tcpsocket *tcpsocket, unsigned int state)
{
        int rc;
        tcpsocket->error = 0;
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
#if defined(MEDUSA_TCPSOCKET_OPENSSL_ENABLE) && (MEDUSA_TCPSOCKET_OPENSSL_ENABLE == 1)
                if (tcpsocket->ssl != NULL) {
                        if (tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_ACCEPT)) {
                                rc = SSL_accept(tcpsocket->ssl);
                        } else {
                                rc = SSL_connect(tcpsocket->ssl);
                        }
                        if (rc <= 0) {
                                int error;
                                error = SSL_get_error(tcpsocket->ssl, rc);
                                if (error == SSL_ERROR_WANT_READ) {
                                        tcpsocket->ssl_wantread = 1;
                                } else if (error == SSL_ERROR_WANT_WRITE) {
                                        tcpsocket->ssl_wantwrite = 1;
                                } else if (error == SSL_ERROR_SYSCALL) {
                                        tcpsocket->ssl_wantread = 1;
                                } else {
                                        return -EIO;
                                }
                        }
                }
#endif
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
        tcpsocket->state = state;
        return 0;
}

static int tcpsocket_ctimer_onevent (struct medusa_timer *timer, unsigned int events, void *context, void *param)
{
        int rc;
        struct medusa_monitor *monitor;
        struct medusa_tcpsocket *tcpsocket = (struct medusa_tcpsocket *) context;

        (void) timer;
        (void) param;

        if (events & MEDUSA_TIMER_EVENT_TIMEOUT) {
                monitor = medusa_tcpsocket_get_monitor(tcpsocket);
                medusa_monitor_lock(monitor);

                rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                if (rc < 0) {
                        medusa_monitor_unlock(monitor);
                        goto bail;
                }
                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_CONNECT_TIMEOUT, NULL);

                medusa_monitor_unlock(monitor);
                return rc;
        }

        return 0;
bail:   return -1;
}

static int tcpsocket_rtimer_onevent (struct medusa_timer *timer, unsigned int events, void *context, void *param)
{
        int rc;
        struct medusa_monitor *monitor;
        struct medusa_tcpsocket *tcpsocket = (struct medusa_tcpsocket *) context;

        (void) timer;
        (void) param;

        if (events & MEDUSA_TIMER_EVENT_TIMEOUT) {
                monitor = medusa_tcpsocket_get_monitor(tcpsocket);
                medusa_monitor_lock(monitor);

                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, tcpsocket_get_buffered(tcpsocket) ? MEDUSA_TCPSOCKET_EVENT_BUFFERED_READ_TIMEOUT : MEDUSA_TCPSOCKET_EVENT_IN_TIMEOUT, NULL);
                if (rc < 0) {
                        medusa_monitor_unlock(monitor);
                        goto bail;
                }

                medusa_monitor_unlock(monitor);
                return rc;
        }

        return 0;
bail:   medusa_monitor_unlock(monitor);
        return -1;
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
        if ((tcpsocket->state == MEDUSA_TCPSOCKET_STATE_CONNECTED) &&
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

static int tcpsocket_wbuffer_onevent (struct medusa_buffer *buffer, unsigned int events, void *context, void *param)
{
        struct medusa_tcpsocket *tcpsocket = (struct medusa_tcpsocket *) context;
        (void) buffer;
        (void) param;
        if (events & MEDUSA_BUFFER_EVENT_WRITE) {
                return tcpsocket_wbuffer_commit(tcpsocket);
        }
        return 0;
}

static int tcpsocket_io_onevent (struct medusa_io *io, unsigned int events, void *context, void *param)
{
        int rc;
        struct medusa_monitor *monitor;
        struct medusa_tcpsocket *tcpsocket = context;

        (void) param;

        monitor = medusa_io_get_monitor(io);
        medusa_monitor_lock(monitor);

        if (events & MEDUSA_IO_EVENT_OUT) {
                if (tcpsocket->state == MEDUSA_TCPSOCKET_STATE_DISCONNECTED) {
                } else if (tcpsocket->state == MEDUSA_TCPSOCKET_STATE_CONNECTING) {
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
                                tcpsocket->error = valopt;
                                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_ERROR, NULL);
                                if (rc < 0) {
                                        goto bail;
                                }
                                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DISCONNECTED, NULL);
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
                                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_CONNECTED, NULL);
                                if (rc < 0) {
                                        goto bail;
                                }
                        }
                } else if (tcpsocket->state == MEDUSA_TCPSOCKET_STATE_CONNECTED) {
                        if (!tcpsocket_get_buffered(tcpsocket)) {
                                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_OUT, NULL);
                                if (rc < 0) {
                                        goto bail;
                                }
                        } else {
                                int64_t blength;
                                int64_t wlength;
                                int64_t clength;
                                int64_t niovecs;
                                struct medusa_iovec iovec;
                                while (1) {
                                        niovecs = medusa_buffer_peekv(tcpsocket->wbuffer, 0, -1, &iovec, 1);
                                        if (niovecs < 0) {
                                                goto bail;
                                        }
                                        if (niovecs == 0) {
                                                break;
                                        }
#if defined(MEDUSA_TCPSOCKET_OPENSSL_ENABLE) && (MEDUSA_TCPSOCKET_OPENSSL_ENABLE == 1)
                                        if (tcpsocket->ssl != NULL) {
                                                wlength = SSL_write(tcpsocket->ssl, iovec.iov_base, iovec.iov_len);
                                                if (wlength <= 0) {
                                                        int error;
                                                        error = SSL_get_error(tcpsocket->ssl, wlength);
                                                        if (error == SSL_ERROR_WANT_READ) {
                                                                wlength = -1;
                                                                errno = EAGAIN;
                                                                tcpsocket->ssl_wantread = 1;
                                                                rc = medusa_io_del_events_unlocked(io, MEDUSA_IO_EVENT_OUT);
                                                                if (rc < 0) {
                                                                        goto bail;
                                                                }
                                                        } else if (error == SSL_ERROR_WANT_WRITE) {
                                                                wlength = -1;
                                                                errno = EAGAIN;
                                                                tcpsocket->ssl_wantwrite = 1;
                                                                rc = medusa_io_del_events_unlocked(io, MEDUSA_IO_EVENT_OUT);
                                                                if (rc < 0) {
                                                                        goto bail;
                                                                }
                                                        } else if (error == SSL_ERROR_SYSCALL) {
                                                                wlength = -1;
                                                                errno = EIO;
                                                        } else {
                                                                wlength = -1;
                                                                errno = EIO;
                                                        }
                                                }
                                                if (!tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_SSL_STATE_OK) &&
                                                    SSL_get_state(tcpsocket->ssl) == TLS_ST_OK) {
                                                        tcpsocket_add_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_SSL_STATE_OK);
                                                        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_CONNECTED_SSL, NULL);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                }
                                        } else
#endif
                                        {
                                                wlength = send(medusa_io_get_fd_unlocked(io), iovec.iov_base, iovec.iov_len, 0);
                                        }
                                        if (wlength < 0) {
                                                if (errno == EINTR ||
                                                    errno == EAGAIN ||
                                                    errno == EWOULDBLOCK) {
                                                } else {
                                                        rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                        tcpsocket->error = errno;
                                                        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_ERROR, NULL);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DISCONNECTED, NULL);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                }
                                        } else if (wlength == 0) {
                                                rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                                                if (rc < 0) {
                                                        goto bail;
                                                }
                                                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DISCONNECTED, NULL);
                                                if (rc < 0) {
                                                        goto bail;
                                                }
                                        } else {
                                                struct medusa_tcpsocket_event_buffered_write medusa_tcpsocket_event_buffered_write;
                                                clength = medusa_buffer_choke(tcpsocket->wbuffer, 0, wlength);
                                                if (clength < 0) {
                                                        goto bail;
                                                }
                                                if (clength != wlength) {
                                                        goto bail;
                                                }
                                                medusa_tcpsocket_event_buffered_write.length    = wlength;
                                                medusa_tcpsocket_event_buffered_write.remaining = medusa_buffer_get_length(tcpsocket->wbuffer);
                                                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_BUFFERED_WRITE, &medusa_tcpsocket_event_buffered_write);
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
                                        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_BUFFERED_WRITE_FINISHED, NULL);
                                        if (rc < 0) {
                                                goto bail;
                                        }
                                }
                        }
                } else {
                        goto bail;
                }
        } else if (events & MEDUSA_IO_EVENT_IN) {
                if (tcpsocket->state == MEDUSA_TCPSOCKET_STATE_DISCONNECTED) {
                } else if (tcpsocket->state == MEDUSA_TCPSOCKET_STATE_LISTENING) {
                        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_CONNECTION, NULL);
                        if (rc < 0) {
                                goto bail;
                        }
                } else if (tcpsocket->state == MEDUSA_TCPSOCKET_STATE_CONNECTED) {
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
                                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_IN, NULL);
                                if (rc < 0) {
                                        goto bail;
                                }
                        } else {
                                int n;
                                int64_t clength;
                                int64_t rlength;
                                int64_t niovecs;
                                struct medusa_iovec iovec;
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
                                                        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DISCONNECTED, NULL);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                } else {
                                                        rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                        tcpsocket->error = EIO;
                                                        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_ERROR, NULL);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DISCONNECTED, NULL);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                }
                                                break;
                                        }
#if defined(MEDUSA_TCPSOCKET_OPENSSL_ENABLE) && (MEDUSA_TCPSOCKET_OPENSSL_ENABLE == 1)
                                        if (tcpsocket->ssl != NULL) {
                                                if (tcpsocket->ssl_wantread ||
                                                    tcpsocket->ssl_wantwrite) {
                                                        int64_t blength;
                                                        blength = medusa_buffer_get_length(tcpsocket->wbuffer);
                                                        if (blength < 0) {
                                                                return blength;
                                                        } else if (blength > 0) {
                                                                rc = medusa_io_add_events_unlocked(tcpsocket->io, MEDUSA_IO_EVENT_OUT);
                                                                if (rc < 0) {
                                                                        return rc;
                                                                }
                                                        }
                                                        tcpsocket->ssl_wantread  = 0;
                                                        tcpsocket->ssl_wantwrite = 0;
                                                }
                                                rlength = SSL_read(tcpsocket->ssl, iovec.iov_base, iovec.iov_len);
                                                if (rlength <= 0) {
                                                        int error;
                                                        error = SSL_get_error(tcpsocket->ssl, rlength);
                                                        if (iovec.iov_len == 0) {
                                                                rlength = -1;
                                                                errno = EAGAIN;
                                                        } else if (error == SSL_ERROR_WANT_READ) {
                                                                rlength = -1;
                                                                errno = EAGAIN;
                                                        } else if (error == SSL_ERROR_WANT_WRITE) {
                                                                rlength = -1;
                                                                errno = EAGAIN;
                                                        } else if (error == SSL_ERROR_SYSCALL) {
                                                                rlength = -1;
                                                                errno = EIO;
                                                        } else if (error == SSL_ERROR_ZERO_RETURN) {
                                                                rlength = 0;
                                                                errno = 0;
                                                        } else {
                                                                rlength = -1;
                                                                errno = EIO;
                                                        }
                                                }
                                                if (!tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_SSL_STATE_OK) &&
                                                    SSL_get_state(tcpsocket->ssl) == TLS_ST_OK) {
                                                        tcpsocket_add_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_SSL_STATE_OK);
                                                        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_CONNECTED_SSL, NULL);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                }
                                        } else
#endif
                                        {
                                                rlength = recv(medusa_io_get_fd_unlocked(io), iovec.iov_base, iovec.iov_len, 0);
                                        }
                                        if (rlength < 0) {
                                                if (errno != EINTR &&
                                                    errno != EAGAIN &&
                                                    errno != EWOULDBLOCK) {
                                                        rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                        tcpsocket->error = errno;
                                                        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_ERROR, NULL);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DISCONNECTED, NULL);
                                                        if (rc < 0) {
                                                                goto bail;
                                                        }
                                                }
                                                break;
                                        } else if (rlength == 0) {
                                                rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                                                if (rc < 0) {
                                                        goto bail;
                                                }
                                                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DISCONNECTED, NULL);
                                                if (rc < 0) {
                                                        goto bail;
                                                }
                                                break;
                                        } else {
                                                iovec.iov_len = rlength;
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
                                                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_BUFFERED_READ, NULL);
                                                if (rc < 0) {
                                                        goto bail;
                                                }
                                        }
#if defined(MEDUSA_TCPSOCKET_OPENSSL_ENABLE) && (MEDUSA_TCPSOCKET_OPENSSL_ENABLE == 1)
#else
                                        break;
#endif
                                 }
                        }
                } else {
                        goto bail;
                }
        } else if (events & MEDUSA_IO_EVENT_ERR) {
                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_ERROR, NULL);
                if (rc < 0) {
                        goto bail;
                }
        } else if (events & MEDUSA_IO_EVENT_HUP) {
                rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                if (rc < 0) {
                        goto bail;
                }
                tcpsocket->error = ECONNRESET;
                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_ERROR, NULL);
                if (rc < 0) {
                        goto bail;
                }
                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DISCONNECTED, NULL);
                if (rc < 0) {
                        goto bail;
                }
        } else if (events & MEDUSA_IO_EVENT_DESTROY) {
        }
        medusa_monitor_unlock(monitor);
        return 0;
bail:   medusa_monitor_unlock(monitor);
        return -EIO;
}

static int tcpsocket_init_unlocked (struct medusa_tcpsocket *tcpsocket, struct medusa_monitor *monitor, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, void *param), void *context)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(onevent)) {
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
        tcpsocket->onevent = onevent;
        tcpsocket->context = context;
        return medusa_monitor_add_unlocked(monitor, &tcpsocket->subject);
}

static void tcpsocket_uninit_unlocked (struct medusa_tcpsocket *tcpsocket)
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
                medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DESTROY, NULL);
        }
}

static struct medusa_tcpsocket * tcpsocket_create_unlocked (struct medusa_monitor *monitor, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, void *param), void *context)
{
        int rc;
        struct medusa_tcpsocket *tcpsocket;
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(onevent)) {
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
        rc = tcpsocket_init_unlocked(tcpsocket, monitor, onevent, context);
        if (rc < 0) {
                medusa_tcpsocket_destroy_unlocked(tcpsocket);
                return MEDUSA_ERR_PTR(rc);
        }
        return tcpsocket;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_bind_options_default (struct medusa_tcpsocket_bind_options *options)
{
        if (options == NULL) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_tcpsocket_bind_options));
        options->protocol   = MEDUSA_TCPSOCKET_PROTOCOL_ANY;
        options->backlog    = 128;
        options->fd         = -1;
        options->clodestroy = 1;
        return 0;
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_bind_with_options_unlocked (const struct medusa_tcpsocket_bind_options *options)
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
        struct medusa_tcpsocket *tcpsocket;

        tcpsocket = NULL;

        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                ret = -EINVAL;
                goto bail;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                ret = -EINVAL;
                goto bail;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                ret = -EINVAL;
                goto bail;
        }

        protocol = options->protocol;
        address  = options->address;
        port     = options->port;

        if (protocol == MEDUSA_TCPSOCKET_PROTOCOL_IPV4) {
ipv4:
                memset(&sockaddr_in, 0, sizeof(sockaddr_in));
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
                        ret = -EINVAL;
                        goto bail;
                }
                sockaddr_in.sin_port = htons(port);
                sockaddr = (struct sockaddr *) &sockaddr_in;
                length = sizeof(struct sockaddr_in);
        } else if (protocol == MEDUSA_TCPSOCKET_PROTOCOL_IPV6) {
ipv6:
                memset(&sockaddr_in6, 0, sizeof(sockaddr_in6));
                sockaddr_in6.sin6_family = AF_INET6;
                if (address == NULL) {
                        address = "0.0.0.0";
                } else if (strcmp(address, "localhost") == 0) {
                        address = "::1";
                } else if (strcmp(address, "loopback") == 0) {
                        address = "::1";
                }
                rc = inet_pton(AF_INET6, address, &sockaddr_in6.sin6_addr);
                if (rc == 0) {
                        ret = -EINVAL;
                        goto bail;
                } else if (rc < 0) {
                        ret = -EINVAL;
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
                ret = -EINVAL;
                goto bail;
        }

        tcpsocket = tcpsocket_create_unlocked(options->monitor, options->onevent, options->context);
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                ret = MEDUSA_PTR_ERR(tcpsocket);
                goto bail;
        }
        tcpsocket_add_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_BIND);

        rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_BINDING);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_BINDING, NULL);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }

        if (options->fd >= 0) {
                fd = options->fd;
        } else {
                fd = socket(sockaddr->sa_family, SOCK_STREAM, 0);
        }
        if (fd < 0) {
                ret = -errno;
                goto bail;
        }
        {
                int rc;
                int on;
                on = !!options->reuseaddr;
                rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
                if (rc < 0) {
                        if (options->fd < 0 ||
                            options->clodestroy == 1) {
                                close(fd);
                        }
                        ret = -errno;
                        goto bail;
                }
        }
        {
                int rc;
                int on;
                on = !!options->reuseport;
                rc = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
                if (rc < 0) {
                        if (options->fd < 0 ||
                            options->clodestroy == 1) {
                                close(fd);
                        }
                        ret = -errno;
                        goto bail;
                }
        }
        rc = bind(fd, sockaddr , length);
        if (rc != 0) {
                if (options->fd < 0 ||
                    options->clodestroy == 1) {
                        close(fd);
                }
                ret = -errno;
                goto bail;
        }

        rc = medusa_io_init_options_default(&io_init_options);
        if (rc < 0) {
                if (options->fd < 0 ||
                    options->clodestroy == 1) {
                        close(fd);
                }
                ret = rc;
                goto bail;
        }
        io_init_options.monitor    = tcpsocket->subject.monitor;
        io_init_options.fd         = fd;
        io_init_options.events     = MEDUSA_IO_EVENT_IN;
        io_init_options.onevent    = tcpsocket_io_onevent;
        io_init_options.context    = tcpsocket;
        io_init_options.clodestroy = options->clodestroy;
        io_init_options.enabled    = 0;
        tcpsocket->io = medusa_io_create_with_options_unlocked(&io_init_options);
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                ret = MEDUSA_PTR_ERR(tcpsocket->io);
                goto bail;
        }

        rc = medusa_tcpsocket_set_reuseaddr_unlocked(tcpsocket, options->reuseaddr);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_set_reuseport_unlocked(tcpsocket, options->reuseport);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_set_nonblocking_unlocked(tcpsocket, options->nonblocking);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_set_nodelay_unlocked(tcpsocket, options->nodelay);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_set_backlog_unlocked(tcpsocket, options->backlog);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_set_buffered_unlocked(tcpsocket, options->buffered);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_set_clodestroy_unlocked(tcpsocket, options->clodestroy);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_set_enabled_unlocked(tcpsocket, options->enabled);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_BOUND);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_BOUND, NULL);
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
        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_LISTENING, NULL);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }

        return tcpsocket;
bail:   if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(ret);
        }
        tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
        tcpsocket->error = -ret;
        medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_ERROR, NULL);
        medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DISCONNECTED, NULL);
        return tcpsocket;
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_bind_with_options (const struct medusa_tcpsocket_bind_options *options)
{
        struct medusa_tcpsocket *rc;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(options->monitor);
        rc = medusa_tcpsocket_bind_with_options_unlocked(options);
        medusa_monitor_unlock(options->monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_bind_unlocked (struct medusa_monitor *monitor, unsigned int protocol, const char *address, unsigned short port, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, void *param), void *context)
{
        int rc;
        struct medusa_tcpsocket_bind_options options;
        rc = medusa_tcpsocket_bind_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.monitor  = monitor;
        options.onevent  = onevent;
        options.context  = context;
        options.protocol = protocol;
        options.address  = address;
        options.port     = port;
        return medusa_tcpsocket_bind_with_options_unlocked(&options);
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_bind (struct medusa_monitor *monitor, unsigned int protocol, const char *address, unsigned short port, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, void *param), void *context)
{
        struct medusa_tcpsocket *tcpsocket;
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(monitor);
        tcpsocket = medusa_tcpsocket_bind_unlocked(monitor, protocol, address, port, onevent, context);
        medusa_monitor_unlock(monitor);
        return tcpsocket;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_accept_options_default (struct medusa_tcpsocket_accept_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_tcpsocket_accept_options));
        options->fd         = -1;
        options->clodestroy = 1;
        return 0;
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_accept_with_options_unlocked (struct medusa_tcpsocket *tcpsocket, const struct medusa_tcpsocket_accept_options *options)
{
        int fd;
        int rc;
        int ret;
        struct medusa_io_init_options io_init_options;
        struct medusa_tcpsocket *accepted;

        accepted = NULL;

        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                ret = -EINVAL;
                goto bail;
        }
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                ret = -EINVAL;
                goto bail;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                ret = -EINVAL;
                goto bail;
        }
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                ret = -EINVAL;
                goto bail;
        }

        accepted = tcpsocket_create_unlocked(medusa_tcpsocket_get_monitor_unlocked(tcpsocket), options->onevent, options->context);
        if (MEDUSA_IS_ERR_OR_NULL(accepted)) {
                ret = MEDUSA_PTR_ERR(accepted);
                goto bail;
        }
        tcpsocket_add_flag(accepted, MEDUSA_TCPSOCKET_FLAG_ACCEPT);

        if (options->fd >= 0) {
                fd = options->fd;
        } else {
                fd = accept(medusa_io_get_fd_unlocked(tcpsocket->io), NULL, NULL);
        }
        if (fd < 0) {
                ret = -errno;
                goto bail;
        }

        rc = medusa_io_init_options_default(&io_init_options);
        if (rc < 0) {
                if (options->fd < 0 ||
                    options->clodestroy == 1) {
                        close(fd);
                }
                ret = rc;
                goto bail;
        }
        io_init_options.monitor    = tcpsocket->subject.monitor;
        io_init_options.fd         = fd;
        io_init_options.events     = MEDUSA_IO_EVENT_IN;
        io_init_options.onevent    = tcpsocket_io_onevent;
        io_init_options.context    = accepted;
        io_init_options.clodestroy = options->clodestroy;
        io_init_options.enabled    = 0;
        accepted->io = medusa_io_create_with_options_unlocked(&io_init_options);
        if (MEDUSA_IS_ERR_OR_NULL(accepted->io)) {
                ret = MEDUSA_PTR_ERR(accepted->io);
                goto bail;
        }

        rc = medusa_tcpsocket_set_nonblocking_unlocked(accepted, options->nonblocking);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_set_nodelay_unlocked(accepted, options->nodelay);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_set_buffered_unlocked(accepted, options->buffered);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_set_clodestroy_unlocked(accepted, options->clodestroy);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_set_enabled_unlocked(accepted, options->enabled);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }

        rc = medusa_tcpsocket_set_ssl_certificate_unlocked(accepted, medusa_tcpsocket_get_ssl_certificate_unlocked(tcpsocket));
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_set_ssl_privatekey_unlocked(accepted, medusa_tcpsocket_get_ssl_privatekey_unlocked(tcpsocket));
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_set_ssl_unlocked(accepted, medusa_tcpsocket_get_ssl_unlocked(tcpsocket));
        if (rc < 0) {
                ret = rc;
                goto bail;
        }

        rc = tcpsocket_set_state(accepted, MEDUSA_TCPSOCKET_STATE_CONNECTED);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_onevent_unlocked(accepted, MEDUSA_TCPSOCKET_EVENT_CONNECTED, NULL);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }

        return accepted;
bail:   if (MEDUSA_IS_ERR_OR_NULL(accepted)) {
                return MEDUSA_ERR_PTR(ret);
        }
        tcpsocket_set_state(accepted, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
        accepted->error = -ret;
        medusa_tcpsocket_onevent_unlocked(accepted, MEDUSA_TCPSOCKET_EVENT_ERROR, NULL);
        medusa_tcpsocket_onevent_unlocked(accepted, MEDUSA_TCPSOCKET_EVENT_DISCONNECTED, NULL);
        return tcpsocket;
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

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_accept_unlocked (struct medusa_tcpsocket *tcpsocket, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, void *param), void *context)
{
        int rc;
        struct medusa_tcpsocket_accept_options options;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        rc = medusa_tcpsocket_accept_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.onevent     = onevent;
        options.context     = context;
        options.buffered    = medusa_tcpsocket_get_buffered_unlocked(tcpsocket);
        options.nodelay     = medusa_tcpsocket_get_nodelay_unlocked(tcpsocket);
        options.nonblocking = medusa_tcpsocket_get_nonblocking_unlocked(tcpsocket);
        return medusa_tcpsocket_accept_with_options_unlocked(tcpsocket, &options);
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_accept (struct medusa_tcpsocket *tcpsocket, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, void *param), void *context)
{
        struct medusa_tcpsocket *accepted;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        accepted = medusa_tcpsocket_accept_unlocked(tcpsocket, onevent, context);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return accepted;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_connect_options_default (struct medusa_tcpsocket_connect_options *options)
{
        if (options == NULL) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_tcpsocket_connect_options));
        options->protocol   = MEDUSA_TCPSOCKET_PROTOCOL_ANY;
        options->sprotocol  = MEDUSA_TCPSOCKET_PROTOCOL_ANY;
        options->timeout    = -1;
        options->fd         = -1;
        options->reuseaddr  = 1;
        options->reuseport  = 1;
        options->clodestroy = 1;
        return 0;
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_connect_with_options_unlocked (const struct medusa_tcpsocket_connect_options *options)
{
        int rc;
        int fd;
        int ret;
        int connected;

        unsigned int protocol;
        const char *address;
        unsigned short port;

        struct addrinfo hints;
        struct addrinfo *result;
        struct addrinfo *res;

        struct medusa_io_init_options io_init_options;
        struct medusa_tcpsocket *tcpsocket;

        result    = NULL;
        tcpsocket = NULL;

        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                ret = -EINVAL;
                goto bail;
        }

        protocol = options->protocol;
        address  = options->address;
        port     = options->port;
        if (address == NULL) {
                ret = -EINVAL;
                goto bail;
        }
        if (port == 0) {
                ret = -EINVAL;
                goto bail;
        }

        tcpsocket = tcpsocket_create_unlocked(options->monitor, options->onevent, options->context);
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                ret = MEDUSA_PTR_ERR(tcpsocket);
                goto bail;
        }
        tcpsocket_add_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_CONNECT);
        if (options->fd >= 0) {
                tcpsocket_add_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_ATTACH);
        }

        rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_RESOLVING);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_RESOLVING, NULL);
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

#if defined(MEDUSA_TCPSOCKET_OPENSSL_ENABLE) && (MEDUSA_TCPSOCKET_OPENSSL_ENABLE == 1)
        tcpsocket->ssl_hostname = strdup(address);
        if (tcpsocket->ssl_hostname == NULL) {
                ret = -ENOMEM;
                goto bail;
        }
#endif

        rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_RESOLVED);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_RESOLVED, NULL);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }

        rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_CONNECTING);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_CONNECTING, NULL);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }

        rc = -1;
        fd = -1;
        for (res = result; res; res = res->ai_next) {
                void *ptr;
                char str[MAX(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];
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

                if (options->fd >= 0) {
                        fd = options->fd;
                } else {
                        fd = socket(res->ai_family, SOCK_STREAM, 0);
                }
                if (fd < 0) {
                        ret = -errno;
                        goto bail;
                }
                {
                        int rc;
                        int flags;
                        flags = fcntl(fd, F_GETFL, 0);
                        if (flags < 0) {
                                ret = -errno;
                                if (options->fd < 0 ||
                                    options->clodestroy == 1) {
                                        close(fd);
                                }
                                goto bail;
                        }
                        flags = (options->nonblocking) ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
                        rc = fcntl(fd, F_SETFL, flags);
                        if (rc != 0) {
                                ret = -errno;
                                if (options->fd < 0 ||
                                    options->clodestroy == 1) {
                                        close(fd);
                                }
                                goto bail;
                        }
                }
                if (options->sport > 0 ||
                    options->saddress != NULL) {
                        unsigned int sprotocol;
                        const char *saddress;
                        unsigned short sport;

                        struct sockaddr_storage bind_sockaddr;

                        sprotocol = options->sprotocol;
                        saddress  = options->saddress;
                        sport     = options->sport;

                        if (sprotocol == MEDUSA_TCPSOCKET_PROTOCOL_IPV4) {
                                struct sockaddr_in *bind_sockaddr_in;
bind_ipv4:
                                bind_sockaddr_in = (struct sockaddr_in *) &bind_sockaddr;
                                bind_sockaddr_in->sin_family = AF_INET;
                                if (saddress == NULL) {
                                        saddress = "0.0.0.0";
                                } else if (strcmp(saddress, "localhost") == 0) {
                                        saddress = "127.0.0.1";
                                } else if (strcmp(saddress, "loopback") == 0) {
                                        saddress = "127.0.0.1";
                                }
                                rc = inet_pton(AF_INET, saddress, &bind_sockaddr_in->sin_addr);
                                if (rc == 0) {
                                        ret = -EINVAL;
                                        if (options->fd < 0 ||
                                            options->clodestroy == 1) {
                                                close(fd);
                                        }
                                        goto bail;
                                } else if (rc < 0) {
                                        ret = -EINVAL;
                                        if (options->fd < 0 ||
                                            options->clodestroy == 1) {
                                                close(fd);
                                        }
                                        goto bail;
                                }
                                bind_sockaddr_in->sin_port = htons(sport);
                        } else if (sprotocol == MEDUSA_TCPSOCKET_PROTOCOL_IPV6) {
                                struct sockaddr_in6 *bind_sockaddr_in6;
bind_ipv6:
                                bind_sockaddr_in6 = (struct sockaddr_in6 *) &bind_sockaddr;
                                bind_sockaddr_in6->sin6_family = AF_INET6;
                                if (saddress == NULL) {
                                        saddress = "0.0.0.0";
                                } else if (strcmp(saddress, "localhost") == 0) {
                                        saddress = "::1";
                                } else if (strcmp(saddress, "loopback") == 0) {
                                        saddress = "::1";
                                }
                                rc = inet_pton(AF_INET6, saddress, &bind_sockaddr_in6->sin6_addr);
                                if (rc == 0) {
                                        ret = -EINVAL;
                                        if (options->fd < 0 ||
                                            options->clodestroy == 1) {
                                                close(fd);
                                        }
                                        goto bail;
                                } else if (rc < 0) {
                                        ret = -EINVAL;
                                        if (options->fd < 0 ||
                                            options->clodestroy == 1) {
                                                close(fd);
                                        }
                                        goto bail;
                                }
                                bind_sockaddr_in6->sin6_port = htons(sport);
                        } else if (saddress == NULL) {
                                saddress = "0.0.0.0";
                                goto bind_ipv4;
                        } else if (strcmp(saddress, "localhost") == 0) {
                                saddress = "127.0.0.1";
                                goto bind_ipv4;
                        } else if (strcmp(saddress, "loopback") == 0) {
                                saddress = "127.0.0.1";
                                goto bind_ipv4;
                        } else {
                                struct sockaddr_in bind_sockaddr_in;
                                struct sockaddr_in6 bind_sockaddr_in6;
                                rc = inet_pton(AF_INET, saddress, &bind_sockaddr_in.sin_addr);
                                if (rc > 0) {
                                        goto bind_ipv4;
                                }
                                rc = inet_pton(AF_INET6, saddress, &bind_sockaddr_in6.sin6_addr);
                                if (rc > 0) {
                                        goto bind_ipv6;
                                }
                                ret = -EINVAL;
                                if (options->fd < 0 ||
                                    options->clodestroy == 1) {
                                        close(fd);
                                }
                                goto bail;
                        }

                        if (options->reuseaddr != 0) {
                                int on;
                                on = 1;
                                rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
                                if (rc < 0) {
                                        ret = -errno;
                                        if (options->fd < 0 ||
                                            options->clodestroy == 1) {
                                                close(fd);
                                        }
                                        goto bail;
                                }
                        }
                        if (options->reuseport != 0) {
                                int on;
                                on = 1;
                                rc = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
                                if (rc < 0) {
                                        ret = -errno;
                                        if (options->fd < 0 ||
                                            options->clodestroy == 1) {
                                                close(fd);
                                        }
                                        goto bail;
                                }
                        }
                        rc = bind(fd, (struct sockaddr *) &bind_sockaddr, sizeof(struct sockaddr_storage));
                        if (rc != 0) {
                                ret = -errno;
                                if (options->fd < 0 ||
                                    options->clodestroy == 1) {
                                        close(fd);
                                }
                                goto bail;
                        }
                }
                rc = connect(fd, res->ai_addr, res->ai_addrlen);
                if (rc != 0) {
                        if (errno != EINPROGRESS &&
                            errno != EALREADY) {
                                if (options->fd < 0) {
                                        close(fd);
                                }
                                fd = -1;
                                rc = -errno;
                                continue;
                        }
                        rc = -errno;
                }
                break;
        }
        if ((res == NULL) ||
            (fd == -1) ||
            (rc != 0 &&
             rc != -EINPROGRESS &&
             rc != -EALREADY)) {
                ret = rc;
                if (options->fd < 0 ||
                    options->clodestroy == 1) {
                        close(fd);
                }
                goto bail;
        }
        connected = (rc == 0);

        rc = medusa_io_init_options_default(&io_init_options);
        if (rc < 0) {
                close(fd);
                ret = rc;
                goto bail;
        }
        io_init_options.monitor    = tcpsocket->subject.monitor;
        io_init_options.fd         = fd;
        io_init_options.events     = MEDUSA_IO_EVENT_IN;
        io_init_options.onevent    = tcpsocket_io_onevent;
        io_init_options.context    = tcpsocket;
        io_init_options.clodestroy = options->clodestroy;
        io_init_options.enabled    = 0;
        tcpsocket->io = medusa_io_create_with_options_unlocked(&io_init_options);
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                ret = MEDUSA_PTR_ERR(tcpsocket->io);
                if (options->fd < 0 ||
                    options->clodestroy == 1) {
                        close(fd);
                }
                goto bail;
        }

        rc = medusa_tcpsocket_set_nonblocking_unlocked(tcpsocket, options->nonblocking);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_set_nodelay_unlocked(tcpsocket, options->nodelay);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_set_buffered_unlocked(tcpsocket, options->buffered);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_set_clodestroy_unlocked(tcpsocket, options->clodestroy);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_set_enabled_unlocked(tcpsocket, options->enabled);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }

        if (connected) {
                rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_CONNECTED);
                if (rc < 0) {
                        ret = rc;
                        goto bail;
                }
                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_CONNECTED, NULL);
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
                if (options->timeout > 0) {
                        rc = medusa_tcpsocket_set_connect_timeout_unlocked(tcpsocket, options->timeout);
                        if (rc < 0) {
                                ret = rc;
                                goto bail;
                        }
                }
        }

        freeaddrinfo(result);
        return tcpsocket;
bail:   if (result != NULL) {
                freeaddrinfo(result);
        }
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(ret);
        }
        tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
        tcpsocket->error = -ret;
        medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_ERROR, NULL);
        medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DISCONNECTED, NULL);
        return tcpsocket;
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_connect_with_options (const struct medusa_tcpsocket_connect_options *options)
{
        struct medusa_tcpsocket *tcpsocket;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(options->monitor);
        tcpsocket = medusa_tcpsocket_connect_with_options_unlocked(options);
        medusa_monitor_unlock(options->monitor);
        return tcpsocket;
}

__attribute__ ((visibility ("default")))struct medusa_tcpsocket * medusa_tcpsocket_connect_unlocked (struct medusa_monitor *monitor, unsigned int protocol, const char *address, unsigned short port, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, void *param), void *context)
{
        int rc;
        struct medusa_tcpsocket_connect_options options;
        rc = medusa_tcpsocket_connect_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.monitor  = monitor;
        options.onevent  = onevent;
        options.context  = context;
        options.protocol = protocol;
        options.address  = address;
        options.port     = port;
        return medusa_tcpsocket_connect_with_options_unlocked(&options);
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_connect (struct medusa_monitor *monitor, unsigned int protocol, const char *address, unsigned short port, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, void *param), void *context)
{
        struct medusa_tcpsocket *tcpsocket;
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(monitor);
        tcpsocket = medusa_tcpsocket_connect_unlocked(monitor, protocol, address, port, onevent, context);
        medusa_monitor_unlock(monitor);
        return tcpsocket;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_attach_options_default (struct medusa_tcpsocket_attach_options *options)
{
        if (options == NULL) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_tcpsocket_attach_options));
        options->fd         = -1;
        options->bound      = 0;
        options->clodestroy = 1;
        return 0;
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_attach_with_options_unlocked (const struct medusa_tcpsocket_attach_options *options)
{
        int rc;
        int fd;
        int ret;

        struct medusa_io_init_options io_init_options;
        struct medusa_tcpsocket *tcpsocket;

        tcpsocket = NULL;

        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                ret = -EINVAL;
                goto bail;
        }
        fd = options->fd;
        if (fd < 0) {
                ret = -EINVAL;
                goto bail;
        }

        tcpsocket = tcpsocket_create_unlocked(options->monitor, options->onevent, options->context);
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                ret = MEDUSA_PTR_ERR(tcpsocket);
                goto bail;
        }
        tcpsocket_add_flag(tcpsocket, (options->bound) ? MEDUSA_TCPSOCKET_FLAG_BIND | MEDUSA_TCPSOCKET_FLAG_ATTACH : MEDUSA_TCPSOCKET_FLAG_ATTACH);

        rc = medusa_io_init_options_default(&io_init_options);
        if (rc < 0) {
                close(fd);
                ret = rc;
                goto bail;
        }
        io_init_options.monitor    = tcpsocket->subject.monitor;
        io_init_options.fd         = fd;
        io_init_options.events     = MEDUSA_IO_EVENT_IN;
        io_init_options.onevent    = tcpsocket_io_onevent;
        io_init_options.context    = tcpsocket;
        io_init_options.clodestroy = options->clodestroy;
        io_init_options.enabled    = 0;
        tcpsocket->io = medusa_io_create_with_options_unlocked(&io_init_options);
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                ret = MEDUSA_PTR_ERR(tcpsocket->io);
                goto bail;
        }

        rc = medusa_tcpsocket_set_nonblocking_unlocked(tcpsocket, options->nonblocking);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_set_nodelay_unlocked(tcpsocket, options->nodelay);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_set_buffered_unlocked(tcpsocket, options->buffered);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_set_clodestroy_unlocked(tcpsocket, options->clodestroy);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }
        rc = medusa_tcpsocket_set_enabled_unlocked(tcpsocket, options->enabled);
        if (rc < 0) {
                ret = rc;
                goto bail;
        }

        if (tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_BIND)) {
                rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_BINDING);
                if (rc < 0) {
                        ret = rc;
                        goto bail;
                }
                rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_BOUND);
                if (rc < 0) {
                        ret = rc;
                        goto bail;
                }
                rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_LISTENING);
                if (rc < 0) {
                        ret = rc;
                        goto bail;
                }
                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_LISTENING, NULL);
                if (rc < 0) {
                        ret = rc;
                        goto bail;
                }
        } else {
                rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_RESOLVING);
                if (rc < 0) {
                        ret = rc;
                        goto bail;
                }
                rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_RESOLVED);
                if (rc < 0) {
                        ret = rc;
                        goto bail;
                }
                rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_CONNECTING);
                if (rc < 0) {
                        ret = rc;
                        goto bail;
                }
                rc = tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_CONNECTED);
                if (rc < 0) {
                        ret = rc;
                        goto bail;
                }
                rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_CONNECTED, NULL);
                if (rc < 0) {
                        ret = rc;
                        goto bail;
                }
        }

        return tcpsocket;
bail:   if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(ret);
        }
        tcpsocket_set_state(tcpsocket, MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
        tcpsocket->error = -ret;
        medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_ERROR, NULL);
        medusa_tcpsocket_onevent_unlocked(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DISCONNECTED, NULL);
        return tcpsocket;
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_attach_with_options (const struct medusa_tcpsocket_attach_options *options)
{
        struct medusa_tcpsocket *tcpsocket;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(options->monitor);
        tcpsocket = medusa_tcpsocket_attach_with_options_unlocked(options);
        medusa_monitor_unlock(options->monitor);
        return tcpsocket;
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_attach_unlocked (struct medusa_monitor *monitor, int fd, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, void *param), void *context)
{
        int rc;
        struct medusa_tcpsocket_attach_options options;
        rc = medusa_tcpsocket_attach_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.monitor = monitor;
        options.onevent = onevent;
        options.context = context;
        options.fd      = fd;
        return medusa_tcpsocket_attach_with_options_unlocked(&options);
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_attach (struct medusa_monitor *monitor, int fd, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, void *param), void *context)
{
        struct medusa_tcpsocket *tcpsocket;
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (fd < 0) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(monitor);
        tcpsocket = medusa_tcpsocket_attach_unlocked(monitor, fd, onevent, context);
        medusa_monitor_unlock(monitor);
        return tcpsocket;
}

__attribute__ ((visibility ("default"))) void medusa_tcpsocket_destroy_unlocked (struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return;
        }
        tcpsocket_uninit_unlocked(tcpsocket);
}

__attribute__ ((visibility ("default"))) void medusa_tcpsocket_destroy (struct medusa_tcpsocket *tcpsocket)
{
        struct medusa_monitor *monitor;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return;
        }
        monitor = tcpsocket->subject.monitor;
        if (monitor != NULL) {
                medusa_monitor_lock(monitor);
        }
        medusa_tcpsocket_destroy_unlocked(tcpsocket);
        if (monitor != NULL) {
                medusa_monitor_unlock(monitor);
        }
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_state_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        return tcpsocket->state;
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
        return tcpsocket->error;
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
        return tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_BUFFERED);
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

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_clodestroy_unlocked (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (enabled) {
                tcpsocket_add_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_CLODESTROY);
        } else {
                tcpsocket_del_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_CLODESTROY);
        }
        if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                int rc;
                rc = medusa_io_set_clodestroy_unlocked(tcpsocket->io, enabled);
                if (rc != 0) {
                        return rc;
                }
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_clodestroy (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_set_clodestroy_unlocked(tcpsocket, enabled);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_clodestroy_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        return tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_CLODESTROY);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_clodestroy (const struct medusa_tcpsocket *tcpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_get_clodestroy_unlocked(tcpsocket);
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
        if (!tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_BIND)) {
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
        if (!tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_BIND)) {
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
        if (!tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_BIND)) {
                return -EINVAL;
        }
        tcpsocket->backlog = backlog;
        tcpsocket_add_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_BACKLOG);
        if (tcpsocket->state == MEDUSA_TCPSOCKET_STATE_LISTENING) {
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
                if (tcpsocket->state == MEDUSA_TCPSOCKET_STATE_CONNECTED) {
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
        if (!tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_CONNECT)) {
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
                if (tcpsocket->state == MEDUSA_TCPSOCKET_STATE_CONNECTING) {
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

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_ssl_unlocked (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
#if defined(MEDUSA_TCPSOCKET_OPENSSL_ENABLE) && (MEDUSA_TCPSOCKET_OPENSSL_ENABLE == 1)
        if (enabled) {
                if (!tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_NONBLOCKING) ||
                    !tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_BUFFERED)) {
                        return -EINVAL;
                }
                if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->ssl_ctx) &&
                    MEDUSA_IS_ERR_OR_NULL(tcpsocket->ssl)) {
                        if (tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_BIND) ||
                            tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_ACCEPT)) {
                                if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->ssl_certificate) ||
                                    MEDUSA_IS_ERR_OR_NULL(tcpsocket->ssl_privatekey)) {
                                        return -EINVAL;
                                }
                        }
                }
                if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->ssl_ctx) &&
                    !tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_BIND)) {
                        SSL_METHOD *method;
                        if (tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_ACCEPT)) {
                                method = (SSL_METHOD *) SSLv23_server_method();
                        } else {
                                method = (SSL_METHOD *) SSLv23_method();
                        }
                        if (method == NULL) {
                                return -EIO;
                        }
                        tcpsocket->ssl_ctx = SSL_CTX_new(method);
                        if (tcpsocket->ssl_ctx == NULL) {
                                return -EIO;
                        }
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) || (OPENSSL_API_COMPAT >= 0x10100000L)
                        SSL_CTX_set_ecdh_auto(tcpsocket->ssl_ctx, 1);
#endif
                }
                if (!tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_BIND)) {
                        int rc;
                        if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->ssl_certificate)) {
                                rc = SSL_CTX_use_certificate_file(tcpsocket->ssl_ctx, tcpsocket->ssl_certificate, SSL_FILETYPE_PEM);
                                if (rc <= 0) {
                                        return -EIO;
                                }
                        }
                        if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->ssl_privatekey)) {
                                rc = SSL_CTX_use_PrivateKey_file(tcpsocket->ssl_ctx, tcpsocket->ssl_privatekey, SSL_FILETYPE_PEM);
                                if (rc <= 0) {
                                        return -EIO;
                                }
                        }
                }
                if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->ssl) &&
                    !tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_BIND)) {
                        int rc;
                        tcpsocket->ssl = SSL_new(tcpsocket->ssl_ctx);
                        if (tcpsocket->ssl == NULL) {
                                return -EIO;
                        }
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) || (OPENSSL_API_COMPAT >= 0x10100000L)
                        SSL_set_tlsext_host_name(tcpsocket->ssl, tcpsocket->ssl_hostname);
#endif
                        rc = SSL_set_fd(tcpsocket->ssl, medusa_tcpsocket_get_fd_unlocked(tcpsocket));
                        if (rc <= 0) {
                                return -EIO;
                        }
                }
                if (!tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_BIND)) {
                        int rc;
                        rc = SSL_set_fd(tcpsocket->ssl, medusa_tcpsocket_get_fd_unlocked(tcpsocket));
                        if (rc <= 0) {
                                return -EIO;
                        }
                }
                if (!tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_BIND) &&
                    tcpsocket->state == MEDUSA_TCPSOCKET_STATE_CONNECTED) {
                        int rc;
                        if (tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_ACCEPT)) {
                                rc = SSL_accept(tcpsocket->ssl);
                        } else {
                                rc = SSL_connect(tcpsocket->ssl);
                        }
                        if (rc <= 0) {
                                int error;
                                error = SSL_get_error(tcpsocket->ssl, rc);
                                if (error == SSL_ERROR_WANT_READ) {
                                        tcpsocket->ssl_wantread = 1;
                                } else if (error == SSL_ERROR_WANT_WRITE) {
                                        tcpsocket->ssl_wantwrite = 1;
                                } else if (error == SSL_ERROR_SYSCALL) {
                                        tcpsocket->ssl_wantread = 1;
                                } else {
                                        return -EIO;
                                }
                        }
                }
        } else {
                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->ssl) &&
                    !tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_SSL_EXTERNAL)) {
                        SSL_free(tcpsocket->ssl);
                }
                tcpsocket->ssl = NULL;
                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->ssl_ctx) &&
                    !tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_SSL_CTX_EXTERNAL)) {
                        SSL_CTX_free(tcpsocket->ssl_ctx);
                }
                tcpsocket->ssl_ctx = NULL;
        }
#endif
        if (enabled) {
                tcpsocket_add_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_SSL);
        } else {
                tcpsocket_del_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_SSL);
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_ssl (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_set_ssl_unlocked(tcpsocket, enabled);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_ssl_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        return tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_SSL);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_ssl (const struct medusa_tcpsocket *tcpsocket)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_get_ssl_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_ssl_certificate_unlocked (struct medusa_tcpsocket *tcpsocket, const char *certificate)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
#if defined(MEDUSA_TCPSOCKET_OPENSSL_ENABLE) && (MEDUSA_TCPSOCKET_OPENSSL_ENABLE == 1)
        if (tcpsocket->ssl_certificate != NULL) {
                free(tcpsocket->ssl_certificate);
                tcpsocket->ssl_certificate = NULL;
        }
        if (certificate != NULL) {
                tcpsocket->ssl_certificate = strdup(certificate);
                if (tcpsocket->ssl_certificate == NULL) {
                        return -ENOMEM;
                }
        }
#else
        (void) certificate;
#endif
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_ssl_certificate (struct medusa_tcpsocket *tcpsocket, const char *certificate)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_set_ssl_certificate_unlocked(tcpsocket, certificate);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) const char * medusa_tcpsocket_get_ssl_certificate_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
#if defined(MEDUSA_TCPSOCKET_OPENSSL_ENABLE) && (MEDUSA_TCPSOCKET_OPENSSL_ENABLE == 1)
        return tcpsocket->ssl_certificate;
#else
        return NULL;
#endif
}

__attribute__ ((visibility ("default"))) const char * medusa_tcpsocket_get_ssl_certificate (const struct medusa_tcpsocket *tcpsocket)
{
        const char *rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_get_ssl_certificate_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_ssl_privatekey_unlocked (struct medusa_tcpsocket *tcpsocket, const char *privatekey)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
#if defined(MEDUSA_TCPSOCKET_OPENSSL_ENABLE) && (MEDUSA_TCPSOCKET_OPENSSL_ENABLE == 1)
        if (tcpsocket->ssl_privatekey != NULL) {
                free(tcpsocket->ssl_privatekey);
                tcpsocket->ssl_privatekey = NULL;
        }
        if (privatekey != NULL) {
                tcpsocket->ssl_privatekey = strdup(privatekey);
                if (tcpsocket->ssl_privatekey == NULL) {
                        return -ENOMEM;
                }
        }
#else
        (void) privatekey;
#endif
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_ssl_privatekey (struct medusa_tcpsocket *tcpsocket, const char *privatekey)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_set_ssl_privatekey_unlocked(tcpsocket, privatekey);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) const char * medusa_tcpsocket_get_ssl_privatekey_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
#if defined(MEDUSA_TCPSOCKET_OPENSSL_ENABLE) && (MEDUSA_TCPSOCKET_OPENSSL_ENABLE == 1)
        return tcpsocket->ssl_privatekey;
#endif
        return NULL;
}

__attribute__ ((visibility ("default"))) const char * medusa_tcpsocket_get_ssl_privatekey (const struct medusa_tcpsocket *tcpsocket)
{
        const char *rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_get_ssl_privatekey_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_ssl_set_SSL_unlocked (struct medusa_tcpsocket *tcpsocket, struct ssl_st *ssl)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(ssl)) {
                return -EINVAL;
        }
#if defined(MEDUSA_TCPSOCKET_OPENSSL_ENABLE) && (MEDUSA_TCPSOCKET_OPENSSL_ENABLE == 1)
        if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->ssl)) {
                return -EINVAL;
        }
        tcpsocket->ssl = ssl;
#endif
        tcpsocket_add_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_SSL_EXTERNAL);
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_ssl_set_SSL (struct medusa_tcpsocket *tcpsocket, struct ssl_st *ssl)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_ssl_set_SSL_unlocked(tcpsocket, ssl);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct ssl_st * medusa_tcpsocket_ssl_get_SSL_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
#if defined(MEDUSA_TCPSOCKET_OPENSSL_ENABLE) && (MEDUSA_TCPSOCKET_OPENSSL_ENABLE == 1)
        return tcpsocket->ssl;
#endif
        return NULL;
}

__attribute__ ((visibility ("default"))) struct ssl_st * medusa_tcpsocket_ssl_get_SSL (const struct medusa_tcpsocket *tcpsocket)
{
        struct ssl_st *rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_ssl_get_SSL_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_ssl_set_SSL_CTX_unlocked (struct medusa_tcpsocket *tcpsocket, struct ssl_ctx_st *ssl_ctx)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(ssl_ctx)) {
                return -EINVAL;
        }
#if defined(MEDUSA_TCPSOCKET_OPENSSL_ENABLE) && (MEDUSA_TCPSOCKET_OPENSSL_ENABLE == 1)
        if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->ssl_ctx)) {
                return -EINVAL;
        }
        tcpsocket->ssl_ctx = ssl_ctx;
#endif
        tcpsocket_add_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_SSL_CTX_EXTERNAL);
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_ssl_set_SSL_CTX (struct medusa_tcpsocket *tcpsocket, struct ssl_ctx_st *ssl_ctx)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_ssl_set_SSL_CTX_unlocked(tcpsocket, ssl_ctx);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct ssl_ctx_st * medusa_tcpsocket_ssl_get_SSL_CTX_unlocked (const struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
#if defined(MEDUSA_TCPSOCKET_OPENSSL_ENABLE) && (MEDUSA_TCPSOCKET_OPENSSL_ENABLE == 1)
        return tcpsocket->ssl_ctx;
#endif
        return NULL;
}

__attribute__ ((visibility ("default"))) struct ssl_ctx_st * medusa_tcpsocket_ssl_get_SSL_CTX (const struct medusa_tcpsocket *tcpsocket)
{
        struct ssl_ctx_st *rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_ssl_get_SSL_CTX_unlocked(tcpsocket);
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
        if ((tcpsocket->state != MEDUSA_TCPSOCKET_STATE_LISTENING) &&
            (tcpsocket->state != MEDUSA_TCPSOCKET_STATE_CONNECTED)) {
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
        if ((tcpsocket->state != MEDUSA_TCPSOCKET_STATE_LISTENING) &&
            (tcpsocket->state != MEDUSA_TCPSOCKET_STATE_CONNECTED)) {
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
        if ((tcpsocket->state != MEDUSA_TCPSOCKET_STATE_LISTENING) &&
            (tcpsocket->state != MEDUSA_TCPSOCKET_STATE_CONNECTED)) {
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
        if ((tcpsocket->state != MEDUSA_TCPSOCKET_STATE_LISTENING) &&
            (tcpsocket->state != MEDUSA_TCPSOCKET_STATE_CONNECTED)) {
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

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_onevent_unlocked (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *param)
{
        int ret;
        struct medusa_monitor *monitor;
        ret = 0;
        monitor = tcpsocket->subject.monitor;
        if (tcpsocket->onevent != NULL) {
                if ((medusa_subject_is_active(&tcpsocket->subject)) ||
                    (events & MEDUSA_TCPSOCKET_EVENT_DESTROY)) {
                        medusa_monitor_unlock(monitor);
                        ret = tcpsocket->onevent(tcpsocket, events, tcpsocket->context, param);
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
#if defined(MEDUSA_TCPSOCKET_OPENSSL_ENABLE) && (MEDUSA_TCPSOCKET_OPENSSL_ENABLE == 1)
                if (tcpsocket->ssl_certificate != NULL) {
                        free(tcpsocket->ssl_certificate);
                        tcpsocket->ssl_certificate = NULL;
                }
                if (tcpsocket->ssl_privatekey != NULL) {
                        free(tcpsocket->ssl_privatekey);
                        tcpsocket->ssl_privatekey = NULL;
                }
                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->ssl) &&
                    !tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_SSL_EXTERNAL)) {
                        SSL_free(tcpsocket->ssl);
                }
                tcpsocket->ssl = NULL;
                if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket->ssl_ctx) &&
                    !tcpsocket_has_flag(tcpsocket, MEDUSA_TCPSOCKET_FLAG_SSL_CTX_EXTERNAL)) {
                        SSL_CTX_free(tcpsocket->ssl_ctx);
                }
                tcpsocket->ssl_ctx = NULL;
                if (tcpsocket->ssl_hostname != NULL) {
                        free(tcpsocket->ssl_hostname);
                        tcpsocket->ssl_hostname = NULL;
                }
#endif
#if defined(MEDUSA_TCPSOCKET_USE_POOL) && (MEDUSA_TCPSOCKET_USE_POOL == 1)
                medusa_pool_free(tcpsocket);
#else
                free(tcpsocket);
#endif
        } else {
                if ((tcpsocket->state == MEDUSA_TCPSOCKET_STATE_CONNECTED) &&
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

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_onevent_unlocked (struct medusa_tcpsocket *tcpsocket, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, void *param), void *context)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        tcpsocket->onevent = onevent;
        tcpsocket->context = context;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_onevent (struct medusa_tcpsocket *tcpsocket, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, void *param), void *context)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_set_onevent_unlocked(tcpsocket, onevent, context);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_context_unlocked (struct medusa_tcpsocket *tcpsocket, void *context)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        tcpsocket->context = context;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_context (struct medusa_tcpsocket *tcpsocket, void *context)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_set_context_unlocked(tcpsocket, context);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void * medusa_tcpsocket_get_context_unlocked (struct medusa_tcpsocket *tcpsocket)
{
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return tcpsocket->context;
}

__attribute__ ((visibility ("default"))) void * medusa_tcpsocket_get_context (struct medusa_tcpsocket *tcpsocket)
{
        void *rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_get_context_unlocked(tcpsocket);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
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

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_userdata_ptr_unlocked (struct medusa_tcpsocket *tcpsocket, void *userdata)
{
        return medusa_tcpsocket_set_userdata_unlocked(tcpsocket, userdata);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_userdata_ptr (struct medusa_tcpsocket *tcpsocket, void *userdata)
{
        return medusa_tcpsocket_set_userdata(tcpsocket, userdata);
}

__attribute__ ((visibility ("default"))) void * medusa_tcpsocket_get_userdata_ptr_unlocked (struct medusa_tcpsocket *tcpsocket)
{
        return medusa_tcpsocket_get_userdata_unlocked(tcpsocket);
}

__attribute__ ((visibility ("default"))) void * medusa_tcpsocket_get_userdata_ptr (struct medusa_tcpsocket *tcpsocket)
{
        return medusa_tcpsocket_get_userdata(tcpsocket);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_userdata_int_unlocked (struct medusa_tcpsocket *tcpsocket, int userdata)
{
        return medusa_tcpsocket_set_userdata_unlocked(tcpsocket, (void *) (intptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_userdata_int (struct medusa_tcpsocket *tcpsocket, int userdata)
{
        return medusa_tcpsocket_set_userdata(tcpsocket, (void *) (intptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_userdata_int_unlocked (struct medusa_tcpsocket *tcpsocket)
{
        return (int) (intptr_t) medusa_tcpsocket_get_userdata_unlocked(tcpsocket);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_userdata_int (struct medusa_tcpsocket *tcpsocket)
{
        return (int) (intptr_t) medusa_tcpsocket_get_userdata(tcpsocket);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_userdata_uint_unlocked (struct medusa_tcpsocket *tcpsocket, unsigned int userdata)
{
        return medusa_tcpsocket_set_userdata_unlocked(tcpsocket, (void *) (uintptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_userdata_uint (struct medusa_tcpsocket *tcpsocket, unsigned int userdata)
{
        return medusa_tcpsocket_set_userdata(tcpsocket, (void *) (uintptr_t) userdata);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_tcpsocket_get_userdata_uint_unlocked (struct medusa_tcpsocket *tcpsocket)
{
        return (unsigned int) (intptr_t) medusa_tcpsocket_get_userdata_unlocked(tcpsocket);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_tcpsocket_get_userdata_uint (struct medusa_tcpsocket *tcpsocket)
{
        return (unsigned int) (uintptr_t) medusa_tcpsocket_get_userdata(tcpsocket);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_sockname_unlocked (struct medusa_tcpsocket *tcpsocket, struct sockaddr_storage *sockaddr)
{
        int fd;
        int rc;
        socklen_t sockaddr_length;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (sockaddr == NULL) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                return -EINVAL;
        }
        fd = medusa_tcpsocket_get_fd_unlocked(tcpsocket);
        if (fd < 0) {
                return fd;
        }
        sockaddr_length = sizeof(struct sockaddr_storage);
        memset(sockaddr, 0, sockaddr_length);
        rc = getsockname(fd, (struct sockaddr *) sockaddr, &sockaddr_length);
        if (rc != 0) {
                return -errno;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_sockname (struct medusa_tcpsocket *tcpsocket, struct sockaddr_storage *sockaddr)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_get_sockname_unlocked(tcpsocket, sockaddr);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_peername_unlocked (struct medusa_tcpsocket *tcpsocket, struct sockaddr_storage *sockaddr)
{
        int fd;
        int rc;
        socklen_t sockaddr_length;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (sockaddr == NULL) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket->io)) {
                return -EINVAL;
        }
        fd = medusa_tcpsocket_get_fd_unlocked(tcpsocket);
        if (fd < 0) {
                return fd;
        }
        sockaddr_length = sizeof(struct sockaddr_storage);
        memset(sockaddr, 0, sockaddr_length);
        rc = getpeername(fd, (struct sockaddr *) sockaddr, &sockaddr_length);
        if (rc != 0) {
                return -errno;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_peername (struct medusa_tcpsocket *tcpsocket, struct sockaddr_storage *sockaddr)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_get_peername_unlocked(tcpsocket, sockaddr);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *param)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_onevent_unlocked(tcpsocket, events, param);
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

__attribute__ ((visibility ("default"))) int64_t medusa_tcpsocket_peek_unlocked (const struct medusa_tcpsocket *tcpsocket, void *data, int64_t length)
{
        int64_t rc;
        int enabled;
        int buffered;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(data)) {
                return -EINVAL;
        }
        if (length < 0) {
                return -EINVAL;
        }
        enabled = medusa_tcpsocket_get_enabled_unlocked(tcpsocket);
        if (enabled < 0) {
                return enabled;
        }
        if (enabled == 0) {
                return -EIO;
        }
        buffered = medusa_tcpsocket_get_buffered_unlocked(tcpsocket);
        if (buffered < 0) {
                return buffered;
        }
        if (buffered) {
                struct medusa_buffer *buffer;
                buffer = medusa_tcpsocket_get_read_buffer_unlocked(tcpsocket);
                if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                        return MEDUSA_PTR_ERR(buffer);
                }
                rc = medusa_buffer_peek(buffer, data, length);
        } else {
                int fd;
                fd = medusa_tcpsocket_get_fd_unlocked(tcpsocket);
                if (fd < 0) {
                        return fd;
                }
                rc = recv(fd, data, length, MSG_PEEK);
                if (rc < 0) {
                        rc = -errno;
                }
        }
        return rc;
}

__attribute__ ((visibility ("default"))) int64_t medusa_tcpsocket_peek (const struct medusa_tcpsocket *tcpsocket, void *data, int64_t length)
{
        int64_t rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_peek_unlocked(tcpsocket, data, length);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int64_t medusa_tcpsocket_read_unlocked (struct medusa_tcpsocket *tcpsocket, void *data, int64_t length)
{
        int64_t rc;
        int enabled;
        int buffered;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(data)) {
                return -EINVAL;
        }
        if (length < 0) {
                return -EINVAL;
        }
        enabled = medusa_tcpsocket_get_enabled_unlocked(tcpsocket);
        if (enabled < 0) {
                return enabled;
        }
        if (enabled == 0) {
                return -EIO;
        }
        buffered = medusa_tcpsocket_get_buffered_unlocked(tcpsocket);
        if (buffered < 0) {
                return buffered;
        }
        if (buffered) {
                struct medusa_buffer *buffer;
                buffer = medusa_tcpsocket_get_read_buffer_unlocked(tcpsocket);
                if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                        return MEDUSA_PTR_ERR(buffer);
                }
                rc = medusa_buffer_read(buffer, data, length);
        } else {
                int fd;
                fd = medusa_tcpsocket_get_fd_unlocked(tcpsocket);
                if (fd < 0) {
                        return fd;
                }
                rc = recv(fd, data, length, 0);
                if (rc < 0) {
                        rc = -errno;
                }
        }
        return rc;
}

__attribute__ ((visibility ("default"))) int64_t medusa_tcpsocket_read (struct medusa_tcpsocket *tcpsocket, void *data, int64_t length)
{
        int64_t rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_read_unlocked(tcpsocket, data, length);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int64_t medusa_tcpsocket_write_unlocked (struct medusa_tcpsocket *tcpsocket, const void *data, int64_t length)
{
        int64_t rc;
        int enabled;
        int buffered;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(data)) {
                return -EINVAL;
        }
        if (length < 0) {
                return -EINVAL;
        }
        enabled = medusa_tcpsocket_get_enabled_unlocked(tcpsocket);
        if (enabled < 0) {
                return enabled;
        }
        if (enabled == 0) {
                return -EIO;
        }
        buffered = medusa_tcpsocket_get_buffered_unlocked(tcpsocket);
        if (buffered < 0) {
                return buffered;
        }
        if (buffered) {
                struct medusa_buffer *buffer;
                buffer = medusa_tcpsocket_get_write_buffer_unlocked(tcpsocket);
                if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                        return MEDUSA_PTR_ERR(buffer);
                }
                rc = medusa_buffer_write(buffer, data, length);
        } else {
                int fd;
                fd = medusa_tcpsocket_get_fd_unlocked(tcpsocket);
                if (fd < 0) {
                        return fd;
                }
                rc = send(fd, data, length, 0);
                if (rc < 0) {
                        rc = -errno;
                }
        }
        return rc;
}

__attribute__ ((visibility ("default"))) int64_t medusa_tcpsocket_write (struct medusa_tcpsocket *tcpsocket, const void *data, int64_t length)
{
        int64_t rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_write_unlocked(tcpsocket, data, length);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int64_t medusa_tcpsocket_writev_unlocked (struct medusa_tcpsocket *tcpsocket, const struct medusa_iovec *iovecs, int64_t niovecs)
{
        int64_t rc;
        int enabled;
        int buffered;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(iovecs)) {
                return -EINVAL;
        }
        if (niovecs < 0) {
                return -EINVAL;
        }
        enabled = medusa_tcpsocket_get_enabled_unlocked(tcpsocket);
        if (enabled < 0) {
                return enabled;
        }
        if (enabled == 0) {
                return -EIO;
        }
        buffered = medusa_tcpsocket_get_buffered_unlocked(tcpsocket);
        if (buffered < 0) {
                return buffered;
        }
        if (buffered) {
                struct medusa_buffer *buffer;
                buffer = medusa_tcpsocket_get_write_buffer_unlocked(tcpsocket);
                if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                        return MEDUSA_PTR_ERR(buffer);
                }
                rc = medusa_buffer_writev(buffer, iovecs, niovecs);
        } else {
                int sr;
                int fd;
                int64_t i;
                fd = medusa_tcpsocket_get_fd_unlocked(tcpsocket);
                if (fd < 0) {
                        return fd;
                }
                rc = 0;
                for (i = 0; i < niovecs; i++) {
                        sr = send(fd, iovecs[i].iov_base, iovecs[i].iov_len, 0);
                        if (sr < 0) {
                                rc = -errno;
                                break;
                        } else if (sr != (int) iovecs[i].iov_len) {
                                rc += sr;
                                break;
                        }
                        rc += sr;
                }
        }
        return rc;
}

__attribute__ ((visibility ("default"))) int64_t medusa_tcpsocket_writev (struct medusa_tcpsocket *tcpsocket, const struct medusa_iovec *iovecs, int64_t niovecs)
{
        int64_t rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_writev_unlocked(tcpsocket, iovecs, niovecs);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int64_t medusa_tcpsocket_vprintf_unlocked (struct medusa_tcpsocket *tcpsocket, const char *format, va_list va)
{
        int64_t rc;
        int enabled;
        int buffered;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(format)) {
                return -EINVAL;
        }
        enabled = medusa_tcpsocket_get_enabled_unlocked(tcpsocket);
        if (enabled < 0) {
                return enabled;
        }
        if (enabled == 0) {
                return -EIO;
        }
        buffered = medusa_tcpsocket_get_buffered_unlocked(tcpsocket);
        if (buffered < 0) {
                return buffered;
        }
        if (buffered) {
                struct medusa_buffer *buffer;
                buffer = medusa_tcpsocket_get_write_buffer_unlocked(tcpsocket);
                if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                        return MEDUSA_PTR_ERR(buffer);
                }
                rc = medusa_buffer_vprintf(buffer, format, va);
        } else {
                int fd;
                va_list vs;
                int length;
                char *buffer;
                fd = medusa_tcpsocket_get_fd_unlocked(tcpsocket);
                if (fd < 0) {
                        return fd;
                }
                va_copy(vs, va);
                length = vsnprintf(NULL, 0, format, vs);
                va_end(vs);
                if (length < 0) {
                        return -EIO;
                }
                buffer = malloc(length + 1);
                if (buffer == NULL) {
                        return -ENOMEM;
                }
                va_copy(vs, va);
                rc = vsnprintf(buffer, length + 1, format, vs);
                va_end(vs);
                if (rc < 0) {
                        free(buffer);
                        return -EIO;
                }
                rc = send(fd, buffer, length, 0);
                if (rc < 0) {
                        rc = -errno;
                }
                free(buffer);
        }
        return rc;
}

__attribute__ ((visibility ("default"))) int64_t medusa_tcpsocket_vprintf (struct medusa_tcpsocket *tcpsocket, const char *format, va_list va)
{
        int64_t rc;
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -EINVAL;
        }
        medusa_monitor_lock(tcpsocket->subject.monitor);
        rc = medusa_tcpsocket_vprintf_unlocked(tcpsocket, format, va);
        medusa_monitor_unlock(tcpsocket->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int64_t medusa_tcpsocket_printf_unlocked (struct medusa_tcpsocket *tcpsocket, const char *format, ...)
{
        int rc;
        va_list ap;
        va_start(ap, format);
        rc = medusa_tcpsocket_vprintf_unlocked(tcpsocket, format, ap);
        va_end(ap);
        return rc;
}

__attribute__ ((visibility ("default"))) int64_t medusa_tcpsocket_printf (struct medusa_tcpsocket *tcpsocket, const char *format, ...)
{
        int rc;
        va_list ap;
        va_start(ap, format);
        rc = medusa_tcpsocket_vprintf(tcpsocket, format, ap);
        va_end(ap);
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
        if (events == MEDUSA_TCPSOCKET_EVENT_CONNECTED_SSL)             return "MEDUSA_TCPSOCKET_EVENT_CONNECTED_SSL";
        if (events == MEDUSA_TCPSOCKET_EVENT_IN)                        return "MEDUSA_TCPSOCKET_EVENT_IN";
        if (events == MEDUSA_TCPSOCKET_EVENT_IN_TIMEOUT)                return "MEDUSA_TCPSOCKET_EVENT_IN_TIMEOUT";
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
