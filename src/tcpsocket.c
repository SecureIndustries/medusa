
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>

#include "pool.h"
#include "queue.h"
#include "buffer.h"
#include "buffer-struct.h"
#include "subject-struct.h"
#include "io.h"
#include "io-struct.h"
#include "tcpsocket.h"
#include "tcpsocket-struct.h"
#include "monitor-private.h"

#define MIN(a, b)                               (((a) < (b)) ? (a) : (b))

#define MEDUSA_TCPSOCKET_DEFAULT_BACKLOG        1

enum {
        MEDUSA_TCPSOCKET_FLAG_DEFAULT           = 0x00000000,
        MEDUSA_TCPSOCKET_FLAG_NONBLOCKING       = 0x00000001,
        MEDUSA_TCPSOCKET_FLAG_REUSEADDR         = 0x00000002,
        MEDUSA_TCPSOCKET_FLAG_REUSEPORT         = 0x00000004,
        MEDUSA_TCPSOCKET_FLAG_BACKLOG           = 0x00000008,
#define MEDUSA_TCPSOCKET_FLAG_DEFAULT           MEDUSA_TCPSOCKET_FLAG_DEFAULT
#define MEDUSA_TCPSOCKET_FLAG_NONBLOCKING       MEDUSA_TCPSOCKET_FLAG_NONBLOCKING
#define MEDUSA_TCPSOCKET_FLAG_REUSEADDR         MEDUSA_TCPSOCKET_FLAG_REUSEADDR
#define MEDUSA_TCPSOCKET_FLAG_REUSEPORT         MEDUSA_TCPSOCKET_FLAG_REUSEPORT
#define MEDUSA_TCPSOCKET_FLAG_BACKLOG           MEDUSA_TCPSOCKET_FLAG_BACKLOG
};

#define MEDUSA_TCPSOCKET_USE_POOL       1
#if defined(MEDUSA_TCPSOCKET_USE_POOL) && (MEDUSA_TCPSOCKET_USE_POOL == 1)
static struct medusa_pool *g_pool;
#endif

static int medusa_tcpsocket_io_onevent (struct medusa_io *io, unsigned int events, void *context)
{
        int rc;
        int64_t length;
        unsigned int es;
        struct medusa_tcpsocket *tcpsocket = (struct medusa_tcpsocket *) io;
        (void) context;
        es = 0;
        if (events & MEDUSA_IO_EVENT_OUT) {
                if (tcpsocket->state == MEDUSA_TCPSOCKET_STATE_CONNECTING) {
                        es |= MEDUSA_TCPSOCKET_EVENT_CONNECTED;
                } else if (tcpsocket->state == MEDUSA_TCPSOCKET_STATE_CONNECTED) {
                        length = medusa_buffer_length(&tcpsocket->wbuffer);
                        if (length <= 0) {
                                return -1;
                        }
                        rc = send(tcpsocket->io.fd, medusa_buffer_base(&tcpsocket->wbuffer), length, 0);
                        if (rc < 0) {
                                return -1;
                        }
                        rc = medusa_buffer_eat(&tcpsocket->wbuffer, rc);
                        if (rc != 0) {
                                return -1;
                        }
                        es |= MEDUSA_TCPSOCKET_EVENT_WRITTEN;
                } else {
                        return -1;
                }
                length = medusa_buffer_length(&tcpsocket->wbuffer);
                if (length <= 0) {
                        rc = medusa_io_del_events(&tcpsocket->io, MEDUSA_IO_EVENT_OUT);
                        if (rc != 0) {
                                return -1;
                        }
                }
        }
        if (events & MEDUSA_IO_EVENT_IN) {
                if (tcpsocket->state == MEDUSA_TCPSOCKET_STATE_LISTENING) {
                        es |= MEDUSA_TCPSOCKET_EVENT_CONNECTION;
                } else if (tcpsocket->state == MEDUSA_TCPSOCKET_STATE_CONNECTED) {
                        rc = medusa_buffer_grow(&tcpsocket->rbuffer, 4096);
                        if (rc != 0) {
                                return -1;
                        }
                        rc = recv(
                                tcpsocket->io.fd,
                                medusa_buffer_base(&tcpsocket->rbuffer) + medusa_buffer_length(&tcpsocket->rbuffer),
                                medusa_buffer_size(&tcpsocket->rbuffer) - medusa_buffer_length(&tcpsocket->rbuffer),
                                0);
                        if (rc < 0) {
                                return -1;
                        }
                        rc = medusa_buffer_set_length(&tcpsocket->rbuffer, medusa_buffer_length(&tcpsocket->rbuffer) + rc);
                        if (rc != 0) {
                                return -1;
                        }
                        es |= MEDUSA_TCPSOCKET_EVENT_READ;
                } else {
                        return -1;
                }
        }
        if (events & MEDUSA_IO_EVENT_DESTROY) {
                es |= MEDUSA_TCPSOCKET_EVENT_DESTROY;
        }
        rc = medusa_tcpsocket_onevent(tcpsocket, es);
        return (rc < 0) ? rc : 1;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_init (struct medusa_monitor *monitor, struct medusa_tcpsocket *tcpsocket, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context), void *context)
{
        if (monitor == NULL) {
                return -1;
        }
        if (tcpsocket == NULL) {
                return -1;
        }
        if (onevent == NULL) {
                return -1;
        }
        memset(tcpsocket, 0, sizeof(struct medusa_tcpsocket));
        tcpsocket->io.fd = -1;
        tcpsocket->io.onevent = medusa_tcpsocket_io_onevent;
        tcpsocket->io.context = context;
        tcpsocket->io.events = MEDUSA_IO_EVENT_IN;
        tcpsocket->io.enabled = 0;
        tcpsocket->io.subject.flags = MEDUSA_SUBJECT_FLAG_IO;
        tcpsocket->io.subject.monitor = NULL;
        tcpsocket->flags = MEDUSA_TCPSOCKET_FLAG_DEFAULT;
        tcpsocket->state = MEDUSA_TCPSOCKET_STATE_DISCONNECTED;
        tcpsocket->onevent = onevent;
        medusa_buffer_init(&tcpsocket->rbuffer);
        medusa_buffer_init(&tcpsocket->wbuffer);
        return medusa_monitor_add(monitor, &tcpsocket->io.subject);
}

__attribute__ ((visibility ("default"))) void medusa_tcpsocket_uninit (struct medusa_tcpsocket *tcpsocket)
{
        if (tcpsocket == NULL) {
                return;
        }
        if ((tcpsocket->io.subject.flags & MEDUSA_SUBJECT_FLAG_IO) == 0) {
             return;
        }
        if (tcpsocket->io.subject.monitor != NULL) {
                medusa_monitor_del(&tcpsocket->io.subject);
        } else {
                medusa_tcpsocket_onevent(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DESTROY);
        }
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_create (struct medusa_monitor *monitor, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context), void *context)
{
        int rc;
        struct medusa_tcpsocket *tcpsocket;
        tcpsocket = NULL;
        if (monitor == NULL) {
                goto bail;
        }
        if (onevent == NULL) {
                goto bail;
        }
#if defined(MEDUSA_TCPSOCKET_USE_POOL) && (MEDUSA_TCPSOCKET_USE_POOL == 1)
        tcpsocket = medusa_pool_malloc(g_pool);
#else
        tcpsocket = malloc(sizeof(struct medusa_tcpsocket));
#endif
        if (tcpsocket == NULL) {
                goto bail;
        }
        memset(tcpsocket, 0, sizeof(struct medusa_tcpsocket));
        rc = medusa_tcpsocket_init(monitor, tcpsocket, onevent, context);
        if (rc != 0) {
                goto bail;
        }
        tcpsocket->io.subject.flags |= MEDUSA_SUBJECT_FLAG_ALLOC;
        return tcpsocket;
bail:   if (tcpsocket != NULL) {
                medusa_tcpsocket_destroy(tcpsocket);
        }
        return NULL;
}

__attribute__ ((visibility ("default"))) void medusa_tcpsocket_destroy (struct medusa_tcpsocket *tcpsocket)
{
        medusa_tcpsocket_uninit(tcpsocket);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_tcpsocket_get_state (const struct medusa_tcpsocket *tcpsocket)
{
        if (tcpsocket == NULL) {
                return MEDUSA_TCPSOCKET_STATE_UNKNWON;
        }
        return tcpsocket->state;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_enabled (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        if (tcpsocket == NULL) {
                return 0;
        }
        return medusa_io_set_enabled(&tcpsocket->io, enabled);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_enabled (const struct medusa_tcpsocket *tcpsocket)
{
        if (tcpsocket == NULL) {
                return 0;
        }
        return medusa_io_get_enabled(&tcpsocket->io);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_nonblocking (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        if (tcpsocket == NULL) {
                goto bail;
        }
        if (tcpsocket->io.fd >= 0) {
                int rc;
                int flags;
                flags = fcntl(tcpsocket->io.fd, F_GETFL, 0);
                if (flags < 0) {
                        goto bail;
                }
                flags = enabled ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
                rc = fcntl(tcpsocket->io.fd, F_SETFL, flags);
                if (rc != 0) {
                        goto bail;
                }
        }
        if (enabled) {
                tcpsocket->flags |= MEDUSA_TCPSOCKET_FLAG_NONBLOCKING;
        } else {
                tcpsocket->flags &= ~MEDUSA_TCPSOCKET_FLAG_NONBLOCKING;
        }
        return medusa_monitor_mod(&tcpsocket->io.subject);
bail:   return -1;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_nonblocking (const struct medusa_tcpsocket *tcpsocket)
{
        if (tcpsocket == NULL) {
                return 0;
        }
        return !!(tcpsocket->flags & MEDUSA_TCPSOCKET_FLAG_NONBLOCKING);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_reuseaddr (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        if (tcpsocket == NULL) {
                goto bail;
        }
        if (tcpsocket->io.fd >= 0) {
                int rc;
                int on;
                on = !!enabled;
                rc = setsockopt(tcpsocket->io.fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
                if (rc < 0) {
                        goto bail;
                }
        }
        if (enabled) {
                tcpsocket->flags |= MEDUSA_TCPSOCKET_FLAG_REUSEADDR;
        } else {
                tcpsocket->flags &= ~MEDUSA_TCPSOCKET_FLAG_REUSEADDR;
        }
        return medusa_monitor_mod(&tcpsocket->io.subject);
bail:   return -1;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_reuseaddr (const struct medusa_tcpsocket *tcpsocket)
{
        if (tcpsocket == NULL) {
                return 0;
        }
        return !!(tcpsocket->flags & MEDUSA_TCPSOCKET_FLAG_REUSEADDR);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_reuseport (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        if (tcpsocket == NULL) {
                goto bail;
        }
        if (tcpsocket->io.fd >= 0) {
                int rc;
                int on;
                on = !!enabled;
                rc = setsockopt(tcpsocket->io.fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
                if (rc < 0) {
                        goto bail;
                }
        }
        if (enabled) {
                tcpsocket->flags |= MEDUSA_TCPSOCKET_FLAG_REUSEPORT;
        } else {
                tcpsocket->flags &= ~MEDUSA_TCPSOCKET_FLAG_REUSEPORT;
        }
        return medusa_monitor_mod(&tcpsocket->io.subject);
bail:   return -1;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_reuseport (const struct medusa_tcpsocket *tcpsocket)
{
        if (tcpsocket == NULL) {
                return 0;
        }
        return !!(tcpsocket->flags & MEDUSA_TCPSOCKET_FLAG_REUSEPORT);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_set_backlog (struct medusa_tcpsocket *tcpsocket, int backlog)
{
        int rc;
        if (tcpsocket == NULL) {
                return -1;
        }
        if (tcpsocket->state != MEDUSA_TCPSOCKET_STATE_DISCONNECTED &&
            tcpsocket->state != MEDUSA_TCPSOCKET_STATE_LISTENING) {
                return -1;
        }
        if (tcpsocket->state == MEDUSA_TCPSOCKET_STATE_LISTENING) {
                rc = listen(tcpsocket->io.fd, backlog);
                if (rc != 0) {
                        return -1;
                }
        }
        tcpsocket->backlog = backlog;
        tcpsocket->flags |= MEDUSA_TCPSOCKET_FLAG_BACKLOG;
        return medusa_monitor_mod(&tcpsocket->io.subject);
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_backlog (const struct medusa_tcpsocket *tcpsocket)
{
        if (tcpsocket == NULL) {
                return -1;
        }
        if (tcpsocket->flags & MEDUSA_TCPSOCKET_FLAG_BACKLOG) {
                return tcpsocket->backlog;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_get_fd (const struct medusa_tcpsocket *tcpsocket)
{
        if (tcpsocket == NULL) {
                return -1;
        }
        return tcpsocket->io.fd;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_bind (struct medusa_tcpsocket *tcpsocket, unsigned int protocol, const char *address, unsigned short port)
{
        int rc;
        unsigned int length;
        struct sockaddr *sockaddr;
        struct sockaddr_in sockaddr_in;
        struct sockaddr_in6 sockaddr_in6;
        if (tcpsocket == NULL) {
                return -1;
        }
        if (address == NULL) {
                return -1;
        }
        if (port == 0) {
                return -1;
        }
        if (tcpsocket->state != MEDUSA_TCPSOCKET_STATE_DISCONNECTED) {
                return -1;
        }
        if (tcpsocket->io.fd >= 0) {
                return -1;
        }
        tcpsocket->state = MEDUSA_TCPSOCKET_STATE_BINDING;
        rc = medusa_tcpsocket_onevent(tcpsocket, MEDUSA_TCPSOCKET_EVENT_BINDING);
        if (rc < 0) {
                goto bail;
        }
        if (protocol == MEDUSA_TCPSOCKET_PROTOCOL_IPV4) {
ipv4:
                sockaddr_in.sin_family = AF_INET;
                if (address == NULL) {
                        sockaddr_in.sin_addr.s_addr = INADDR_ANY;
                } else {
                        rc = inet_pton(AF_INET, address, &sockaddr_in.sin_addr);
                        if (rc <= 0) {
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
                        if (rc <= 0) {
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
                        if (rc <= 0) {
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
                goto bail;
        }
        tcpsocket->io.fd = socket(sockaddr->sa_family, SOCK_STREAM, 0);
        if (tcpsocket->io.fd < 0) {
                goto bail;
        }
        rc = bind(tcpsocket->io.fd, sockaddr , length);
        if (rc != 0) {
                goto bail;
        }
        tcpsocket->state = MEDUSA_TCPSOCKET_STATE_BOUND;
        rc = medusa_tcpsocket_onevent(tcpsocket, MEDUSA_TCPSOCKET_EVENT_BOUND);
        if (rc < 0) {
                goto bail;
        }
        if (tcpsocket->flags & MEDUSA_TCPSOCKET_FLAG_BACKLOG) {
                rc = listen(tcpsocket->io.fd, tcpsocket->backlog);
                if (rc != 0) {
                        goto bail;
                }
        }
        rc = medusa_io_set_events(&tcpsocket->io, MEDUSA_IO_EVENT_IN);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_io_set_enabled(&tcpsocket->io, 1);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_monitor_mod(&tcpsocket->io.subject);
        if (rc != 0) {
                goto bail;
        }
        tcpsocket->state = MEDUSA_TCPSOCKET_STATE_LISTENING;
        rc = medusa_tcpsocket_onevent(tcpsocket, MEDUSA_TCPSOCKET_EVENT_LISTENING);
        if (rc < 0) {
                goto bail;
        }
        return 0;
bail:   if (tcpsocket->io.fd >= 0) {
                close(tcpsocket->io.fd);
                tcpsocket->io.fd = -1;
        }
        tcpsocket->state = MEDUSA_TCPSOCKET_STATE_DISCONNECTED;
        medusa_tcpsocket_onevent(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DISCONNECTED);
        return -1;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_connect (struct medusa_tcpsocket *tcpsocket, unsigned int protocol, const char *address, unsigned short port)
{
        int rc;
        struct addrinfo hints;
        struct addrinfo *result;
        struct addrinfo *res;
        result = NULL;
        if (tcpsocket == NULL) {
                return -1;
        }
        if (address == NULL) {
                return -1;
        }
        if (port == 0) {
                return -1;
        }
        if (tcpsocket->state != MEDUSA_TCPSOCKET_STATE_DISCONNECTED) {
                return -1;
        }
        if (tcpsocket->io.fd >= 0) {
                return -1;
        }
        tcpsocket->state = MEDUSA_TCPSOCKET_STATE_RESOLVING;
        rc = medusa_tcpsocket_onevent(tcpsocket, MEDUSA_TCPSOCKET_EVENT_RESOLVING);
        if (rc < 0) {
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
                goto bail;
        }
        tcpsocket->state = MEDUSA_TCPSOCKET_STATE_RESOLVED;
        rc = medusa_tcpsocket_onevent(tcpsocket, MEDUSA_TCPSOCKET_EVENT_RESOLVED);
        if (rc < 0) {
                goto bail;
        }
        tcpsocket->state = MEDUSA_TCPSOCKET_STATE_CONNECTING;
        rc = medusa_tcpsocket_onevent(tcpsocket, MEDUSA_TCPSOCKET_EVENT_CONNECTING);
        if (rc < 0) {
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
                                goto bail;
                }
                if (inet_ntop(res->ai_family, ptr, str, sizeof(str)) == NULL) {
                        continue;
                }
                tcpsocket->io.fd = socket(res->ai_family, SOCK_STREAM, 0);
                if (tcpsocket->io.fd < 0) {
                        goto bail;
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
                goto bail;
        }
        if (rc == 0) {
                tcpsocket->state = MEDUSA_TCPSOCKET_STATE_CONNECTED;
                rc = medusa_tcpsocket_onevent(tcpsocket, MEDUSA_TCPSOCKET_EVENT_CONNECTED);
                if (rc < 0) {
                        goto bail;
                }
        }
        rc = medusa_io_set_enabled(&tcpsocket->io, 1);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_monitor_mod(&tcpsocket->io.subject);
        if (rc != 0) {
                goto bail;
        }
        freeaddrinfo(result);
        return 0;
bail:   if (result != NULL) {
                freeaddrinfo(result);
        }
        if (tcpsocket->io.fd >= 0) {
                close(tcpsocket->io.fd);
                tcpsocket->io.fd = -1;
        }
        tcpsocket->state = MEDUSA_TCPSOCKET_STATE_DISCONNECTED;
        medusa_tcpsocket_onevent(tcpsocket, MEDUSA_TCPSOCKET_EVENT_DISCONNECTED);
        return -1;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_accept_init (struct medusa_tcpsocket *tcpsocket, struct medusa_tcpsocket *accepted, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context), void *context)
{
        int fd;
        int rc;
        if (tcpsocket == NULL) {
                return -1;
        }
        if (accepted == NULL) {
                return -1;
        }
        if (onevent == NULL) {
                return -1;
        }
        fd = accept(tcpsocket->io.fd, NULL, NULL);
        if (fd < 0) {
                return -1;
        }
        rc = medusa_tcpsocket_init(medusa_tcpsocket_get_monitor(tcpsocket), accepted, onevent, context);
        if (rc < 0) {
                close(fd);
                return -1;
        }
        accepted->io.fd = fd;
        accepted->state = MEDUSA_TCPSOCKET_STATE_CONNECTED;
        rc = medusa_tcpsocket_onevent(accepted, MEDUSA_TCPSOCKET_EVENT_CONNECTED);
        if (rc < 0) {
                medusa_tcpsocket_uninit(accepted);
                return -1;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) struct medusa_tcpsocket * medusa_tcpsocket_accept (struct medusa_tcpsocket *tcpsocket, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context), void *context)
{
        int fd;
        int rc;
        struct medusa_tcpsocket *accepted;
        if (tcpsocket == NULL) {
                return NULL;
        }
        if (onevent == NULL) {
                return NULL;
        }
        fd = accept(tcpsocket->io.fd, NULL, NULL);
        if (fd < 0) {
                return NULL;
        }
        accepted = medusa_tcpsocket_create(medusa_tcpsocket_get_monitor(tcpsocket), onevent, context);
        if (accepted == NULL) {
                close(fd);
                return NULL;
        }
        accepted->io.fd = fd;
        rc = medusa_io_set_enabled(&accepted->io, 1);
        if (rc != 0) {
                medusa_tcpsocket_destroy(accepted);
                return NULL;
        }
        rc = medusa_monitor_mod(&accepted->io.subject);
        if (rc != 0) {
                medusa_tcpsocket_destroy(accepted);
                return NULL;
        }
        accepted->state = MEDUSA_TCPSOCKET_STATE_CONNECTED;
        rc = medusa_tcpsocket_onevent(accepted, MEDUSA_TCPSOCKET_EVENT_CONNECTED);
        if (rc < 0) {
                medusa_tcpsocket_destroy(accepted);
                return NULL;
        }
        return accepted;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_read (struct medusa_tcpsocket *tcpsocket, void *data, int size)
{
        int rc;
        int length;
        if (tcpsocket == NULL) {
                return -1;
        }
        if (size < 0) {
                return -1;
        }
        if (size == 0) {
                return 0;
        }
        if (data == NULL) {
                return -1;
        }
        length = MIN(size, medusa_buffer_length(&tcpsocket->rbuffer));
        memcpy(data, medusa_buffer_base(&tcpsocket->rbuffer), length);
        rc = medusa_buffer_eat(&tcpsocket->rbuffer, length);
        if (rc != 0) {
                return -1;
        }
        return length;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_write (struct medusa_tcpsocket *tcpsocket, const void *data, int size)
{
        int rc;
        if (tcpsocket == NULL) {
                return -1;
        }
        if (size < 0) {
                return -1;
        }
        if (size == 0) {
                return 0;
        }
        if (data == NULL) {
                return -1;
        }
        rc = medusa_buffer_push(&tcpsocket->wbuffer, data, size);
        if (rc != 0) {
                return -1;
        }
        rc = medusa_io_add_events(&tcpsocket->io, MEDUSA_IO_EVENT_OUT);
        if (rc != 0) {
                return -1;
        }
        return size;
}

__attribute__ ((visibility ("default"))) int medusa_tcpsocket_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events)
{
        int rc;
        rc = 0;
        if (tcpsocket->onevent != NULL) {
                rc = tcpsocket->onevent(tcpsocket, events, tcpsocket->io.context);
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_DESTROY) {
                medusa_buffer_uninit(&tcpsocket->rbuffer);
                medusa_buffer_uninit(&tcpsocket->wbuffer);
                if (tcpsocket->io.fd >= 0) {
                        close(tcpsocket->io.fd);
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
        return (rc < 0) ? rc : 0;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_tcpsocket_get_monitor (struct medusa_tcpsocket *tcpsocket)
{
        if (tcpsocket == NULL) {
                return NULL;
        }
        return tcpsocket->io.subject.monitor;
}

__attribute__ ((constructor)) static void tcpsocket_constructor (void)
{
#if defined(MEDUSA_TCPSOCKET_USE_POOL) && (MEDUSA_TCPSOCKET_USE_POOL == 1)
        g_pool = medusa_pool_create("medusa-tcpsocket", sizeof(struct medusa_tcpsocket), 0, 0, MEDUSA_POOL_FLAG_DEFAULT, NULL, NULL, NULL);
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
