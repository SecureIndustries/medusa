
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "queue.h"
#include "subject-struct.h"
#include "io.h"
#include "io-struct.h"
#include "tcpsocket.h"

enum {
        MEDUSA_TCPSOCKET_FLAG_DEFAULT           = 0x00000000,
        MEDUSA_TCPSOCKET_FLAG_NONBLOCKING       = 0x00000001,
        MEDUSA_TCPSOCKET_FLAG_REUSEADDR         = 0x00000002,
        MEDUSA_TCPSOCKET_FLAG_REUSEPORT         = 0x00000004,
#define MEDUSA_TCPSOCKET_FLAG_DEFAULT           MEDUSA_TCPSOCKET_FLAG_DEFAULT
#define MEDUSA_TCPSOCKET_FLAG_NONBLOCKING       MEDUSA_TCPSOCKET_FLAG_NONBLOCKING
#define MEDUSA_TCPSOCKET_FLAG_REUSEADDR         MEDUSA_TCPSOCKET_FLAG_REUSEADDR
#define MEDUSA_TCPSOCKET_FLAG_REUSEPORT         MEDUSA_TCPSOCKET_FLAG_REUSEPORT
};

struct medusa_tcpsocket {
        int fd;
        unsigned int flags;
        unsigned int state;
        int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context);
        void *context;
        struct medusa_io io;
        struct medusa_monitor *monitor;
};

struct medusa_tcpsocket * medusa_tcpsocket_create (struct medusa_monitor *monitor, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context), void *context)
{
        struct medusa_tcpsocket *tcpsocket;
        tcpsocket = NULL;
        if (monitor == NULL) {
                goto bail;
        }
        if (onevent == NULL) {
                goto bail;
        }
        tcpsocket = malloc(sizeof(struct medusa_tcpsocket));
        if (tcpsocket == NULL) {
                goto bail;
        }
        memset(tcpsocket, 0, sizeof(struct medusa_tcpsocket));
        tcpsocket->fd = -1;
        tcpsocket->flags = MEDUSA_TCPSOCKET_FLAG_DEFAULT;
        tcpsocket->state = MEDUSA_TCPSOCKET_STATE_DISCONNECTED;
        tcpsocket->onevent = onevent;
        tcpsocket->context = context;
        tcpsocket->monitor = monitor;
        return tcpsocket;
bail:   if (tcpsocket != NULL) {
                medusa_tcpsocket_destroy(tcpsocket);
        }
        return NULL;
}

void medusa_tcpsocket_destroy (struct medusa_tcpsocket *tcpsocket)
{
        if (tcpsocket == NULL) {
                return;
        }
        if (tcpsocket->fd >= 0) {
                medusa_io_uninit(&tcpsocket->io);
        } else {
                free(tcpsocket);
        }
}

unsigned int medusa_tcpspcket_get_state (const struct medusa_tcpsocket *tcpsocket)
{
        if (tcpsocket == NULL) {
                return MEDUSA_TCPSOCKET_STATE_UNKNWON;
        }
        return tcpsocket->state;
}

int medusa_tcpsocket_set_nonblocking (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        if (tcpsocket == NULL) {
                goto bail;
        }
        if (tcpsocket->fd >= 0) {
                int rc;
                int flags;
                flags = fcntl(tcpsocket->fd, F_GETFL, 0);
                if (flags < 0) {
                        goto bail;
                }
                flags = enabled ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
                rc = fcntl(tcpsocket->fd, F_SETFL, flags);
                if (rc != 0) {
                        goto bail;
                }
        }
        if (enabled) {
                tcpsocket->flags |= MEDUSA_TCPSOCKET_FLAG_NONBLOCKING;
        } else {
                tcpsocket->flags &= ~MEDUSA_TCPSOCKET_FLAG_NONBLOCKING;
        }
        return 0;
bail:   return -1;
}

int medusa_tcpsocket_get_nonblocking (const struct medusa_tcpsocket *tcpsocket)
{
        if (tcpsocket == NULL) {
                return 0;
        }
        return !!(tcpsocket->flags & MEDUSA_TCPSOCKET_FLAG_NONBLOCKING);
}

int medusa_tcpsocket_set_reuseaddr (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        if (tcpsocket == NULL) {
                goto bail;
        }
        if (tcpsocket->fd >= 0) {
                int rc;
                int on;
                on = !!enabled;
                rc = setsockopt(tcpsocket->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
                if (rc < 0) {
                        goto bail;
                }
        }
        if (enabled) {
                tcpsocket->flags |= MEDUSA_TCPSOCKET_FLAG_REUSEADDR;
        } else {
                tcpsocket->flags &= ~MEDUSA_TCPSOCKET_FLAG_REUSEADDR;
        }
        return 0;
bail:   return -1;
}

int medusa_tcpsocket_get_reuseaddr (const struct medusa_tcpsocket *tcpsocket)
{
        if (tcpsocket == NULL) {
                return 0;
        }
        return !!(tcpsocket->flags & MEDUSA_TCPSOCKET_FLAG_REUSEADDR);
}

int medusa_tcpsocket_set_reuseport (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        if (tcpsocket == NULL) {
                goto bail;
        }
        if (tcpsocket->fd >= 0) {
                int rc;
                int on;
                on = !!enabled;
                rc = setsockopt(tcpsocket->fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
                if (rc < 0) {
                        goto bail;
                }
        }
        if (enabled) {
                tcpsocket->flags |= MEDUSA_TCPSOCKET_FLAG_REUSEPORT;
        } else {
                tcpsocket->flags &= ~MEDUSA_TCPSOCKET_FLAG_REUSEPORT;
        }
        return 0;
bail:   return -1;
}

int medusa_tcpsocket_get_reuseport (const struct medusa_tcpsocket *tcpsocket)
{
        if (tcpsocket == NULL) {
                return 0;
        }
        return !!(tcpsocket->flags & MEDUSA_TCPSOCKET_FLAG_REUSEPORT);
}

int medusa_tcpsocket_bind (struct medusa_tcpsocket *tcpsocket, const char *address, unsigned short port)
{
        if (tcpsocket == NULL) {
                goto bail;
        }
        if (address == NULL) {
                goto bail;
        }
        if (port == 0) {
                goto bail;
        }
        if (tcpsocket->state != MEDUSA_TCPSOCKET_STATE_DISCONNECTED) {
                goto bail;
        }
        return 0;
bail:   return -1;
}

int medusa_tcpsocket_connect (struct medusa_tcpsocket *tcpsocket, const char *address, unsigned short port)
{
        if (tcpsocket == NULL) {
                goto bail;
        }
        if (address == NULL) {
                goto bail;
        }
        if (port == 0) {
                goto bail;
        }
        if (tcpsocket->state != MEDUSA_TCPSOCKET_STATE_DISCONNECTED) {
                goto bail;
        }
        return 0;
bail:   return -1;
}

int medusa_tcpsocket_read (struct medusa_tcpsocket *tcpsocket, void *data, int size)
{
        (void) tcpsocket;
        (void) data;
        (void) size;
        return 0;
}

int medusa_tcpsocket_write (struct medusa_tcpsocket *tcpsocket, const void *data, int size)
{
        (void) tcpsocket;
        (void) data;
        (void) size;
        return 0;
}
