
#include <stdlib.h>
#include <string.h>

#include "queue.h"
#include "subject-struct.h"
#include "io.h"
#include "io-struct.h"
#include "tcpsocket.h"

struct medusa_tcpsocket {
        struct medusa_io io;
};

struct medusa_tcpsocket * medusa_tcpsocket_create (struct medusa_monitor *monitor, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context), void *context)
{
        struct medusa_tcpsocket *tcpsocket;
        (void) monitor;
        (void) onevent;
        (void) context;
        tcpsocket = malloc(sizeof(struct medusa_tcpsocket));
        if (tcpsocket == NULL) {
                goto bail;
        }
        memset(tcpsocket, 0, sizeof(struct medusa_tcpsocket));
        return tcpsocket;
bail:   return NULL;
}

void medusa_tcpsocket_destroy (struct medusa_tcpsocket *tcpsocket)
{
        if (tcpsocket == NULL) {
                return;
        }
        medusa_io_uninit(&tcpsocket->io);
}

unsigned int medusa_tcpspcket_get_state (const struct medusa_tcpsocket *tcpsocket)
{
        (void) tcpsocket;
        return 0;
}

int medusa_tcpsocket_set_nonblocking (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        (void) tcpsocket;
        (void) enabled;
        return 0;
}

int medusa_tcpsocket_get_nonblocking (const struct medusa_tcpsocket *tcpsocket)
{
        (void) tcpsocket;
        return 0;
}

int medusa_tcpsocket_set_reuseaddr (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        (void) tcpsocket;
        (void) enabled;
        return 0;
}

int medusa_tcpsocket_get_reuseaddr (const struct medusa_tcpsocket *tcpsocket)
{
        (void) tcpsocket;
        return 0;
}

int medusa_tcpsocket_set_reuseport (struct medusa_tcpsocket *tcpsocket, int enabled)
{
        (void) tcpsocket;
        (void) enabled;
        return 0;
}

int medusa_tcpsocket_get_reuseport (const struct medusa_tcpsocket *tcpsocket)
{
        (void) tcpsocket;
        return 0;
}

int medusa_tcpsocket_bind (struct medusa_tcpsocket *tcpsocket, const char *address, unsigned int port)
{
        (void) tcpsocket;
        (void) address;
        (void) port;
        return 0;
}

int medusa_tcpsocket_connect (struct medusa_tcpsocket *tcpsocket, const char *address, unsigned int port)
{
        (void) tcpsocket;
        (void) address;
        (void) port;
        return 0;
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
