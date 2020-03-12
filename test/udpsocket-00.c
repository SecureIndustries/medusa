
#include <stdio.h>
#include <stdlib.h>

#include <medusa/error.h>
#include <medusa/udpsocket.h>

int main (int argc, char *argv[])
{
        struct medusa_udpsocket *udpsocket;
        (void) argc;
        (void) argv;
        fprintf(stderr, "start\n");
        udpsocket = medusa_udpsocket_bind(NULL, 0, NULL, 0, NULL, NULL);
        if (!MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -1;
        }
        udpsocket = medusa_udpsocket_open(NULL, 0, NULL, NULL);
        if (!MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -1;
        }
        udpsocket = medusa_udpsocket_connect(NULL, 0, NULL, 0, NULL, NULL);
        if (!MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -1;
        }
        udpsocket = medusa_udpsocket_attach(NULL, -1, NULL, NULL);
        if (!MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                return -1;
        }
        fprintf(stderr, "success\n");
        return 0;
}
