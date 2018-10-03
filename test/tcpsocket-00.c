
#include <stdio.h>
#include <stdlib.h>

#include <medusa/error.h>
#include <medusa/tcpsocket.h>

int main (int argc, char *argv[])
{
        struct medusa_tcpsocket *tcpsocket;
        (void) argc;
        (void) argv;
        fprintf(stderr, "start\n");
        tcpsocket = medusa_tcpsocket_create(NULL, NULL, NULL);
        if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -1;
        }
        fprintf(stderr, "success\n");
        return 0;
}
