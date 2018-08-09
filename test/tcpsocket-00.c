
#include <stdlib.h>
#include <medusa/error.h>
#include <medusa/tcpsocket.h>

int main (int argc, char *argv[])
{
        struct medusa_tcpsocket *tcpsocket;
        (void) argc;
        (void) argv;
        tcpsocket = medusa_tcpsocket_create(NULL, NULL, NULL);
        if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -1;
        }
        return 0;
}
