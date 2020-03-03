
#include <stdio.h>
#include <stdlib.h>

#if defined(MEDUSA_TEST_TCPSOCKET_SSL) && (MEDUSA_TEST_TCPSOCKET_SSL == 1)
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#include <medusa/error.h>
#include <medusa/tcpsocket.h>

int main (int argc, char *argv[])
{
        struct medusa_tcpsocket *tcpsocket;
        (void) argc;
        (void) argv;
#if defined(MEDUSA_TEST_TCPSOCKET_SSL) && (MEDUSA_TEST_TCPSOCKET_SSL == 1)
        SSL_library_init();
        SSL_load_error_strings();
#endif
        fprintf(stderr, "start\n");
        tcpsocket = medusa_tcpsocket_bind(NULL, 0, NULL, 0, NULL, NULL);
        if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -1;
        }
        tcpsocket = medusa_tcpsocket_accept(NULL, NULL, NULL);
        if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -1;
        }
        tcpsocket = medusa_tcpsocket_connect(NULL, 0, NULL, 0, NULL, NULL);
        if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -1;
        }
        tcpsocket = medusa_tcpsocket_attach(NULL, -1, NULL, NULL);
        if (!MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                return -1;
        }
        fprintf(stderr, "success\n");
        return 0;
}
