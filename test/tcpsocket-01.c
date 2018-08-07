
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include "medusa/tcpsocket.h"
#include "medusa/monitor.h"

static const unsigned int g_polls[] = {
        MEDUSA_MONITOR_POLL_DEFAULT,
#if defined(__LINUX__)
        MEDUSA_MONITOR_POLL_EPOLL,
#endif
#if defined(__APPLE__)
        MEDUSA_MONITOR_POLL_KQUEUE,
#endif
        MEDUSA_MONITOR_POLL_POLL,
        MEDUSA_MONITOR_POLL_SELECT
};

static int tcpsocket_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context)
{
        (void) tcpsocket;
        (void) events;
        (void) context;
        return 0;
}

static int test_poll (unsigned int poll)
{
        int rc;

        struct medusa_monitor *monitor;
        struct medusa_monitor_init_options options;

        struct medusa_tcpsocket *tcpsocket;

        monitor = NULL;

        medusa_monitor_init_options_default(&options);
        options.poll.type = poll;

        monitor = medusa_monitor_create(&options);
        if (monitor == NULL) {
                goto bail;
        }

        tcpsocket = medusa_tcpsocket_create(monitor, tcpsocket_onevent, NULL);
        if (tcpsocket == NULL) {
                goto bail;
        }
        rc = medusa_tcpsocket_set_nonblocking(tcpsocket, 1);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_tcpsocket_set_reuseaddr(tcpsocket, 0);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_tcpsocket_set_reuseport(tcpsocket, 1);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_tcpsocket_bind(tcpsocket, MEDUSA_TCPSOCKET_PROTOCOL_ANY, "127.0.0.1", 12345);
        if (rc != 0) {
                fprintf(stderr, "  medusa_tcpsocket_bind failed\n");
                goto bail;
        }
        rc = medusa_tcpsocket_set_enabled(tcpsocket, 1);
        if (rc != 0) {
                goto bail;
        }

        medusa_monitor_destroy(monitor);
        return 0;
bail:   if (monitor != NULL) {
                medusa_monitor_destroy(monitor);
        }
        return -1;
}

int main (int argc, char *argv[])
{
        int rc;
        unsigned int i;
        (void) argc;
        (void) argv;
        for (i = 0; i < sizeof(g_polls) / sizeof(g_polls[0]); i++) {
                fprintf(stderr, "testing poll: %d\n", g_polls[i]);
                rc = test_poll(g_polls[i]);
                if (rc != 0) {
                        fprintf(stderr, "  failed\n");
                        return -1;
                }
        }
        return 0;
}
