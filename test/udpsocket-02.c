
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "medusa/error.h"
#include "medusa/udpsocket.h"
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

static int udpsocket_bind_onevent (struct medusa_udpsocket *udpsocket, unsigned int events, void *context, ...)
{
        (void) udpsocket;
        (void) events;
        (void) context;
        fprintf(stderr, "bind    events: 0x%08x, %s\n", events, medusa_udpsocket_event_string(events));
        if (events & MEDUSA_UDPSOCKET_EVENT_IN) {
                return medusa_monitor_break(medusa_udpsocket_get_monitor(udpsocket));
        }
        if (events & MEDUSA_UDPSOCKET_EVENT_ERROR) {
                fprintf(stderr, "          error: %d, %s\n", medusa_udpsocket_get_error(udpsocket), strerror(medusa_udpsocket_get_error(udpsocket)));
        }
        return 0;
}

static int udpsocket_connect_onevent (struct medusa_udpsocket *udpsocket, unsigned int events, void *context, ...)
{
        int rc;
        (void) udpsocket;
        (void) events;
        (void) context;
        fprintf(stderr, "connect events: 0x%08x, %s\n", events, medusa_udpsocket_event_string(events));
        if (events & MEDUSA_UDPSOCKET_EVENT_ERROR) {
                fprintf(stderr, "          error: %d, %s\n", medusa_udpsocket_get_error(udpsocket), strerror(medusa_udpsocket_get_error(udpsocket)));
        }
        if (events & MEDUSA_UDPSOCKET_EVENT_CONNECTED) {
                rc = sendto(medusa_udpsocket_get_fd(udpsocket), "e", 1, 0, NULL, 0);
                if (rc != 1) {
                        return -1;
                }
        }
        return 0;
}

static int test_poll (unsigned int poll)
{
        int rc;

        struct medusa_monitor *monitor;
        struct medusa_monitor_init_options options;

        int port;
        struct medusa_udpsocket *udpsocket;

        monitor = NULL;

        medusa_monitor_init_options_default(&options);
        options.poll.type = poll;

        monitor = medusa_monitor_create_with_options(&options);
        if (monitor == NULL) {
                goto bail;
        }

        udpsocket = medusa_udpsocket_create(monitor, udpsocket_bind_onevent, NULL);
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                goto bail;
        }
        rc = medusa_udpsocket_set_nonblocking(udpsocket, 1);
        if (rc < 0) {
                goto bail;
        }
        rc = medusa_udpsocket_set_reuseaddr(udpsocket, 0);
        if (rc < 0) {
                goto bail;
        }
        rc = medusa_udpsocket_set_reuseport(udpsocket, 0);
        if (rc < 0) {
                goto bail;
        }
        for (port = 12345; port < 65535; port++) {
                rc = medusa_udpsocket_bind(udpsocket, MEDUSA_UDPSOCKET_PROTOCOL_ANY, "127.0.0.1", port);
                if (rc == 0) {
                        break;
                }
        }
        if (port >= 65535) {
                fprintf(stderr, "medusa_udpsocket_bind failed\n");
                goto bail;
        }
        fprintf(stderr, "port: %d\n", port);
        rc = medusa_udpsocket_set_enabled(udpsocket, 1);
        if (rc < 0) {
                goto bail;
        }

        udpsocket = medusa_udpsocket_create(monitor, udpsocket_connect_onevent, NULL);
        if (MEDUSA_IS_ERR_OR_NULL(udpsocket)) {
                goto bail;
        }
        rc = medusa_udpsocket_set_nonblocking(udpsocket, 1);
        if (rc < 0) {
                goto bail;
        }
        rc = medusa_udpsocket_connect(udpsocket, MEDUSA_UDPSOCKET_PROTOCOL_ANY, "127.0.0.1", port);
        if (rc < 0) {
                fprintf(stderr, "medusa_udpsocket_connect failed\n");
                goto bail;
        }
        rc = medusa_udpsocket_set_enabled(udpsocket, 1);
        if (rc < 0) {
                goto bail;
        }

        rc = medusa_monitor_run(monitor);
        if (rc != 0) {
                fprintf(stderr, "medusa_monitor_run failed: %d\n", rc);
                goto bail;
        }

        medusa_monitor_destroy(monitor);
        return 0;
bail:   if (monitor != NULL) {
                medusa_monitor_destroy(monitor);
        }
        return -1;
}

static void alarm_handler (int sig)
{
        (void) sig;
        abort();
}

int main (int argc, char *argv[])
{
        int rc;
        unsigned int i;

        (void) argc;
        (void) argv;

        srand(time(NULL));
        signal(SIGALRM, alarm_handler);

        for (i = 0; i < sizeof(g_polls) / sizeof(g_polls[0]); i++) {
                alarm(5);

                fprintf(stderr, "testing poll: %d\n", g_polls[i]);
                rc = test_poll(g_polls[i]);
                if (rc != 0) {
                        fprintf(stderr, "  failed\n");
                        return -1;
                }
                fprintf(stderr, "success\n");
        }
        return 0;
}
