
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

#include "medusa/error.h"
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

static int tcpsocket_client_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context)
{
        int rc;
        char c;
        unsigned int *cevents;
        cevents = (unsigned int *) context;
        fprintf(stderr, "client   events: 0x%08x / 0x%08x\n", events, *cevents);
        if (events & MEDUSA_TCPSOCKET_EVENT_RESOLVING) {
                if (*cevents & MEDUSA_TCPSOCKET_EVENT_RESOLVING) {
                        fprintf(stderr, "  invalid events\n");
                        return -1;
                }
                *cevents |= MEDUSA_TCPSOCKET_EVENT_RESOLVING;
                if (medusa_tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_RESOLVING) {
                        fprintf(stderr, "  invalid state\n");
                        return -1;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_RESOLVED) {
                if (*cevents & MEDUSA_TCPSOCKET_EVENT_RESOLVED) {
                        fprintf(stderr, "  invalid events\n");
                        return -1;
                }
                *cevents |= MEDUSA_TCPSOCKET_EVENT_RESOLVED;
                if (medusa_tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_RESOLVED) {
                        fprintf(stderr, "  invalid state\n");
                        return -1;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_CONNECTING) {
                if (*cevents & MEDUSA_TCPSOCKET_EVENT_CONNECTING) {
                        fprintf(stderr, "  invalid events\n");
                        return -1;
                }
                *cevents |= MEDUSA_TCPSOCKET_EVENT_CONNECTING;
                if (medusa_tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_CONNECTING) {
                        fprintf(stderr, "  invalid state\n");
                        return -1;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_CONNECTED) {
                if (*cevents & MEDUSA_TCPSOCKET_EVENT_CONNECTED) {
                        fprintf(stderr, "  invalid events\n");
                        return -1;
                }
                *cevents |= MEDUSA_TCPSOCKET_EVENT_CONNECTED;
                if (medusa_tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_CONNECTED) {
                        fprintf(stderr, "  invalid state\n");
                        return -1;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_READ) {
                if (*cevents & MEDUSA_TCPSOCKET_EVENT_READ) {
                        fprintf(stderr, "  invalid events\n");
                        return -1;
                }
                *cevents |= MEDUSA_TCPSOCKET_EVENT_READ;
                if (medusa_tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_CONNECTED) {
                        fprintf(stderr, "  invalid state\n");
                        return -1;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_WRITTEN) {
                if (*cevents & MEDUSA_TCPSOCKET_EVENT_WRITTEN) {
                        fprintf(stderr, "  invalid events\n");
                        return -1;
                }
                *cevents |= MEDUSA_TCPSOCKET_EVENT_WRITTEN;
                if (medusa_tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_CONNECTED) {
                        fprintf(stderr, "  invalid state\n");
                        return -1;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_WRITE_FINISHED) {
                if (*cevents & MEDUSA_TCPSOCKET_EVENT_WRITE_FINISHED) {
                        fprintf(stderr, "  invalid events\n");
                        return -1;
                }
                *cevents |= MEDUSA_TCPSOCKET_EVENT_WRITE_FINISHED;
                if (medusa_tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_CONNECTED) {
                        fprintf(stderr, "  invalid state\n");
                        return -1;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_DISCONNECTED) {
                if (*cevents & MEDUSA_TCPSOCKET_EVENT_DISCONNECTED) {
                        fprintf(stderr, "  invalid events\n");
                        return -1;
                }
                *cevents |= MEDUSA_TCPSOCKET_EVENT_DISCONNECTED;
                if (medusa_tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_DISCONNECTED) {
                        fprintf(stderr, "  invalid state %d != %d\n", medusa_tcpsocket_get_state(tcpsocket), MEDUSA_TCPSOCKET_STATE_DISCONNECTED);
                        return -1;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_CONNECTED) {
                fprintf(stderr, "write\n");
                rc = medusa_tcpsocket_write(tcpsocket, "e", 1);
                if (rc != 1) {
                        fprintf(stderr, "medusa_tcpsocket_write failed\n");
                        return -1;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_READ) {
                rc = medusa_tcpsocket_read(tcpsocket, &c, 1);
                if (rc != 1) {
                        fprintf(stderr, "medusa_tcpsocket_read failed, rc: %d\n", rc);
                        return -1;
                }
                if (c != 'e') {
                        return -1;
                }
                medusa_tcpsocket_destroy(tcpsocket);
                return medusa_monitor_break(medusa_tcpsocket_get_monitor(tcpsocket));
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_DISCONNECTED) {
                return medusa_monitor_break(medusa_tcpsocket_get_monitor(tcpsocket));
        }
        return 0;
}

static int tcpsocket_server_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context)
{
        int rc;
        char c;
        unsigned int *levents;
        levents = (unsigned int *) context;
        fprintf(stderr, "server   events: 0x%08x / 0x%08x\n", events, *levents);
        if (events & MEDUSA_TCPSOCKET_EVENT_CONNECTED) {
                if (*levents & MEDUSA_TCPSOCKET_EVENT_CONNECTED) {
                        fprintf(stderr, "  invalid events\n");
                        return -1;
                }
                *levents |= MEDUSA_TCPSOCKET_EVENT_CONNECTED;
                if (medusa_tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_CONNECTED) {
                        fprintf(stderr, "  invalid state\n");
                        return -1;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_READ) {
                if (*levents & MEDUSA_TCPSOCKET_EVENT_READ) {
                        fprintf(stderr, "  invalid events\n");
                        return -1;
                }
                *levents |= MEDUSA_TCPSOCKET_EVENT_READ;
                if (medusa_tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_CONNECTED) {
                        fprintf(stderr, "  invalid state\n");
                        return -1;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_WRITTEN) {
                if (*levents & MEDUSA_TCPSOCKET_EVENT_WRITTEN) {
                        fprintf(stderr, "  invalid events\n");
                        return -1;
                }
                *levents |= MEDUSA_TCPSOCKET_EVENT_WRITTEN;
                if (medusa_tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_CONNECTED) {
                        fprintf(stderr, "  invalid state\n");
                        return -1;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_WRITE_FINISHED) {
                if (*levents & MEDUSA_TCPSOCKET_EVENT_WRITE_FINISHED) {
                        fprintf(stderr, "  invalid events\n");
                        return -1;
                }
                *levents |= MEDUSA_TCPSOCKET_EVENT_WRITE_FINISHED;
                if (medusa_tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_CONNECTED) {
                        fprintf(stderr, "  invalid state\n");
                        return -1;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_DISCONNECTED) {
                if (*levents & MEDUSA_TCPSOCKET_EVENT_DISCONNECTED) {
                        fprintf(stderr, "  invalid events\n");
                        return -1;
                }
                *levents |= MEDUSA_TCPSOCKET_EVENT_DISCONNECTED;
                if (medusa_tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_DISCONNECTED) {
                        fprintf(stderr, "  invalid state\n");
                        return -1;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_READ) {
                fprintf(stderr, "read\n");
                rc = medusa_tcpsocket_read(tcpsocket, &c, 1);
                if (rc != 1) {
                        fprintf(stderr, "medusa_tcpsocket_read failed\n");
                        return -1;
                }
                rc = medusa_tcpsocket_write(tcpsocket, &c, 1);
                if (rc != 1) {
                        fprintf(stderr, "medusa_tcpsocket_write failed\n");
                        return -1;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_DISCONNECTED) {
                return medusa_monitor_break(medusa_tcpsocket_get_monitor(tcpsocket));
        }
        return 0;
}

static int tcpsocket_listener_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context)
{
        int rc;
        unsigned int *levents;
        struct medusa_tcpsocket *accepted;
        levents = (unsigned int *) context;
        fprintf(stderr, "listener events: 0x%08x\n", events);
        if (events & MEDUSA_TCPSOCKET_EVENT_DISCONNECTED) {
                if (*levents & MEDUSA_TCPSOCKET_EVENT_DISCONNECTED) {
                        fprintf(stderr, "  invalid events\n");
                        return -1;
                }
                *levents = 0;
                if (medusa_tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_DISCONNECTED) {
                        fprintf(stderr, "  invalid state\n");
                        return -1;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_BINDING) {
                if (*levents & MEDUSA_TCPSOCKET_EVENT_BINDING) {
                        fprintf(stderr, "  invalid events\n");
                        return -1;
                }
                *levents |= MEDUSA_TCPSOCKET_EVENT_BINDING;
                if (medusa_tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_BINDING) {
                        fprintf(stderr, "  invalid state\n");
                        return -1;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_BOUND) {
                if (*levents & MEDUSA_TCPSOCKET_EVENT_BOUND) {
                        fprintf(stderr, "  invalid events\n");
                        return -1;
                }
                *levents |= MEDUSA_TCPSOCKET_EVENT_BOUND;
                if (medusa_tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_BOUND) {
                        fprintf(stderr, "  invalid state\n");
                        return -1;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_LISTENING) {
                if (*levents & MEDUSA_TCPSOCKET_EVENT_LISTENING) {
                        fprintf(stderr, "  invalid events\n");
                        return -1;
                }
                *levents |= MEDUSA_TCPSOCKET_EVENT_LISTENING;
                if (medusa_tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_LISTENING) {
                        fprintf(stderr, "  invalid state\n");
                        return -1;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_CONNECTION) {
                if (*levents & MEDUSA_TCPSOCKET_EVENT_CONNECTION) {
                        fprintf(stderr, "  invalid events\n");
                        return -1;
                }
                *levents |= MEDUSA_TCPSOCKET_EVENT_CONNECTION;
                if (medusa_tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_LISTENING) {
                        fprintf(stderr, "  invalid state\n");
                        return -1;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_CONNECTION) {
                accepted = medusa_tcpsocket_accept(tcpsocket, tcpsocket_server_onevent, context);
                if (MEDUSA_IS_ERR_OR_NULL(accepted)) {
                        return MEDUSA_PTR_ERR(accepted);
                }
                rc = medusa_tcpsocket_set_nonblocking(accepted, 1);
                if (rc < 0) {
                        medusa_tcpsocket_destroy(accepted);
                        return -1;
                }
                rc = medusa_tcpsocket_set_enabled(accepted, 1);
                if (rc < 0) {
                        medusa_tcpsocket_destroy(accepted);
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

        unsigned short port;
        unsigned int levents;
        unsigned int cevents;
        struct medusa_tcpsocket *tcpsocket;

        monitor = NULL;
        cevents = 0;
        levents = 0;

        medusa_monitor_init_options_default(&options);
        options.poll.type = poll;

        monitor = medusa_monitor_create(&options);
        if (monitor == NULL) {
                goto bail;
        }

        tcpsocket = medusa_tcpsocket_create(monitor, tcpsocket_listener_onevent, &levents);
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                goto bail;
        }
        if (medusa_tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_DISCONNECTED) {
                fprintf(stderr, "  invalid state\n");
                return -1;
        }
        rc = medusa_tcpsocket_set_enabled(tcpsocket, 1);
        if (rc < 0) {
                goto bail;
        }
        rc = medusa_tcpsocket_set_nonblocking(tcpsocket, 1);
        if (rc < 0) {
                goto bail;
        }
        rc = medusa_tcpsocket_set_reuseaddr(tcpsocket, 0);
        if (rc < 0) {
                goto bail;
        }
        rc = medusa_tcpsocket_set_reuseport(tcpsocket, 1);
        if (rc < 0) {
                goto bail;
        }
        rc = medusa_tcpsocket_set_backlog(tcpsocket, 10);
        if (rc < 0) {
                goto bail;
        }
        for (port = 12345; port < 65535; port++) {
                rc = medusa_tcpsocket_bind(tcpsocket, MEDUSA_TCPSOCKET_PROTOCOL_ANY, "127.0.0.1", port);
                if (rc == 0) {
                        break;
                }
        }
        if (port >= 65535) {
                fprintf(stderr, "medusa_tcpsocket_bind failed\n");
                goto bail;
        }

        fprintf(stderr, "port: %d\n", port);

        tcpsocket = medusa_tcpsocket_create(monitor, tcpsocket_client_onevent, &cevents);
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                goto bail;
        }
        if (medusa_tcpsocket_get_state(tcpsocket) != MEDUSA_TCPSOCKET_STATE_DISCONNECTED) {
                fprintf(stderr, "  invalid state\n");
                return -1;
        }
        rc = medusa_tcpsocket_set_enabled(tcpsocket, 1);
        if (rc < 0) {
                goto bail;
        }
        rc = medusa_tcpsocket_set_nonblocking(tcpsocket, 1);
        if (rc < 0) {
                goto bail;
        }
        rc = medusa_tcpsocket_connect(tcpsocket, MEDUSA_TCPSOCKET_PROTOCOL_ANY, "127.0.0.1", port);
        if (rc < 0) {
                fprintf(stderr, "medusa_tcpsocket_connect failed\n");
                goto bail;
        }

        rc = medusa_monitor_run(monitor);
        if (rc != 0) {
                fprintf(stderr, "medusa_monitor_run failed\n");
                goto bail;
        }

        if (levents != (MEDUSA_TCPSOCKET_EVENT_BINDING |
                        MEDUSA_TCPSOCKET_EVENT_BOUND |
                        MEDUSA_TCPSOCKET_EVENT_LISTENING |
                        MEDUSA_TCPSOCKET_EVENT_CONNECTION |
                        MEDUSA_TCPSOCKET_EVENT_CONNECTED |
                        MEDUSA_TCPSOCKET_EVENT_READ |
                        MEDUSA_TCPSOCKET_EVENT_WRITTEN |
                        MEDUSA_TCPSOCKET_EVENT_WRITE_FINISHED |
                        MEDUSA_TCPSOCKET_EVENT_DISCONNECTED)) {
                fprintf(stderr, "listener events: 0x%08x is invalid\n", levents);
                goto bail;
        }
        if (cevents != (MEDUSA_TCPSOCKET_EVENT_RESOLVING |
                        MEDUSA_TCPSOCKET_EVENT_RESOLVED |
                        MEDUSA_TCPSOCKET_EVENT_CONNECTING |
                        MEDUSA_TCPSOCKET_EVENT_CONNECTED |
                        MEDUSA_TCPSOCKET_EVENT_READ |
                        MEDUSA_TCPSOCKET_EVENT_WRITTEN |
                        MEDUSA_TCPSOCKET_EVENT_WRITE_FINISHED)) {
                fprintf(stderr, "client   events: 0x%08x invalid\n", cevents);
                goto bail;
        }

        medusa_monitor_destroy(monitor);
        return 0;
bail:   if (monitor != NULL) {
                medusa_monitor_destroy(monitor);
        }
        return -1;
}

static void sigalarm_handler (int sig)
{
        (void) sig;
        abort();
}

static void sigint_handler (int sig)
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
        signal(SIGALRM, sigalarm_handler);
        signal(SIGINT, sigint_handler);

        for (i = 0; i < sizeof(g_polls) / sizeof(g_polls[0]); i++) {
                alarm(5);
                fprintf(stderr, "testing poll: %d\n", g_polls[i]);

                rc = test_poll(g_polls[i]);
                if (rc != 0) {
                        fprintf(stderr, "failed\n");
                        return -1;
                }
        }
        return 0;
}
