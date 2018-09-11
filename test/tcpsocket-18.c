
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

#include "medusa/error.h"
#include "medusa/buffer.h"
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

static int g_backend;
static int g_nclients;

static int g_clients_connected;
static int g_clients_read_finished;
static int g_clients_disconnected;

static int g_server_connected;
static int g_server_write_finished;
static int g_server_disconnected;

static const char *g_greeting =
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";

static int tcpsocket_client_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...)
{
        int rc;
        struct medusa_buffer *rbuffer;
        (void) context;
        fprintf(stderr, "client  : %p, events: 0x%08x\n", tcpsocket, events);
        if (events & MEDUSA_TCPSOCKET_EVENT_CONNECTED) {
                fprintf(stderr, "  connected\n");
                g_clients_connected += 1;
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_READ) {
                fprintf(stderr, "  read\n");
                rbuffer = medusa_tcpsocket_get_read_buffer(tcpsocket);
                if (MEDUSA_IS_ERR_OR_NULL(rbuffer)) {
                        return MEDUSA_PTR_ERR(rbuffer);
                }
                rc = medusa_buffer_get_length(rbuffer);
                if (rc < 0) {
                        return rc;
                }
                if (rc == (int) strlen(g_greeting)) {
                        g_clients_read_finished += 1;
                        medusa_tcpsocket_destroy(tcpsocket);
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_DESTROY) {
                fprintf(stderr, "  destroy\n");
                g_clients_disconnected += 1;
        }
        return 0;
}

static int tcpsocket_server_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...)
{
        int rc;
        (void) context;
        fprintf(stderr, "server  : %p, events: 0x%08x\n", tcpsocket, events);
        if (events & MEDUSA_TCPSOCKET_EVENT_CONNECTED) {
                fprintf(stderr, "  connected\n");
                g_server_connected += 1;
                rc = medusa_tcpsocket_printf(tcpsocket, "%s", g_greeting);
                if (rc < 0) {
                        return rc;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_WRITE_FINISHED) {
                fprintf(stderr, "  write finished\n");
                g_server_write_finished += 1;
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_DISCONNECTED) {
                fprintf(stderr, "  disconnected\n");
                g_server_disconnected += 1;
        }
        return 0;
}

static int tcpsocket_listener_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...)
{
        int rc;
        struct medusa_tcpsocket *accepted;
        struct medusa_tcpsocket_accept_options accepted_options;
        fprintf(stderr, "listener: %p, events: 0x%08x\n", tcpsocket, events);
        if (events & MEDUSA_TCPSOCKET_EVENT_CONNECTION) {
                fprintf(stderr, "  accept\n");
                rc = medusa_tcpsocket_accept_options_default(&accepted_options);
                if (rc < 0) {
                        return rc;
                }
                accepted_options.tcpsocket = tcpsocket;
                accepted_options.nonblocking = 1;
                accepted_options.enabled = 1;
                accepted_options.onevent = tcpsocket_server_onevent;
                accepted_options.context = context;
                accepted_options.monitor = NULL;
                accepted = medusa_tcpsocket_accept_with_options(&accepted_options);
                if (MEDUSA_IS_ERR_OR_NULL(accepted)) {
                        return MEDUSA_PTR_ERR(accepted);
                }
        }
        return 0;
}

static int test_poll (unsigned int poll)
{
        int i;
        int rc;

        struct medusa_monitor *monitor;
        struct medusa_monitor_init_options options;

        unsigned short port;
        struct medusa_tcpsocket *tcpsocket;
        struct medusa_tcpsocket_init_options tcpsocket_init_options;

        monitor = NULL;

        medusa_monitor_init_options_default(&options);
        options.poll.type = poll;

        monitor = medusa_monitor_create(&options);
        if (monitor == NULL) {
                goto bail;
        }

        rc = medusa_tcpsocket_init_options_default(&tcpsocket_init_options);
        if (rc < 0) {
                goto bail;
        }
        tcpsocket_init_options.monitor = monitor;
        tcpsocket_init_options.nonblocking = 1;
        tcpsocket_init_options.reuseaddr = 1;
        tcpsocket_init_options.reuseport = 1;
        tcpsocket_init_options.backlog = g_nclients + 1000;
        tcpsocket_init_options.enabled = 1;
        tcpsocket_init_options.onevent = tcpsocket_listener_onevent;
        tcpsocket_init_options.context = NULL;
        tcpsocket = medusa_tcpsocket_create_with_options(&tcpsocket_init_options);
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
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

        for (i = 0; i < g_nclients; i++) {
                rc = medusa_tcpsocket_init_options_default(&tcpsocket_init_options);
                if (rc < 0) {
                        goto bail;
                }
                tcpsocket_init_options.monitor = monitor;
                tcpsocket_init_options.nonblocking = 1;
                tcpsocket_init_options.reuseaddr = 1;
                tcpsocket_init_options.reuseport = 1;
                tcpsocket_init_options.backlog = 0;
                tcpsocket_init_options.enabled = 1;
                tcpsocket_init_options.onevent = tcpsocket_client_onevent;
                tcpsocket_init_options.context = NULL;
                tcpsocket = medusa_tcpsocket_create_with_options(&tcpsocket_init_options);
                if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                        fprintf(stderr, "can not create tcpsocket\n");
                        goto bail;
                }
                rc = medusa_tcpsocket_connect(tcpsocket, MEDUSA_TCPSOCKET_PROTOCOL_ANY, "127.0.0.1", port);
                if (rc < 0) {
                        fprintf(stderr, "can not connect tcpsocket\n");
                        goto bail;
                }
        }

        g_clients_connected     = 0;
        g_clients_read_finished = 0;
        g_clients_disconnected  = 0;

        g_server_connected      = 0;
        g_server_write_finished = 0;
        g_server_disconnected   = 0;

        while (1) {
                rc = medusa_monitor_run_once(monitor);
                if (rc < 0) {
                        fprintf(stderr, "medusa_monitor_run failed, rc: %d\n", rc);
                        goto bail;
                }
                fprintf(stderr, "monitor run:\n");
                fprintf(stderr, "  client connected: %8d, read-finished : %8d, disconnected: %8d\n", g_clients_connected, g_clients_read_finished, g_clients_disconnected);
                fprintf(stderr, "  server connected: %8d, write-finished: %8d, disconnected: %8d\n", g_server_connected, g_server_write_finished, g_server_disconnected);

                if (g_clients_connected == g_nclients &&
                    g_clients_read_finished == g_nclients &&
                    g_clients_disconnected == g_nclients &&
                    g_server_connected == g_nclients &&
                    g_server_write_finished == g_nclients &&
                    g_server_disconnected == g_nclients) {
                        break;
                }
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
        int c;
        int rc;
        unsigned int i;

        srand(time(NULL));
        signal(SIGALRM, sigalarm_handler);
        signal(SIGINT, sigint_handler);

        g_backend   = -1;
        g_nclients = 100;

        while ((c = getopt(argc, argv, "hb:c:")) != -1) {
                switch (c) {
                        case 'b':
                                g_backend = atoi(optarg);
                                break;
                        case 'c':
                                g_nclients = atoi(optarg);
                                break;
                        case 'h':
                                fprintf(stderr, "%s [-b backend] [-c clients]\n", argv[0]);
                                fprintf(stderr, "  -b: poll backend (default: %d)\n", g_backend);
                                fprintf(stderr, "  -c: client count (default: %d)\n", g_nclients);
                                return 0;
                        default:
                                fprintf(stderr, "unknown param: %c\n", c);
                                return -1;
                }
        }

        fprintf(stderr, "backend : %d\n", g_backend);
        fprintf(stderr, "clients : %d\n", g_nclients);

        if (g_backend >= 0) {
                alarm(30);
                fprintf(stderr, "testing poll: %d ... \n", g_backend);

                rc = test_poll(g_backend);
                if (rc != 0) {
                        fprintf(stderr, "fail\n");
                        return -1;
                } else {
                        fprintf(stderr, "success\n");
                }
        } else {
                for (i = 0; i < sizeof(g_polls) / sizeof(g_polls[0]); i++) {
                        alarm(30);
                        fprintf(stderr, "testing poll: %d ... \n", g_polls[i]);

                        rc = test_poll(g_polls[i]);
                        if (rc != 0) {
                                fprintf(stderr, "fail\n");
                                return -1;
                        } else {
                                fprintf(stderr, "success\n");
                        }
                }
        }

        return 0;
}
