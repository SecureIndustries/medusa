
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

#include "medusa/error.h"
#include "medusa/buffer.h"
#include "medusa/tcpsocket.h"
#include "medusa/monitor.h"

#define GREETING_MESSAGE        "greetings from server"

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

struct client {
        struct medusa_tcpsocket *tcpsocket;
        char *buffer;
        int buffer_size;
        int buffer_length;
};

static int client_tcpsocket_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...)
{
        int64_t length;
        struct client *client = (struct client *) context;

        fprintf(stderr, "client   events: 0x%08x, %s\n", events, medusa_tcpsocket_event_string(events));

        if (events & MEDUSA_TCPSOCKET_EVENT_BUFFERED_READ) {
                fprintf(stderr, "         - reading greeting message\n");
                length = medusa_buffer_get_length(medusa_tcpsocket_get_read_buffer(tcpsocket));
                if (length < 0) {
                        fprintf(stderr, "can not get tcpsocket read buffer length\n");
                        goto bail;
                }
                if (client->buffer_length + length > client->buffer_size) {
                        char *tmp;
                        tmp = realloc(client->buffer, client->buffer_length + length);
                        if (tmp == NULL) {
                                tmp = malloc(client->buffer_length + length);
                                if (tmp == NULL) {
                                        fprintf(stderr, "can not allocate memory\n");
                                        goto bail;
                                }
                                memcpy(tmp, client->buffer, client->buffer_length);
                                free(client->buffer);
                        }
                        client->buffer = tmp;
                        client->buffer_size = client->buffer_length + length;
                }
                length = medusa_buffer_read(medusa_tcpsocket_get_read_buffer(tcpsocket), client->buffer + client->buffer_length, client->buffer_size - client->buffer_length);
                if (length < 0) {
                        fprintf(stderr, "can not read tcpsocket read buffer\n");
                        goto bail;
                }
                client->buffer_length += length;
                if (client->buffer_length == (strlen(GREETING_MESSAGE) + 1)) {
                        fprintf(stderr, "         - read whole greeting message\n");
                        if (memcmp(client->buffer, GREETING_MESSAGE, client->buffer_length) != 0) {
                                fprintf(stderr, "invalid data in tcpsocket read buffer\n");
                                goto bail;
                        } else {
                                fprintf(stderr, "         - greeting message is valid\n");
                                medusa_monitor_break(medusa_tcpsocket_get_monitor(tcpsocket));
                        }
                }
        }
        return 0;
bail:   return -1;
}

static void client_destroy (struct client *client)
{
        if (client == NULL) {
                return;
        }
        if (!MEDUSA_IS_ERR_OR_NULL(client->tcpsocket)) {
                medusa_tcpsocket_destroy(client->tcpsocket);
        }
        if (client->buffer != NULL) {
                free(client->buffer);
        }
        free(client);
}

static struct client * client_create (struct medusa_monitor *monitor, const char *host, unsigned short port)
{
        int rc;
        struct client *client;
        struct medusa_tcpsocket_init_options tcpsocket_init_options;

        client = malloc(sizeof(struct client));
        if (client == NULL) {
                fprintf(stderr, "can not allocate memory\n");
                goto bail;
        }
        memset(client, 0, sizeof(struct client));

        client->buffer        = 0;
        client->buffer_size   = 0;
        client->buffer_length = 0;

        rc = medusa_tcpsocket_init_options_default(&tcpsocket_init_options);
        if (rc != 0) {
                fprintf(stderr, "can not init tcpsocket init options\n");
                goto bail;
        }
        tcpsocket_init_options.monitor     = monitor;
        tcpsocket_init_options.backlog     = 10;
        tcpsocket_init_options.buffered    = 1;
        tcpsocket_init_options.nodelay     = 1;
        tcpsocket_init_options.nonblocking = 1;
        tcpsocket_init_options.reuseaddr   = 1;
        tcpsocket_init_options.reuseport   = 1;
        tcpsocket_init_options.enabled     = 1;
        tcpsocket_init_options.onevent     = client_tcpsocket_onevent;
        tcpsocket_init_options.context     = client;
        client->tcpsocket = medusa_tcpsocket_create_with_options(&tcpsocket_init_options);
        if (MEDUSA_IS_ERR_OR_NULL(client->tcpsocket)) {
                fprintf(stderr, "can not create tcpsocket\n");
                goto bail;
        }
        rc = medusa_tcpsocket_connect(client->tcpsocket, MEDUSA_TCPSOCKET_PROTOCOL_ANY, host, port);
        if (rc < 0) {
                fprintf(stderr, "medusa_tcpsocket_connect failed\n");
                goto bail;
        }

        return client;
bail:   if (client != NULL) {
                client_destroy(client);
        }
        return NULL;
}

static int tcpsocket_server_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...)
{
        (void) tcpsocket;
        (void) context;
        fprintf(stderr, "server   events: 0x%08x, %s\n", events, medusa_tcpsocket_event_string(events));
        return 0;
}

static int tcpsocket_listener_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...)
{
        int rc;
        struct medusa_tcpsocket *accepted;
        struct medusa_tcpsocket_accept_options accepted_options;

        (void) context;

        fprintf(stderr, "listener events: 0x%08x, %s\n", events, medusa_tcpsocket_event_string(events));
        if (events & MEDUSA_TCPSOCKET_EVENT_CONNECTION) {
                fprintf(stderr, "         - accepting new connection\n");
                rc = medusa_tcpsocket_accept_options_default(&accepted_options);
                if (rc != 0) {
                        fprintf(stderr, "can not init accept options\n");
                        goto bail;
                }
                accepted_options.buffered    = 1;
                accepted_options.nodelay     = 1;
                accepted_options.nonblocking = 1;
                accepted_options.enabled     = 1;
                accepted_options.onevent     = tcpsocket_server_onevent;
                accepted_options.context     = NULL;
                accepted = medusa_tcpsocket_accept_with_options(tcpsocket, &accepted_options);
                if (MEDUSA_IS_ERR_OR_NULL(accepted)) {
                        return MEDUSA_PTR_ERR(accepted);
                }

                fprintf(stderr, "         - writing greeting message\n");
                rc = medusa_buffer_write(medusa_tcpsocket_get_write_buffer(accepted), GREETING_MESSAGE, strlen(GREETING_MESSAGE) + 1);
                if (rc != strlen(GREETING_MESSAGE) + 1) {
                        fprintf(stderr, "can not write to tcpsocket buffer (rc: %d)\n", rc);
                        goto bail;
                }
        }

        return 0;
bail:   return -1;
}

static int test_poll (unsigned int poll)
{
        int rc;

        struct medusa_monitor *monitor;
        struct medusa_monitor_init_options monitor_init_options;

        unsigned short port;

        struct medusa_tcpsocket *tcpsocket;
        struct medusa_tcpsocket_init_options tcpsocket_init_options;

        struct client *client;

        monitor = NULL;
        client  = NULL;

        rc = medusa_monitor_init_options_default(&monitor_init_options);
        if (rc != 0) {
                fprintf(stderr, "can not init monitor init options\n");
                goto bail;
        }
        monitor_init_options.poll.type = poll;
        monitor = medusa_monitor_create_with_options(&monitor_init_options);
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                fprintf(stderr, "can not create monitor\n");
                goto bail;
        }

        rc = medusa_tcpsocket_init_options_default(&tcpsocket_init_options);
        if (rc != 0) {
                fprintf(stderr, "can not init tcpsocket init options\n");
                goto bail;
        }
        tcpsocket_init_options.monitor     = monitor;
        tcpsocket_init_options.backlog     = 10;
        tcpsocket_init_options.buffered    = 1;
        tcpsocket_init_options.nodelay     = 1;
        tcpsocket_init_options.nonblocking = 1;
        tcpsocket_init_options.reuseaddr   = 1;
        tcpsocket_init_options.reuseport   = 1;
        tcpsocket_init_options.enabled     = 1;
        tcpsocket_init_options.onevent     = tcpsocket_listener_onevent;
        tcpsocket_init_options.context     = NULL;
        tcpsocket = medusa_tcpsocket_create_with_options(&tcpsocket_init_options);
        if (MEDUSA_IS_ERR_OR_NULL(tcpsocket)) {
                fprintf(stderr, "can not create tcpsocket\n");
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

        client = client_create(monitor, "127.0.0.1", port);
        if (client == NULL) {
                fprintf(stderr, "can not create client\n");
                goto bail;
        }

        rc = medusa_monitor_run(monitor);
        if (rc != 0) {
                fprintf(stderr, "medusa_monitor_run failed\n");
                goto bail;
        }

        client_destroy(client);
        medusa_monitor_destroy(monitor);
        return 0;
bail:   if (client != NULL) {
                client_destroy(client);
        }
        if (monitor != NULL) {
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
                fprintf(stderr, "success\n");
        }
        return 0;
}
