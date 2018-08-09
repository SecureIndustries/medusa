
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "http_parser.h"

#include "error.h"
#include "tcpsocket.h"
#include "http_parser.h"
#include "http.h"

struct callback {
        char *path;
        struct medusa_http_server_callback callback;
        void *context;
};

struct client {
        http_parser http_parser;
        struct medusa_tcpsocket *tcpsocket;
        struct medusa_http_server *server;
};

struct medusa_http_server {
        struct medusa_tcpsocket *tcpsocket;
};

static int client_http_on_message_begin (http_parser *http_parser)
{
        struct client *client = http_parser->data;
        (void) client;
        fprintf(stderr, "enter @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        return 0;
}

static int client_http_on_url (http_parser *http_parser, const char *at, size_t length)
{
        struct client *client = http_parser->data;
        (void) client;
        (void) at;
        (void) length;
        fprintf(stderr, "enter @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        return 0;
}

static int client_http_on_status (http_parser *http_parser, const char *at, size_t length)
{
        struct client *client = http_parser->data;
        (void) client;
        (void) at;
        (void) length;
        fprintf(stderr, "enter @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        return 0;
}

static int client_http_on_header_field (http_parser *http_parser, const char *at, size_t length)
{
        struct client *client = http_parser->data;
        (void) client;
        (void) at;
        (void) length;
        fprintf(stderr, "enter @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        return 0;
}

static int client_http_on_header_value (http_parser *http_parser, const char *at, size_t length)
{
        struct client *client = http_parser->data;
        (void) client;
        (void) at;
        (void) length;
        fprintf(stderr, "enter @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        return 0;
}

static int client_http_on_headers_complete (http_parser *http_parser)
{
        struct client *client = http_parser->data;
        (void) client;
        fprintf(stderr, "enter @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        return 0;
}

static int client_http_on_body (http_parser *http_parser, const char *at, size_t length)
{
        struct client *client = http_parser->data;
        (void) client;
        (void) at;
        (void) length;
        fprintf(stderr, "enter @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        return 0;
}

static int client_http_on_message_complete (http_parser *http_parser)
{
        struct client *client = http_parser->data;
        (void) client;
        fprintf(stderr, "enter @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        return 0;
}

static int client_http_on_chunk_header (http_parser *http_parser)
{
        struct client *client = http_parser->data;
        (void) client;
        fprintf(stderr, "enter @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        return 0;
}

static int client_http_on_chunk_complete (http_parser *http_parser)
{
        struct client *client = http_parser->data;
        (void) client;
        fprintf(stderr, "enter @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        return 0;
}

static int client_tcpsocket_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context)
{
        int recved;
        int parsed;
        http_parser_settings http_parser_settings;
        struct client *client = context;

        memset(&http_parser_settings, 0, sizeof(http_parser_settings));
        http_parser_settings.on_message_begin           = client_http_on_message_begin;
        http_parser_settings.on_url                     = client_http_on_url;
        http_parser_settings.on_status                  = client_http_on_status;
        http_parser_settings.on_header_field            = client_http_on_header_field;
        http_parser_settings.on_header_value            = client_http_on_header_value;
        http_parser_settings.on_headers_complete        = client_http_on_headers_complete;
        http_parser_settings.on_body                    = client_http_on_body;
        http_parser_settings.on_message_complete        = client_http_on_message_complete;
        http_parser_settings.on_chunk_header            = client_http_on_chunk_header;
        http_parser_settings.on_chunk_complete          = client_http_on_chunk_complete;

        if (events & MEDUSA_TCPSOCKET_EVENT_READ) {
                char buffer[64];
                int buffer_length = sizeof(buffer);
                while (1) {
                        recved = medusa_tcpsocket_read(tcpsocket, buffer, buffer_length);
                        if (recved < 0) {
                                return recved;
                        }
                        if (recved == 0) {
                                break;
                        }
                        parsed = http_parser_execute(&client->http_parser, &http_parser_settings, buffer, recved);
                        if (parsed != recved) {
                                return -EIO;
                        }
                }
        }

        if (events & MEDUSA_TCPSOCKET_EVENT_DISCONNECTED) {
                medusa_tcpsocket_destroy(tcpsocket);
        }

        if (events & MEDUSA_TCPSOCKET_EVENT_DESTROY) {
                client->tcpsocket = NULL;
                free(client);
        }

        return 0;
}

static int server_tcpsocket_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context)
{
        int rc;
        struct client *client;
        struct medusa_http_server *server = context;
        if (events & MEDUSA_TCPSOCKET_EVENT_CONNECTION) {
                client = malloc(sizeof(struct client));
                if (client == NULL) {
                        return -ENOMEM;
                }
                memset(client, 0, sizeof(struct client));
                http_parser_init(&client->http_parser, HTTP_REQUEST);
                client->http_parser.data = client;
                client->server = server;
                client->tcpsocket = medusa_tcpsocket_accept(tcpsocket, client_tcpsocket_onevent, client);
                if (MEDUSA_IS_ERR_OR_NULL(client->tcpsocket)) {
                        return MEDUSA_PTR_ERR(client->tcpsocket);
                }
                rc = medusa_tcpsocket_set_nonblocking(client->tcpsocket, 1);
                if (rc < 0) {
                        medusa_tcpsocket_destroy(client->tcpsocket);
                        free(client);
                        return rc;
                }
                rc = medusa_tcpsocket_set_enabled(client->tcpsocket, 1);
                if (rc < 0) {
                        medusa_tcpsocket_destroy(client->tcpsocket);
                        free(client);
                        return rc;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_DESTROY) {
                server->tcpsocket = NULL;
                medusa_http_server_destroy(server);
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_http_server_init_options_default (struct medusa_http_server_init_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_http_server_init_options));
        options->protocol = MEDUSA_HTTP_PROTOCOL_ANY;
        options->address = "0.0.0.0";
        options->port = 80;
        options->reuseaddr = 1;
        options->reuseport = 1;
        options->backlog = 128;
        options->threads = 1;
        return 0;
}

__attribute__ ((visibility ("default"))) struct medusa_http_server * medusa_http_server_create (struct medusa_monitor *monitor, unsigned int protocol, const char *address, unsigned short port)
{
        int rc;
        struct medusa_http_server_init_options options;
        rc = medusa_http_server_init_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.protocol = protocol;
        options.address = address;
        options.port = port;
        return medusa_http_server_create_with_options(monitor, &options);
}

__attribute__ ((visibility ("default"))) struct medusa_http_server * medusa_http_server_create_with_options (struct medusa_monitor *monitor, const struct medusa_http_server_init_options *options)
{
        int rc;
        unsigned int tcpsocket_protocol;
        struct medusa_http_server *server;
        struct medusa_http_server_init_options __options;
        const struct medusa_http_server_init_options *_options;
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                rc = medusa_http_server_init_options_default(&__options);
                if (rc < 0) {
                        return MEDUSA_ERR_PTR(rc);
                }
                _options = &__options;
        } else {
                _options = options;
        }
        server = malloc(sizeof(struct medusa_http_server));
        if (server == NULL) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(server, 0, sizeof(struct medusa_http_server));
        server->tcpsocket = medusa_tcpsocket_create(monitor, server_tcpsocket_onevent, server);
        if (MEDUSA_IS_ERR_OR_NULL(server->tcpsocket)) {
                medusa_http_server_destroy(server);
                return MEDUSA_ERR_PTR(MEDUSA_PTR_ERR(server->tcpsocket));
        }
        rc = medusa_tcpsocket_set_nonblocking(server->tcpsocket, 1);
        if (rc < 0) {
                medusa_http_server_destroy(server);
                return MEDUSA_ERR_PTR(rc);
        }
        rc = medusa_tcpsocket_set_reuseaddr(server->tcpsocket, _options->reuseaddr);
        if (rc < 0) {
                medusa_http_server_destroy(server);
                return MEDUSA_ERR_PTR(rc);
        }
        rc = medusa_tcpsocket_set_reuseport(server->tcpsocket, _options->reuseport);
        if (rc < 0) {
                medusa_http_server_destroy(server);
                return MEDUSA_ERR_PTR(rc);
        }
        rc = medusa_tcpsocket_set_backlog(server->tcpsocket, _options->backlog);
        if (rc < 0) {
                medusa_http_server_destroy(server);
                return MEDUSA_ERR_PTR(rc);
        }
        tcpsocket_protocol = MEDUSA_TCPSOCKET_PROTOCOL_ANY;
        if (_options->protocol == MEDUSA_HTTP_PROTOCOL_ANY) {
                tcpsocket_protocol = MEDUSA_TCPSOCKET_PROTOCOL_ANY;
        } else if (_options->protocol == MEDUSA_HTTP_PROTOCOL_IPV4) {
                tcpsocket_protocol = MEDUSA_TCPSOCKET_PROTOCOL_IPV4;
        } else if (_options->protocol == MEDUSA_HTTP_PROTOCOL_IPV6) {
                tcpsocket_protocol = MEDUSA_TCPSOCKET_PROTOCOL_IPV6;
        }
        rc = medusa_tcpsocket_bind(server->tcpsocket, tcpsocket_protocol, options->address, options->port);
        if (rc < 0) {
                medusa_http_server_destroy(server);
                return MEDUSA_ERR_PTR(rc);
        }
        return server;
}

__attribute__ ((visibility ("default"))) void medusa_http_server_destroy (struct medusa_http_server *server)
{
        if (MEDUSA_IS_ERR_OR_NULL(server)) {
                return;
        }
        if (!MEDUSA_IS_ERR_OR_NULL(server->tcpsocket)) {
                medusa_tcpsocket_destroy(server->tcpsocket);
        } else {
                free(server);
        }
}

__attribute__ ((visibility ("default"))) int medusa_http_server_set_enabled (struct medusa_http_server *server, int enabled)
{
        if (MEDUSA_IS_ERR_OR_NULL(server)) {
                return -EINVAL;
        }
        return medusa_tcpsocket_set_enabled(server->tcpsocket, enabled);
}

__attribute__ ((visibility ("default"))) int medusa_http_server_get_enabled (struct medusa_http_server *server)
{
        if (MEDUSA_IS_ERR_OR_NULL(server)) {
                return -EINVAL;
        }
        return medusa_tcpsocket_get_enabled(server->tcpsocket);
}

__attribute__ ((visibility ("default"))) int medusa_http_server_add_path (struct medusa_http_server *server, const char *path, const struct medusa_http_server_callback *callback, void *context)
{
        if (MEDUSA_IS_ERR_OR_NULL(server)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(callback)) {
                return medusa_http_server_del_path(server, path);
        }
        (void) path;
        (void) context;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_http_server_del_path (struct medusa_http_server *server, const char *path)
{
        if (MEDUSA_IS_ERR_OR_NULL(server)) {
                return -EINVAL;
        }
        (void) path;
        return 0;
}
