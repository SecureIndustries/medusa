
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "http_parser.h"

#include "error.h"
#include "queue.h"
#include "tcpsocket.h"
#include "http_parser.h"
#include "http.h"
#include "http-client.h"
#include "http-request.h"
#include "http-request-struct.h"
#include "http-request-private.h"

struct medusa_http_client {
        http_parser http_parser;
        struct medusa_http_requests requests;
        struct medusa_http_request *active;
        struct medusa_tcpsocket *tcpsocket;
};

static int client_http_on_message_begin (http_parser *http_parser)
{
        struct client *client = http_parser->data;
        (void) client;
        fprintf(stderr, "enter @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        fprintf(stderr, "  method: %d\n", http_parser->method);
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
        struct medusa_http_client *client = context;

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

        if (events & MEDUSA_TCPSOCKET_EVENT_CONNECTED) {

        }

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
                medusa_http_client_destroy(client);
        }

        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_http_client_init_options_default (struct medusa_http_client_init_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_http_client_init_options));
        options->protocol = MEDUSA_HTTP_PROTOCOL_ANY;
        options->address = "0.0.0.0";
        options->port = 80;
        return 0;
}

__attribute__ ((visibility ("default"))) struct medusa_http_client * medusa_http_client_create (struct medusa_monitor *monitor, unsigned int protocol, const char *address, unsigned short port)
{
        int rc;
        struct medusa_http_client_init_options options;
        rc = medusa_http_client_init_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.protocol = protocol;
        options.address = address;
        options.port = port;
        return medusa_http_client_create_with_options(monitor, &options);
}

__attribute__ ((visibility ("default"))) struct medusa_http_client * medusa_http_client_create_with_options (struct medusa_monitor *monitor, const struct medusa_http_client_init_options *options)
{
        int rc;
        unsigned int tcpsocket_protocol;
        struct medusa_http_client *client;
        struct medusa_http_client_init_options __options;
        const struct medusa_http_client_init_options *_options;
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                rc = medusa_http_client_init_options_default(&__options);
                if (rc < 0) {
                        return MEDUSA_ERR_PTR(rc);
                }
                _options = &__options;
        } else {
                _options = options;
        }
        client = malloc(sizeof(struct medusa_http_client));
        if (client == NULL) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(client, 0, sizeof(struct medusa_http_client));
        TAILQ_INIT(&client->requests);
        http_parser_init(&client->http_parser, HTTP_RESPONSE);
        client->tcpsocket = medusa_tcpsocket_create(monitor, client_tcpsocket_onevent, client);
        if (MEDUSA_IS_ERR_OR_NULL(client->tcpsocket)) {
                medusa_http_client_destroy(client);
                return MEDUSA_ERR_PTR(MEDUSA_PTR_ERR(client->tcpsocket));
        }
        rc = medusa_tcpsocket_set_nonblocking(client->tcpsocket, 1);
        if (rc < 0) {
                medusa_http_client_destroy(client);
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
        rc = medusa_tcpsocket_connect(client->tcpsocket, tcpsocket_protocol, options->address, options->port);
        if (rc < 0) {
                medusa_http_client_destroy(client);
                return MEDUSA_ERR_PTR(rc);
        }
        return client;
}

__attribute__ ((visibility ("default"))) void medusa_http_client_destroy (struct medusa_http_client *client)
{
        if (MEDUSA_IS_ERR_OR_NULL(client)) {
                return;
        }
        if (!MEDUSA_IS_ERR_OR_NULL(client->tcpsocket)) {
                medusa_tcpsocket_destroy(client->tcpsocket);
        } else {
                struct medusa_http_request *request;
                struct medusa_http_request *nrequest;
                TAILQ_FOREACH_SAFE(request, &client->requests, list, nrequest) {
                        TAILQ_REMOVE(&client->requests, request, list);
                        medusa_http_request_destroy(request);
                }
                free(client);
        }
}

__attribute__ ((visibility ("default"))) int medusa_http_client_set_enabled (struct medusa_http_client *client, int enabled)
{
        if (MEDUSA_IS_ERR_OR_NULL(client)) {
                return -EINVAL;
        }
        return medusa_tcpsocket_set_enabled(client->tcpsocket, enabled);
}

__attribute__ ((visibility ("default"))) int medusa_http_client_get_enabled (struct medusa_http_client *client)
{
        if (MEDUSA_IS_ERR_OR_NULL(client)) {
                return -EINVAL;
        }
        return medusa_tcpsocket_get_enabled(client->tcpsocket);
}

__attribute__ ((visibility ("default"))) int medusa_http_client_add_request (struct medusa_http_client *client, struct medusa_http_request *request, int (*onevent) (struct medusa_http_client *client, struct medusa_http_request *request, unsigned int events, void *context), void *context)
{
        if (MEDUSA_IS_ERR_OR_NULL(client)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return -EINVAL;
        }
        if (!medusa_http_request_is_valid(request)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(onevent)) {
                return -EINVAL;
        }
        TAILQ_INSERT_TAIL(&client->requests, request, list);
        request->onevent = onevent;
        request->onevent_context = context;
        return 0;
}
