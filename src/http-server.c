
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "http_parser.h"

#include "error.h"
#include "buffer.h"
#include "queue.h"
#include "tcpsocket.h"
#include "http_parser.h"
#include "http.h"
#include "http-server.h"
#include "http-request.h"
#include "http-request-struct.h"
#include "http-response.h"
#include "http-response-struct.h"

TAILQ_HEAD(callbacks, callback);
struct callback {
        TAILQ_ENTRY(callback) list;
        char *path;
        struct medusa_http_server_callback callback;
        void *context;
};

struct client {
        http_parser http_parser;
        struct medusa_tcpsocket *tcpsocket;
        struct medusa_http_request *request;
        struct medusa_http_response *response;
        void *request_handle;
        void *response_handle;
        struct medusa_buffer *header_field;
        struct medusa_buffer *header_value;
        unsigned int status;
        struct medusa_http_server *server;
};

struct medusa_http_server {
        struct callbacks callbacks;
        struct medusa_tcpsocket *tcpsocket;
};

static int client_http_on_message_begin (http_parser *http_parser)
{
        int rc;
        struct client *client = http_parser->data;
        fprintf(stderr, "enter @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        fprintf(stderr, "  method: %d\n", http_parser->method);
        if (MEDUSA_IS_ERR_OR_NULL(client)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(client->request)) {
                return -EINVAL;
        }
        rc = medusa_http_request_reset(client->request);
        if (rc < 0) {
                return rc;
        }
        rc = medusa_http_response_reset(client->response);
        if (rc < 0) {
                return rc;
        }
        rc = medusa_http_request_set_method(client->request, http_method_str(http_parser->method));
        if (rc < 0) {
                return rc;
        }
        rc = medusa_http_request_set_version(client->request, http_parser->http_major, http_parser->http_minor);
        if (rc < 0) {
                return rc;
        }
        return 0;
}

static int client_http_on_url (http_parser *http_parser, const char *at, size_t length)
{
        int rc;
        struct http_parser_url url;
        struct client *client = http_parser->data;
        fprintf(stderr, "enter @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        fprintf(stderr, "  method: %d\n", http_parser->method);
        fprintf(stderr, "  url: %.*s\n", (int) length, at);
        if (MEDUSA_IS_ERR_OR_NULL(client)) {
                return -EINVAL;
        }
        rc = http_parser_parse_url(at, length, http_parser->method == HTTP_CONNECT, &url);
        if (rc != 0) {
                return -EIO;
        }
        if ((url.field_set & (1 << UF_PATH)) == 0) {
                return -EIO;
        }
        rc = medusa_http_request_set_method(client->request, http_method_str(http_parser->method));
        if (rc < 0) {
                return rc;
        }
        rc = medusa_http_request_set_url(client->request, "%.*s", url.field_data[UF_PATH].len, at + url.field_data[UF_PATH].off);
        if (rc < 0) {
                return rc;
        }
        rc = medusa_http_request_set_version(client->request, http_parser->http_major, http_parser->http_minor);
        if (rc < 0) {
                return rc;
        }
        return 0;
}

static int client_http_on_status (http_parser *http_parser, const char *at, size_t length)
{
        struct client *client = http_parser->data;
        (void) at;
        (void) length;
        fprintf(stderr, "enter @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        if (MEDUSA_IS_ERR_OR_NULL(client)) {
                return -EINVAL;
        }
        return 0;
}

static int client_http_on_header_field (http_parser *http_parser, const char *at, size_t length)
{
        int rc;
        struct client *client = http_parser->data;
        (void) at;
        (void) length;
        fprintf(stderr, "enter @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        if (MEDUSA_IS_ERR_OR_NULL(client)) {
                return -EINVAL;
        }
        if (medusa_buffer_length(client->header_field) > 0 &&
            medusa_buffer_length(client->header_value) > 0) {
                rc = medusa_http_request_add_header(client->request, medusa_buffer_base(client->header_field), medusa_buffer_base(client->header_value));
                if (rc < 0) {
                        return rc;
                }
                rc = medusa_buffer_set_length(client->header_field, 0);
                if (rc < 0) {
                        return rc;
                }
                rc = medusa_buffer_set_length(client->header_value, 0);
                if (rc < 0) {
                        return rc;
                }
        }
        rc = medusa_buffer_printf(client->header_field, "%.*s", (int) length, at);
        if (rc < 0) {
                return rc;
        }
        return 0;
}

static int client_http_on_header_value (http_parser *http_parser, const char *at, size_t length)
{
        int rc;
        struct client *client = http_parser->data;
        (void) at;
        (void) length;
        fprintf(stderr, "enter @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        if (MEDUSA_IS_ERR_OR_NULL(client)) {
                return -EINVAL;
        }
        if (medusa_buffer_length(client->header_field) <= 0) {
                return -EIO;
        }
        rc = medusa_buffer_printf(client->header_value, "%.*s", (int) length, at);
        if (rc < 0) {
                return rc;
        }
        return 0;
}

static int client_http_on_headers_complete (http_parser *http_parser)
{
        int rc;
        struct callback *callback;
        struct client *client = http_parser->data;
        fprintf(stderr, "enter @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        fprintf(stderr, "  method: %d\n", http_parser->method);
        if (MEDUSA_IS_ERR_OR_NULL(client)) {
                return -EINVAL;
        }
        rc = medusa_http_request_set_method(client->request, http_method_str(http_parser->method));
        if (rc < 0) {
                return rc;
        }
        rc = medusa_http_request_set_version(client->request, http_parser->http_major, http_parser->http_minor);
        if (rc < 0) {
                return rc;
        }
        if (medusa_buffer_length(client->header_field) > 0 &&
            medusa_buffer_length(client->header_value) > 0) {
                rc = medusa_http_request_add_header(client->request, medusa_buffer_base(client->header_field), medusa_buffer_base(client->header_value));
                if (rc < 0) {
                        return rc;
                }
                rc = medusa_buffer_set_length(client->header_field, 0);
                if (rc < 0) {
                        return rc;
                }
                rc = medusa_buffer_set_length(client->header_value, 0);
                if (rc < 0) {
                        return rc;
                }
        }
        TAILQ_FOREACH(callback, &client->server->callbacks, list) {
                if (callback->path != NULL &&
                    strcasecmp(callback->path, client->request->url) == 0) {
                        break;
                }
        }
        if (callback == NULL) {
                TAILQ_FOREACH(callback, &client->server->callbacks, list) {
                        if (callback->path == NULL) {
                                break;
                        }
                }
        }
        if (callback == NULL) {
                client->status = HTTP_STATUS_NOT_FOUND;
                return -ENOENT;
        }
        if (callback->callback.open != NULL) {
                client->request_handle = callback->callback.open(client->server, client->request, client->response, callback->context, callback->path);
                if (MEDUSA_IS_ERR_OR_NULL(client->request_handle)) {
                        client->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
                        return -EIO;
                }
        }
        return 0;
}

static int client_http_on_body (http_parser *http_parser, const char *at, size_t length)
{
        int rc;
        struct callback *callback;
        struct client *client = http_parser->data;
        fprintf(stderr, "enter @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        if (MEDUSA_IS_ERR_OR_NULL(client)) {
                return -EINVAL;
        }
        TAILQ_FOREACH(callback, &client->server->callbacks, list) {
                if (callback->path != NULL &&
                    strcasecmp(callback->path, client->request->url) == 0) {
                        break;
                }
        }
        if (callback == NULL) {
                TAILQ_FOREACH(callback, &client->server->callbacks, list) {
                        if (callback->path == NULL) {
                                break;
                        }
                }
        }
        if (callback == NULL) {
                client->status = HTTP_STATUS_NOT_FOUND;
                return -ENOENT;
        }
        if (callback->callback.write != NULL) {
                rc = callback->callback.write(client->server, client->request, client->response, callback->context, client->request_handle, at, length);
                if (rc < 0) {
                        return rc;
                } else if (rc != (int) length) {
                        return -EIO;
                }
        }
        return 0;
}

static int client_http_on_message_complete (http_parser *http_parser)
{
        int rc;
        struct callback *callback;
        struct client *client = http_parser->data;
        fprintf(stderr, "enter @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        if (MEDUSA_IS_ERR_OR_NULL(client)) {
                return -EINVAL;
        }
        TAILQ_FOREACH(callback, &client->server->callbacks, list) {
                if (callback->path != NULL &&
                    strcasecmp(callback->path, client->request->url) == 0) {
                        break;
                }
        }
        if (callback == NULL) {
                TAILQ_FOREACH(callback, &client->server->callbacks, list) {
                        if (callback->path == NULL) {
                                break;
                        }
                }
        }
        if (callback == NULL) {
                client->status = HTTP_STATUS_NOT_FOUND;
                return -ENOENT;
        }
        if (callback->callback.close != NULL) {
                rc = callback->callback.close(client->server, client->request, client->response, callback->context, client->request_handle);
                if (rc < 0) {
                        return rc;
                }
        }
        return 0;
}

static int client_http_on_chunk_header (http_parser *http_parser)
{
        struct client *client = http_parser->data;
        fprintf(stderr, "enter @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        if (MEDUSA_IS_ERR_OR_NULL(client)) {
                return -EINVAL;
        }
        return 0;
}

static int client_http_on_chunk_complete (http_parser *http_parser)
{
        struct client *client = http_parser->data;
        fprintf(stderr, "enter @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        if (MEDUSA_IS_ERR_OR_NULL(client)) {
                return -EINVAL;
        }
        return 0;
}

static int client_reply_http_status_not_found (struct client *client)
{
        int rc;
        struct medusa_http_response_header *response_header;
        if (MEDUSA_IS_ERR_OR_NULL(client)) {
                return -EINVAL;
        }
        rc = medusa_http_response_reset(client->response);
        if (rc < 0) {
                return rc;
        }
        rc = medusa_http_response_set_version(client->response, client->request->major, client->request->minor);
        if (rc < 0) {
                return rc;
        }
        rc = medusa_http_response_set_status(client->response, HTTP_STATUS_NOT_FOUND, http_status_str(HTTP_STATUS_NOT_FOUND));
        if (rc < 0) {
                return rc;
        }
        rc = medusa_http_response_add_header(client->response, "Connection", "close");
        if (rc < 0) {
                return rc;
        }
        rc = medusa_tcpsocket_printf(client->tcpsocket,
                        "HTTP/%d.%d %d %s\r\n",
                        client->response->major, client->response->minor,
                        client->response->code,
                        (client->response->reason) ? client->response->reason : "");
        if (rc < 0) {
                return rc;
        }
        TAILQ_FOREACH(response_header, &client->response->headers, list) {
                rc = medusa_tcpsocket_printf(client->tcpsocket, "%s: %s\r\n", response_header->key, response_header->value);
                if (rc < 0) {
                        return rc;
                }
        }
        rc = medusa_tcpsocket_printf(client->tcpsocket, "\r\n");
        if (rc < 0) {
                return rc;
        }
        rc = medusa_tcpsocket_printf(client->tcpsocket,
                        "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                        "<html><head>\n"
                        "<title>%d %s</title>\n"
                        "</head><body>\n"
                        "<h1>%s</h1>\n"
                        "<p>The requested URL %s was not found on this server.</p>\n"
                        "<hr>\n"
                        "</body></html>\n",
                        HTTP_STATUS_NOT_FOUND, http_status_str(HTTP_STATUS_NOT_FOUND),
                        http_status_str(HTTP_STATUS_NOT_FOUND),
                        client->request->url);
        if (rc < 0) {
                return rc;
        }
        return 0;
}

static int client_reply_http_status_interval_server_error (struct client *client)
{
        int rc;
        struct medusa_http_response_header *response_header;
        if (MEDUSA_IS_ERR_OR_NULL(client)) {
                return -EINVAL;
        }
        rc = medusa_http_response_reset(client->response);
        if (rc < 0) {
                return rc;
        }
        rc = medusa_http_response_set_version(client->response, client->request->major, client->request->minor);
        if (rc < 0) {
                return rc;
        }
        rc = medusa_http_response_set_status(client->response, HTTP_STATUS_INTERNAL_SERVER_ERROR, http_status_str(HTTP_STATUS_INTERNAL_SERVER_ERROR));
        if (rc < 0) {
                return rc;
        }
        rc = medusa_http_response_add_header(client->response, "Connection", "close");
        if (rc < 0) {
                return rc;
        }
        rc = medusa_tcpsocket_printf(client->tcpsocket,
                        "HTTP/%d.%d %d %s\r\n",
                        client->response->major, client->response->minor,
                        client->response->code,
                        (client->response->reason) ? client->response->reason : "");
        if (rc < 0) {
                return rc;
        }
        TAILQ_FOREACH(response_header, &client->response->headers, list) {
                rc = medusa_tcpsocket_printf(client->tcpsocket, "%s: %s\r\n", response_header->key, response_header->value);
                if (rc < 0) {
                        return rc;
                }
        }
        rc = medusa_tcpsocket_printf(client->tcpsocket, "\r\n");
        if (rc < 0) {
                return rc;
        }
        rc = medusa_tcpsocket_printf(client->tcpsocket,
                        "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                        "<html><head>\n"
                        "<title>%d %s</title>\n"
                        "</head><body>\n"
                        "<h1>%s</h1>\n"
                        "<p>Internal server error occured whilw processing the requested URL %s.</p>\n"
                        "<hr>\n"
                        "</body></html>\n",
                        HTTP_STATUS_INTERNAL_SERVER_ERROR, http_status_str(HTTP_STATUS_INTERNAL_SERVER_ERROR),
                        http_status_str(HTTP_STATUS_INTERNAL_SERVER_ERROR),
                        client->request->url);
        if (rc < 0) {
                return rc;
        }
        return 0;
}

static void client_destroy (struct client *client)
{
        if (MEDUSA_IS_ERR_OR_NULL(client)) {
                return;
        }
        if (!MEDUSA_IS_ERR_OR_NULL(client->tcpsocket)) {
                medusa_tcpsocket_destroy(client->tcpsocket);
        } else {
                if (client->request_handle != NULL &&
                    client->request->callback.close != NULL) {
                        client->request->callback.close(client->request, client->request->callback_context, client->request_handle);
                }
                if (client->request != NULL) {
                        medusa_http_request_destroy(client->request);
                }
                if (client->response != NULL) {
                        medusa_http_response_destroy(client->response);
                }
                if (client->header_field != NULL) {
                        medusa_buffer_destroy(client->header_field);
                }
                if (client->header_value != NULL) {
                        medusa_buffer_destroy(client->header_value);
                }
                free(client);
        }
}

static int client_tcpsocket_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context)
{
        int rc;

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
                char buffer[1024];
                int buffer_length = sizeof(buffer);
                while (1) {
                        recved = medusa_tcpsocket_read(tcpsocket, buffer, buffer_length);
                        if (recved < 0) {
                                return recved;
                        }
                        if (recved == 0) {
                                break;
                        }
                        client->status = 0;
                        client->http_parser.http_errno = 0;
                        parsed = http_parser_execute(&client->http_parser, &http_parser_settings, buffer, recved);
                        if (parsed != recved ||
                            client->status != 0 ||
                            client->http_parser.http_errno != 0) {
                                if (client->status == HTTP_STATUS_NOT_FOUND) {
                                        rc = client_reply_http_status_not_found(client);
                                        if (rc < 0) {
                                                return rc;
                                        }
                                } else if (client->status == HTTP_STATUS_INTERNAL_SERVER_ERROR) {
                                        rc = client_reply_http_status_interval_server_error(client);
                                        if (rc < 0) {
                                                return rc;
                                        }
                                } else {
                                        medusa_tcpsocket_destroy(tcpsocket);
                                }
                                break;
                        }
                }
        }

        if (events & MEDUSA_TCPSOCKET_EVENT_WRITTEN) {

        }

        if (events & MEDUSA_TCPSOCKET_EVENT_WRITE_FINISHED) {
                medusa_tcpsocket_destroy(tcpsocket);
        }

        if (events & MEDUSA_TCPSOCKET_EVENT_DISCONNECTED) {
                medusa_tcpsocket_destroy(tcpsocket);
        }

        if (events & MEDUSA_TCPSOCKET_EVENT_DESTROY) {
                client->tcpsocket = NULL;
                client_destroy(client);
        }

        return 0;
}

static void callback_destroy (struct callback *callback)
{
        if (callback == NULL) {
                return;
        }
        if (callback->path != NULL) {
                free(callback->path);
        }
        free(callback);
}

static struct callback * callback_create (const char *path, const struct medusa_http_server_callback *function, void *context)
{
        struct callback *callback;
        if (function == NULL) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        callback = malloc(sizeof(struct callback));
        if (callback == NULL) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(callback, 0, sizeof(struct callback));
        if (path != NULL) {
                callback->path = strdup(path);
                if (callback->path == NULL) {
                        callback_destroy(callback);
                        return MEDUSA_ERR_PTR(-ENOMEM);
                }
        }
        memcpy(&callback->callback, function, sizeof(struct medusa_http_server_callback));
        callback->context = context;
        return callback;
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
                client->header_field = medusa_buffer_create();
                if (MEDUSA_IS_ERR_OR_NULL(client->header_field)) {
                        client_destroy(client);
                        return MEDUSA_PTR_ERR(client->header_field);
                }
                client->header_value = medusa_buffer_create();
                if (MEDUSA_IS_ERR_OR_NULL(client->header_value)) {
                        client_destroy(client);
                        return MEDUSA_PTR_ERR(client->header_value);
                }
                client->request = medusa_http_request_create();
                if (MEDUSA_IS_ERR_OR_NULL(client->request)) {
                        client_destroy(client);
                        return MEDUSA_PTR_ERR(client->request);
                }
                client->response = medusa_http_response_create();
                if (MEDUSA_IS_ERR_OR_NULL(client->response)) {
                        client_destroy(client);
                        return MEDUSA_PTR_ERR(client->response);
                }
                client->tcpsocket = medusa_tcpsocket_accept(tcpsocket, client_tcpsocket_onevent, client);
                if (MEDUSA_IS_ERR_OR_NULL(client->tcpsocket)) {
                        client_destroy(client);
                        return MEDUSA_PTR_ERR(client->tcpsocket);
                }
                rc = medusa_tcpsocket_set_nonblocking(client->tcpsocket, 1);
                if (rc < 0) {
                        client_destroy(client);
                        return rc;
                }
                rc = medusa_tcpsocket_set_enabled(client->tcpsocket, 1);
                if (rc < 0) {
                        client_destroy(client);
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
        TAILQ_INIT(&server->callbacks);
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
                struct callback *callback;
                struct callback *ncallback;
                TAILQ_FOREACH_SAFE(callback, &server->callbacks, list, ncallback) {
                        TAILQ_REMOVE(&server->callbacks, callback, list);
                        callback_destroy(callback);
                }
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

__attribute__ ((visibility ("default"))) int medusa_http_server_add_path (struct medusa_http_server *server, const char *path, const struct medusa_http_server_callback *function, void *context)
{
        struct callback *callback;
        if (MEDUSA_IS_ERR_OR_NULL(server)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(function)) {
                return -EINVAL;
        }
        callback = callback_create(path, function, context);
        if (MEDUSA_IS_ERR_OR_NULL(callback)) {
                return MEDUSA_PTR_ERR(callback);
        }
        TAILQ_INSERT_TAIL(&server->callbacks, callback, list);
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_http_server_del_path (struct medusa_http_server *server, const char *path)
{
        struct callback *callback;
        struct callback *ncallback;
        if (MEDUSA_IS_ERR_OR_NULL(server)) {
                return -EINVAL;
        }
        TAILQ_FOREACH_SAFE(callback, &server->callbacks, list, ncallback) {
                if (path == NULL) {
                        if (callback->path == NULL) {
                                TAILQ_REMOVE(&server->callbacks, callback, list);
                                callback_destroy(callback);
                        }
                } else {
                        if (callback->path != NULL &&
                            strcasecmp(callback->path, path) == 0) {
                                TAILQ_REMOVE(&server->callbacks, callback, list);
                                callback_destroy(callback);
                        }
                }
        }
        return 0;
}
