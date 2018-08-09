
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "error.h"
#include "tcpsocket.h"
#include "http_parser.h"
#include "http.h"

struct callback {
        char *path;
        struct medusa_http_server_callback callback;
        void *context;
};

struct medusa_http_server {
        struct medusa_tcpsocket *tcpsocket;
};

static int server_tcpsocket_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context)
{
        struct medusa_http_server *server = context;
        (void) tcpsocket;
        if (events & MEDUSA_TCPSOCKET_EVENT_DESTROY) {
                server->tcpsocket = NULL;
                medusa_http_server_destroy(server);
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_http_server_init_options_default (struct medusa_http_server_init_options *options)
{
        if (options == NULL) {
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
        if (options == NULL) {
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
