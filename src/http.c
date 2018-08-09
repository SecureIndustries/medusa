
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "error.h"
#include "tcpsocket.h"
#include "http_parser.h"
#include "http.h"

struct medusa_http_responder {
        struct medusa_tcpsocket *tcpsocket;
};

static int responder_tcpsocket_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context)
{
        (void) tcpsocket;
        (void) events;
        (void) context;
        return 0;
}

int medusa_http_responder_init_options_default (struct medusa_http_responder_init_options *options)
{
        if (options == NULL) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_http_responder_init_options));
        options->protocol = MEDUSA_HTTP_PROTOCOL_ANY;
        options->address = "0.0.0.0";
        options->port = 80;
        options->reuseaddr = 1;
        options->reuseport = 1;
        options->backlog = 128;
        return 0;
}

struct medusa_http_responder * medusa_http_responder_create (struct medusa_monitor *monitor, unsigned int protocol, const char *address, unsigned short port)
{
        int rc;
        struct medusa_http_responder_init_options options;
        rc = medusa_http_responder_init_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.protocol = protocol;
        options.address = address;
        options.port = port;
        return medusa_http_responder_create_with_options(monitor, &options);
}

struct medusa_http_responder * medusa_http_responder_create_with_options (struct medusa_monitor *monitor, const struct medusa_http_responder_init_options *options)
{
        int rc;
        unsigned int tcpsocket_protocol;
        struct medusa_http_responder *responder;
        struct medusa_http_responder_init_options __options;
        const struct medusa_http_responder_init_options *_options;
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (options == NULL) {
                rc = medusa_http_responder_init_options_default(&__options);
                if (rc < 0) {
                        return MEDUSA_ERR_PTR(rc);
                }
                _options = &__options;
        } else {
                _options = options;
        }
        responder = malloc(sizeof(struct medusa_http_responder));
        if (responder == NULL) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(responder, 0, sizeof(struct medusa_http_responder));
        responder->tcpsocket = medusa_tcpsocket_create(monitor, responder_tcpsocket_onevent, responder);
        if (MEDUSA_IS_ERR_OR_NULL(responder->tcpsocket)) {
                return MEDUSA_ERR_PTR(MEDUSA_PTR_ERR(responder->tcpsocket));
        }
        rc = medusa_tcpsocket_set_nonblocking(responder->tcpsocket, 1);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        rc = medusa_tcpsocket_set_reuseaddr(responder->tcpsocket, _options->reuseaddr);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        rc = medusa_tcpsocket_set_reuseport(responder->tcpsocket, _options->reuseport);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        rc = medusa_tcpsocket_set_backlog(responder->tcpsocket, _options->backlog);
        if (rc < 0) {
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
        rc = medusa_tcpsocket_bind(responder->tcpsocket, tcpsocket_protocol, options->address, options->port);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        return responder;
}

void medusa_http_responder_destroy (struct medusa_http_responder *responder)
{
        if (MEDUSA_IS_ERR_OR_NULL(responder)) {
                return;
        }
        free(responder);
}

int medusa_http_responder_set_enabled (struct medusa_http_responder *responder, int enabled)
{
        if (MEDUSA_IS_ERR_OR_NULL(responder)) {
                return -EINVAL;
        }
        return medusa_tcpsocket_set_enabled(responder->tcpsocket, enabled);
}

int medusa_http_responder_get_enabled (struct medusa_http_responder *responder)
{
        if (MEDUSA_IS_ERR_OR_NULL(responder)) {
                return -EINVAL;
        }
        return medusa_tcpsocket_get_enabled(responder->tcpsocket);
}

int medusa_http_responder_add_callback (struct medusa_http_responder *responder, const char *path, const struct medusa_http_responder_callback *callback)
{
        if (MEDUSA_IS_ERR_OR_NULL(responder)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(callback)) {
                return medusa_http_responder_del_callback(responder, path);
        }
        (void) path;
        return 0;
}

int medusa_http_responder_del_callback (struct medusa_http_responder *responder, const char *path)
{
        if (MEDUSA_IS_ERR_OR_NULL(responder)) {
                return -EINVAL;
        }
        (void) path;
        return 0;
}
