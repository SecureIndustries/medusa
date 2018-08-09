
#if !defined(MEDUSA_HTTP_H)
#define MEDUSA_HTTP_H

enum {
        MEDUSA_HTTP_PROTOCOL_ANY           = 0,
        MEDUSA_HTTP_PROTOCOL_IPV4          = 1,
        MEDUSA_HTTP_PROTOCOL_IPV6          = 2
#define MEDUSA_HTTP_PROTOCOL_ANY           MEDUSA_HTTP_PROTOCOL_ANY
#define MEDUSA_HTTP_PROTOCOL_IPV4          MEDUSA_HTTP_PROTOCOL_IPV4
#define MEDUSA_HTTP_PROTOCOL_IPV6          MEDUSA_HTTP_PROTOCOL_IPV6
};

struct medusa_http_responder;

struct medusa_http_responder_init_options {
        unsigned int protocol;
        const char *address;
        unsigned short port;
        int reuseaddr;
        int reuseport;
        int backlog;
};

struct medusa_http_responder_callback {

};

int medusa_http_responder_init_options_default (struct medusa_http_responder_init_options *options);

struct medusa_http_responder * medusa_http_responder_create (struct medusa_monitor *monitor, unsigned int protocol, const char *address, unsigned short port);
struct medusa_http_responder * medusa_http_responder_create_with_options (struct medusa_monitor *monitor, const struct medusa_http_responder_init_options *options);
void medusa_http_responder_destroy (struct medusa_http_responder *responder);

int medusa_http_responder_set_enabled (struct medusa_http_responder *responder, int enabled);
int medusa_http_responder_get_enabled (struct medusa_http_responder *responder);

int medusa_http_responder_add_callback (struct medusa_http_responder *responder, const char *path, const struct medusa_http_responder_callback *callback);
int medusa_http_responder_del_callback (struct medusa_http_responder *responder, const char *path);

#endif
