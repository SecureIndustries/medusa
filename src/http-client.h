
#if !defined(MEDUSA_HTTP_CLIENT_H)
#define MEDUSA_HTTP_CLIENT_H

struct medusa_monitor;
struct medusa_http_request;
struct medusa_http_client;

struct medusa_http_client_init_options {
        unsigned int protocol;
        const char *address;
        unsigned short port;
};

int medusa_http_client_init_options_default (struct medusa_http_client_init_options *options);

struct medusa_http_client * medusa_http_client_create (struct medusa_monitor *monitor, unsigned int protocol, const char *address, unsigned short port);
struct medusa_http_client * medusa_http_client_create_with_options (struct medusa_monitor *monitor, const struct medusa_http_client_init_options *options);
void medusa_http_client_destroy (struct medusa_http_client *client);

int medusa_http_client_set_enabled (struct medusa_http_client *client, int enabled);
int medusa_http_client_get_enabled (struct medusa_http_client *client);

int medusa_http_client_add_request (struct medusa_http_client *client, struct medusa_http_request *request, int (*onevent) (struct medusa_http_client *client, struct medusa_http_request *request, unsigned int events, void *context), void *context);

#endif
