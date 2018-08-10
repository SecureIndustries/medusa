
#if !defined(MEDUSA_HTTP_REQUEST_STRUCT_H)
#define MEDUSA_HTTP_REQUEST_STRUCT_H

struct medusa_http_client;

TAILQ_HEAD(headers, header);
struct header {
        TAILQ_ENTRY(header) list;
        char *key;
        char *value;
};

TAILQ_HEAD(medusa_http_requests, medusa_http_request);
struct medusa_http_request {
        TAILQ_ENTRY(medusa_http_request) list;
        char *method;
        char *url;
        int major;
        int minor;
        struct headers headers;
        struct medusa_http_request_callback callback;
        void *callback_context;
        int (*onevent) (struct medusa_http_client *client, struct medusa_http_request *request, unsigned int events, void *context);
        void *onevent_context;
};

#endif
