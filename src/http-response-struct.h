
#if !defined(MEDUSA_HTTP_RESPONSE_STRUCT_H)
#define MEDUSA_HTTP_RESPONSE_STRUCT_H

struct medusa_http_client;

TAILQ_HEAD(medusa_http_response_headers, medusa_http_response_header);
struct medusa_http_response_header {
        TAILQ_ENTRY(medusa_http_response_header) list;
        char *key;
        char *value;
};

TAILQ_HEAD(medusa_http_responses, medusa_http_response);
struct medusa_http_response {
        TAILQ_ENTRY(medusa_http_response) list;
        int code;
        char *reason;
        int major;
        int minor;
        struct medusa_http_response_headers headers;
        struct medusa_http_response_callback callback;
        void *callback_context;
        int (*onevent) (struct medusa_http_client *client, struct medusa_http_response *response, unsigned int events, void *context);
        void *onevent_context;
};

#endif
