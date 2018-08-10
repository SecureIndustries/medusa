
#if !defined(MEDUSA_HTTP_REQUEST_STRUCT_H)
#define MEDUSA_HTTP_REQUEST_STRUCT_H

TAILQ_HEAD(headers, header);
struct header {
        TAILQ_ENTRY(header) list;
        char *key;
        char *value;
};

struct medusa_http_request {
        char *method;
        char *url;
        int major;
        int minor;
        struct headers headers;
        struct medusa_http_request_callback callback;
        void *context;
};

#endif
