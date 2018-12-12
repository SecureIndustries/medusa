
#if !defined(MEDUSA_HTTP_REQUEST_STRUCT_H)
#define MEDUSA_HTTP_REQUEST_STRUCT_H

struct medusa_http_request {
        struct medusa_subject subject;
        unsigned int state;
        int (*onevent) (struct medusa_http_request *http_request, unsigned int events, void *context, ...);
        void *context;
};

int medusa_http_request_init (struct medusa_http_request *http_request, struct medusa_monitor *monitor, int (*onevent) (struct medusa_http_request *http_request, unsigned int events, void *context, ...), void *context);
int medusa_http_request_init_with_options (struct medusa_http_request *http_request, const struct medusa_http_request_init_options *options);
void medusa_http_request_uninit (struct medusa_http_request *http_request);

#endif
