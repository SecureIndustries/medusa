
#if !defined(MEDUSA_HTTP_REQUEST_H)
#define MEDUSA_HTTP_REQUEST_H

struct medusa_http_stat;
struct medusa_http_request;

struct medusa_http_request_callback {
        int (*stat) (struct medusa_http_request *server, void *cookie, const char *path, struct medusa_http_stat *stat);
        void * (*open) (struct medusa_http_request *server, void *cookie, const char *path, unsigned int mode);
        int (*read) (struct medusa_http_request *server, void *cookie, void *handle, void *buffer, int length);
        int (*close) (struct medusa_http_request *server, void *cookie, void *handle);
};

struct medusa_http_request * medusa_http_request_create (void);
void medusa_http_request_destroy (struct medusa_http_request *request);

int medusa_http_request_set_method (struct medusa_http_request *request, const char *method);
int medusa_http_request_set_url (struct medusa_http_request *request, const char *url);
int medusa_http_request_set_version (struct medusa_http_request *request, int major, int minor);
int medusa_http_request_add_header (struct medusa_http_request *request, const char *key, const char *value, ...);
int medusa_http_request_del_header (struct medusa_http_request *request, const char *key);
int medusa_http_request_set_callback (struct medusa_http_request *request, const struct medusa_http_request_callback *callback, void *context);

#endif
