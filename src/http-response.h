
#if !defined(MEDUSA_HTTP_RESPONSE_H)
#define MEDUSA_HTTP_RESPONSE_H

struct medusa_http_stat;
struct medusa_http_response;

struct medusa_http_response_callback {
        int (*stat) (struct medusa_http_response *server, void *cookie, const char *path, struct medusa_http_stat *stat);
        void * (*open) (struct medusa_http_response *server, void *cookie, const char *path, unsigned int mode);
        int (*read) (struct medusa_http_response *server, void *cookie, void *handle, void *buffer, int length);
        int (*close) (struct medusa_http_response *server, void *cookie, void *handle);
};

struct medusa_http_response * medusa_http_response_create (void);
void medusa_http_response_destroy (struct medusa_http_response *response);

int medusa_http_response_reset (struct medusa_http_response *response);

int medusa_http_response_set_status (struct medusa_http_response *response, int code, const char *reason, ...)  __attribute__((format(printf, 3, 4)));
int medusa_http_response_get_status_code (const struct medusa_http_response *response);
const char * medusa_http_response_get_status_reason (const struct medusa_http_response *response);

int medusa_http_response_set_version (struct medusa_http_response *response, int major, int minor);
int medusa_http_response_get_version_major (const struct medusa_http_response *response);
int medusa_http_response_get_version_minor (const struct medusa_http_response *response);

int medusa_http_response_add_header (struct medusa_http_response *response, const char *key, const char *value, ...)  __attribute__((format(printf, 3, 4)));
int medusa_http_response_del_header (struct medusa_http_response *response, const char *key);
const char * medusa_http_response_get_header_value (const struct medusa_http_response *response, const char *key);

int medusa_http_response_set_callback (struct medusa_http_response *response, const struct medusa_http_response_callback *callback, void *context);

#endif
