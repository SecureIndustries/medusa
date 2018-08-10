
#if !defined(MEDUSA_HTTP_SERVER_H)
#define MEDUSA_HTTP_SERVER_H

struct medusa_monitor;
struct medusa_http_stat;
struct medusa_http_request;
struct medusa_http_server;

struct medusa_http_server_init_options {
        unsigned int protocol;
        const char *address;
        unsigned short port;
        int reuseaddr;
        int reuseport;
        int backlog;
        int threads;
};

struct medusa_http_server_callback {
        int (*stat) (struct medusa_http_server *server, struct medusa_http_request *request, void *context, const char *path, struct medusa_http_stat *stat);
        void * (*open) (struct medusa_http_server *server, struct medusa_http_request *request, void *context, const char *path, unsigned int mode);
        int (*read) (struct medusa_http_server *server, struct medusa_http_request *request, void *context, void *handle, void *buffer, int length);
        int (*write) (struct medusa_http_server *server, struct medusa_http_request *request, void *context, void *handle, const void *buffer, int length);
        long long (*seek) (struct medusa_http_server *server, struct medusa_http_request *request, void *context, void *handle, long long offset, unsigned int whence);
        int (*close) (struct medusa_http_server *server, struct medusa_http_request *request, void *context, void *handle);
};

int medusa_http_server_init_options_default (struct medusa_http_server_init_options *options);

struct medusa_http_server * medusa_http_server_create (struct medusa_monitor *monitor, unsigned int protocol, const char *address, unsigned short port);
struct medusa_http_server * medusa_http_server_create_with_options (struct medusa_monitor *monitor, const struct medusa_http_server_init_options *options);
void medusa_http_server_destroy (struct medusa_http_server *server);

int medusa_http_server_set_enabled (struct medusa_http_server *server, int enabled);
int medusa_http_server_get_enabled (struct medusa_http_server *server);

int medusa_http_server_add_path (struct medusa_http_server *server, const char *path, const struct medusa_http_server_callback *callback, void *context);
int medusa_http_server_del_path (struct medusa_http_server *server, const char *path);

#endif
