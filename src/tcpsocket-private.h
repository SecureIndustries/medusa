
#if !defined(MEDUSA_TCPSOCKET_PRIVATE_H)
#define MEDUSA_TCPSOCKET_PRIVATE_H

struct medusa_tcpsocket;

int medusa_tcpsocket_init_unlocked (struct medusa_tcpsocket *tcpsocket, struct medusa_monitor *monitor, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...), void *context);
int medusa_tcpsocket_init_with_options_unlocked (struct medusa_tcpsocket *tcpsocket, const struct medusa_tcpsocket_init_options *options);

struct medusa_tcpsocket * medusa_tcpsocket_create_unlocked (struct medusa_monitor *monitor, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...), void *context);
struct medusa_tcpsocket * medusa_tcpsocket_create_with_options_unlocked (const struct medusa_tcpsocket_init_options *options);

int medusa_tcpsocket_accept_init_unlocked (struct medusa_tcpsocket *accepted, struct medusa_tcpsocket *tcpsocket, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...), void *context);
int medusa_tcpsocket_accept_init_with_options_unlocked (struct medusa_tcpsocket *accepted, const struct medusa_tcpsocket_accept_options *options);

struct medusa_tcpsocket * medusa_tcpsocket_accept_unlocked (struct medusa_tcpsocket *tcpsocket, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...), void *context);
struct medusa_tcpsocket * medusa_tcpsocket_accept_with_options_unlocked (const struct medusa_tcpsocket_accept_options *options);

void medusa_tcpsocket_uninit_unlocked (struct medusa_tcpsocket *tcpsocket);
void medusa_tcpsocket_destroy_unlocked (struct medusa_tcpsocket *tcpsocket);

unsigned int medusa_tcpsocket_get_state_unlocked (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_set_enabled_unlocked (struct medusa_tcpsocket *tcpsocket, int enabled);
int medusa_tcpsocket_get_enabled_unlocked (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_set_nonblocking_unlocked (struct medusa_tcpsocket *tcpsocket, int enabled);
int medusa_tcpsocket_get_nonblocking_unlocked (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_set_reuseaddr_unlocked (struct medusa_tcpsocket *tcpsocket, int enabled);
int medusa_tcpsocket_get_reuseaddr_unlocked (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_set_reuseport_unlocked (struct medusa_tcpsocket *tcpsocket, int enabled);
int medusa_tcpsocket_get_reuseport_unlocked (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_set_backlog_unlocked (struct medusa_tcpsocket *tcpsocket, int backlog);
int medusa_tcpsocket_get_backlog_unlocked (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_get_fd_unlocked (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_bind_unlocked (struct medusa_tcpsocket *tcpsocket, unsigned int protocol, const char *address, unsigned short port);
int medusa_tcpsocket_connect_unlocked (struct medusa_tcpsocket *tcpsocket, unsigned int protocol, const char *address, unsigned short port);

int medusa_tcpsocket_read_unlocked (struct medusa_tcpsocket *tcpsocket, void *data, int64_t size);
int64_t medusa_tcpsocket_get_read_length_unlocked (const struct medusa_tcpsocket *tcpsocket);
int medusa_tcpsocket_set_read_buffer_unlocked (struct medusa_tcpsocket *tcpsocket, struct medusa_buffer *buffer);
struct medusa_buffer * medusa_tcpsocket_get_read_buffer_unlocked (struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_write_unlocked (struct medusa_tcpsocket *tcpsocket, const void *data, int64_t size);
int medusa_tcpsocket_writev_unlocked (struct medusa_tcpsocket *tcpsocket, const struct iovec *iovecs, int niovecs);
int medusa_tcpsocket_printf_unlocked (struct medusa_tcpsocket *tcpsocket, const char *format, ...);
int medusa_tcpsocket_vprintf_unlocked (struct medusa_tcpsocket *tcpsocket, const char *format, va_list va);
int64_t medusa_tcpsocket_get_write_length_unlocked (const struct medusa_tcpsocket *tcpsocket);
int medusa_tcpsocket_set_write_buffer_unlocked (struct medusa_tcpsocket *tcpsocket, struct medusa_buffer *buffer);
struct medusa_buffer * medusa_tcpsocket_get_write_buffer_unlocked (struct medusa_tcpsocket *tcpsocket);

struct medusa_monitor * medusa_tcpsocket_get_monitor_unlocked (struct medusa_tcpsocket *tcpsocket);
int medusa_tcpsocket_onevent_unlocked (struct medusa_tcpsocket *tcpsocket, unsigned int events);

#endif
