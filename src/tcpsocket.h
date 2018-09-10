
#if !defined(MEDUSA_TCPSOCKET_H)
#define MEDUSA_TCPSOCKET_H

struct medusa_buffer;
struct medusa_monitor;
struct medusa_tcpsocket;

enum {
        MEDUSA_TCPSOCKET_PROTOCOL_ANY           = 0,
        MEDUSA_TCPSOCKET_PROTOCOL_IPV4          = 1,
        MEDUSA_TCPSOCKET_PROTOCOL_IPV6          = 2
#define MEDUSA_TCPSOCKET_PROTOCOL_ANY           MEDUSA_TCPSOCKET_PROTOCOL_ANY
#define MEDUSA_TCPSOCKET_PROTOCOL_IPV4          MEDUSA_TCPSOCKET_PROTOCOL_IPV4
#define MEDUSA_TCPSOCKET_PROTOCOL_IPV6          MEDUSA_TCPSOCKET_PROTOCOL_IPV6
};

enum {
        MEDUSA_TCPSOCKET_EVENT_BINDING          = 0x00000001,
        MEDUSA_TCPSOCKET_EVENT_BOUND            = 0x00000002,
        MEDUSA_TCPSOCKET_EVENT_LISTENING        = 0x00000004,
        MEDUSA_TCPSOCKET_EVENT_CONNECTION       = 0x00000008,
        MEDUSA_TCPSOCKET_EVENT_RESOLVING        = 0x00000010,
        MEDUSA_TCPSOCKET_EVENT_RESOLVE_TIMEOUT  = 0x00000020,
        MEDUSA_TCPSOCKET_EVENT_RESOLVED         = 0x00000040,
        MEDUSA_TCPSOCKET_EVENT_CONNECTING       = 0x00000080,
        MEDUSA_TCPSOCKET_EVENT_CONNECT_TIMEOUT  = 0x00000100,
        MEDUSA_TCPSOCKET_EVENT_CONNECTED        = 0x00000200,
        MEDUSA_TCPSOCKET_EVENT_WRITE_TIMEOUT    = 0x00000400,
        MEDUSA_TCPSOCKET_EVENT_WRITTEN          = 0x00000800,
        MEDUSA_TCPSOCKET_EVENT_WRITE_FINISHED   = 0x00001000,
        MEDUSA_TCPSOCKET_EVENT_READ             = 0x00002000,
        MEDUSA_TCPSOCKET_EVENT_READ_TIMEOUT     = 0x00004000,
        MEDUSA_TCPSOCKET_EVENT_DISCONNECTED     = 0x00008000,
        MEDUSA_TCPSOCKET_EVENT_DESTROY          = 0x00010000
#define MEDUSA_TCPSOCKET_EVENT_BINDING          MEDUSA_TCPSOCKET_EVENT_BINDING
#define MEDUSA_TCPSOCKET_EVENT_BOUND            MEDUSA_TCPSOCKET_EVENT_BOUND
#define MEDUSA_TCPSOCKET_EVENT_LISTENING        MEDUSA_TCPSOCKET_EVENT_LISTENING
#define MEDUSA_TCPSOCKET_EVENT_CONNECTION       MEDUSA_TCPSOCKET_EVENT_CONNECTION
#define MEDUSA_TCPSOCKET_EVENT_RESOLVING        MEDUSA_TCPSOCKET_EVENT_RESOLVING
#define MEDUSA_TCPSOCKET_EVENT_RESOLVE_TIMEOUT  MEDUSA_TCPSOCKET_EVENT_RESOLVE_TIMEOUT
#define MEDUSA_TCPSOCKET_EVENT_RESOLVED         MEDUSA_TCPSOCKET_EVENT_RESOLVED
#define MEDUSA_TCPSOCKET_EVENT_CONNECTING       MEDUSA_TCPSOCKET_EVENT_CONNECTING
#define MEDUSA_TCPSOCKET_EVENT_CONNECT_TIMEOUT  MEDUSA_TCPSOCKET_EVENT_CONNECT_TIMEOUT
#define MEDUSA_TCPSOCKET_EVENT_CONNECTED        MEDUSA_TCPSOCKET_EVENT_CONNECTED
#define MEDUSA_TCPSOCKET_EVENT_WRITE_TIMEOUT    MEDUSA_TCPSOCKET_EVENT_WRITE_TIMEOUT
#define MEDUSA_TCPSOCKET_EVENT_WRITE_FINISHED   MEDUSA_TCPSOCKET_EVENT_WRITE_FINISHED
#define MEDUSA_TCPSOCKET_EVENT_WRITTEN          MEDUSA_TCPSOCKET_EVENT_WRITTEN
#define MEDUSA_TCPSOCKET_EVENT_READ             MEDUSA_TCPSOCKET_EVENT_READ
#define MEDUSA_TCPSOCKET_EVENT_READ_TIMEOUT     MEDUSA_TCPSOCKET_EVENT_READ_TIMEOUT
#define MEDUSA_TCPSOCKET_EVENT_DISCONNECTED     MEDUSA_TCPSOCKET_EVENT_DISCONNECTED
#define MEDUSA_TCPSOCKET_EVENT_DESTROY          MEDUSA_TCPSOCKET_EVENT_DESTROY
};

enum {
        MEDUSA_TCPSOCKET_STATE_UNKNWON          = 0,
        MEDUSA_TCPSOCKET_STATE_DISCONNECTED     = 1,
        MEDUSA_TCPSOCKET_STATE_BINDING          = 2,
        MEDUSA_TCPSOCKET_STATE_BOUND            = 3,
        MEDUSA_TCPSOCKET_STATE_LISTENING        = 4,
        MEDUSA_TCPSOCKET_STATE_RESOLVING        = 5,
        MEDUSA_TCPSOCKET_STATE_RESOLVED         = 6,
        MEDUSA_TCPSOCKET_STATE_CONNECTING       = 7,
        MEDUSA_TCPSOCKET_STATE_CONNECTED        = 8
#define MEDUSA_TCPSOCKET_STATE_UNKNWON          MEDUSA_TCPSOCKET_STATE_UNKNWON
#define MEDUSA_TCPSOCKET_STATE_BINDING          MEDUSA_TCPSOCKET_STATE_BINDING
#define MEDUSA_TCPSOCKET_STATE_BOUND            MEDUSA_TCPSOCKET_STATE_BOUND
#define MEDUSA_TCPSOCKET_STATE_LISTENING        MEDUSA_TCPSOCKET_STATE_LISTENING
#define MEDUSA_TCPSOCKET_STATE_DISCONNECTED     MEDUSA_TCPSOCKET_STATE_DISCONNECTED
#define MEDUSA_TCPSOCKET_STATE_RESOLVING        MEDUSA_TCPSOCKET_STATE_RESOLVING
#define MEDUSA_TCPSOCKET_STATE_RESOLVED         MEDUSA_TCPSOCKET_STATE_RESOLVED
#define MEDUSA_TCPSOCKET_STATE_CONNECTING       MEDUSA_TCPSOCKET_STATE_CONNECTING
#define MEDUSA_TCPSOCKET_STATE_CONNECTED        MEDUSA_TCPSOCKET_STATE_CONNECTED
};

struct medusa_tcpsocket_init_options {
        struct medusa_monitor *monitor;
        int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...);
        void *context;
        int nonblocking;
        int reuseaddr;
        int reuseport;
        int backlog;
        int enabled;
};

struct medusa_tcpsocket_accept_options {
        struct medusa_tcpsocket *tcpsocket;
        struct medusa_monitor *monitor;
        int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...);
        void *context;
        int nonblocking;
        int enabled;
};

int medusa_tcpsocket_init_options_default (struct medusa_tcpsocket_init_options *options);

struct medusa_tcpsocket * medusa_tcpsocket_create (struct medusa_monitor *monitor, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...), void *context);
struct medusa_tcpsocket * medusa_tcpsocket_create_with_options (const struct medusa_tcpsocket_init_options *options);
void medusa_tcpsocket_destroy (struct medusa_tcpsocket *tcpsocket);

unsigned int medusa_tcpsocket_get_state (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_set_enabled (struct medusa_tcpsocket *tcpsocket, int enabled);
int medusa_tcpsocket_get_enabled (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_set_nonblocking (struct medusa_tcpsocket *tcpsocket, int enabled);
int medusa_tcpsocket_get_nonblocking (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_set_reuseaddr (struct medusa_tcpsocket *tcpsocket, int enabled);
int medusa_tcpsocket_get_reuseaddr (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_set_reuseport (struct medusa_tcpsocket *tcpsocket, int enabled);
int medusa_tcpsocket_get_reuseport (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_set_backlog (struct medusa_tcpsocket *tcpsocket, int backlog);
int medusa_tcpsocket_get_backlog (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_get_fd (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_bind (struct medusa_tcpsocket *tcpsocket, unsigned int protocol, const char *address, unsigned short port);
int medusa_tcpsocket_connect (struct medusa_tcpsocket *tcpsocket, unsigned int protocol, const char *address, unsigned short port);

int medusa_tcpsocket_accept_options_default (struct medusa_tcpsocket_accept_options *options);

struct medusa_tcpsocket * medusa_tcpsocket_accept (struct medusa_tcpsocket *tcpsocket, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...), void *context);
struct medusa_tcpsocket * medusa_tcpsocket_accept_with_options (const struct medusa_tcpsocket_accept_options *options);

int medusa_tcpsocket_read (struct medusa_tcpsocket *tcpsocket, void *data, int64_t size);
struct medusa_buffer * medusa_tcpsocket_get_read_buffer (struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_write (struct medusa_tcpsocket *tcpsocket, const void *data, int64_t size);
int medusa_tcpsocket_printf (struct medusa_tcpsocket *tcpsocket, const char *format, ...) __attribute__((format(printf, 2, 3)));
int medusa_tcpsocket_vprintf (struct medusa_tcpsocket *tcpsocket, const char *format, va_list va);

int medusa_tcpsocket_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events);
struct medusa_monitor * medusa_tcpsocket_get_monitor (struct medusa_tcpsocket *tcpsocket);

#endif
