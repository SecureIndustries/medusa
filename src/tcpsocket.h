
#if !defined(MEDUSA_TCPSOCKET_H)
#define MEDUSA_TCPSOCKET_H

struct iovec;
struct medusa_buffer;
struct medusa_monitor;
struct medusa_tcpsocket;

enum {
        MEDUSA_TCPSOCKET_PROTOCOL_ANY                   = 0,
        MEDUSA_TCPSOCKET_PROTOCOL_IPV4                  = 1,
        MEDUSA_TCPSOCKET_PROTOCOL_IPV6                  = 2
#define MEDUSA_TCPSOCKET_PROTOCOL_ANY                   MEDUSA_TCPSOCKET_PROTOCOL_ANY
#define MEDUSA_TCPSOCKET_PROTOCOL_IPV4                  MEDUSA_TCPSOCKET_PROTOCOL_IPV4
#define MEDUSA_TCPSOCKET_PROTOCOL_IPV6                  MEDUSA_TCPSOCKET_PROTOCOL_IPV6
};

enum {
        MEDUSA_TCPSOCKET_EVENT_BINDING                  = (1 <<  0), /* 0x00000001 */
        MEDUSA_TCPSOCKET_EVENT_BOUND                    = (1 <<  1), /* 0x00000002 */
        MEDUSA_TCPSOCKET_EVENT_LISTENING                = (1 <<  2), /* 0x00000004 */
        MEDUSA_TCPSOCKET_EVENT_CONNECTION               = (1 <<  3), /* 0x00000008 */
        MEDUSA_TCPSOCKET_EVENT_RESOLVING                = (1 <<  4), /* 0x00000010 */
        MEDUSA_TCPSOCKET_EVENT_RESOLVE_TIMEOUT          = (1 <<  5), /* 0x00000020 */
        MEDUSA_TCPSOCKET_EVENT_RESOLVED                 = (1 <<  6), /* 0x00000040 */
        MEDUSA_TCPSOCKET_EVENT_CONNECTING               = (1 <<  7), /* 0x00000080 */
        MEDUSA_TCPSOCKET_EVENT_CONNECT_TIMEOUT          = (1 <<  8), /* 0x00000100 */
        MEDUSA_TCPSOCKET_EVENT_CONNECTED                = (1 <<  9), /* 0x00000200 */
        MEDUSA_TCPSOCKET_EVENT_IN                       = (1 << 10), /* 0x00000400 */
        MEDUSA_TCPSOCKET_EVENT_IN_TIMEOUT               = (1 << 11), /* 0x00000800 */
        MEDUSA_TCPSOCKET_EVENT_OUT                      = (1 << 12), /* 0x00001000 */
        MEDUSA_TCPSOCKET_EVENT_BUFFERED_READ            = (1 << 13), /* 0x00002000 */
        MEDUSA_TCPSOCKET_EVENT_BUFFERED_READ_TIMEOUT    = (1 << 14), /* 0x00004000 */
        MEDUSA_TCPSOCKET_EVENT_BUFFERED_WRITE           = (1 << 15), /* 0x00008000 */
        MEDUSA_TCPSOCKET_EVENT_BUFFERED_WRITE_TIMEOUT   = (1 << 16), /* 0x00010000 */
        MEDUSA_TCPSOCKET_EVENT_BUFFERED_WRITE_FINISHED  = (1 << 17), /* 0x00020000 */
        MEDUSA_TCPSOCKET_EVENT_DISCONNECTED             = (1 << 18), /* 0x00040000 */
        MEDUSA_TCPSOCKET_EVENT_ERROR                    = (1 << 19), /* 0x00080000 */
        MEDUSA_TCPSOCKET_EVENT_DESTROY                  = (1 << 20)  /* 0x00100000 */
#define MEDUSA_TCPSOCKET_EVENT_BINDING                  MEDUSA_TCPSOCKET_EVENT_BINDING
#define MEDUSA_TCPSOCKET_EVENT_BOUND                    MEDUSA_TCPSOCKET_EVENT_BOUND
#define MEDUSA_TCPSOCKET_EVENT_LISTENING                MEDUSA_TCPSOCKET_EVENT_LISTENING
#define MEDUSA_TCPSOCKET_EVENT_CONNECTION               MEDUSA_TCPSOCKET_EVENT_CONNECTION
#define MEDUSA_TCPSOCKET_EVENT_RESOLVING                MEDUSA_TCPSOCKET_EVENT_RESOLVING
#define MEDUSA_TCPSOCKET_EVENT_RESOLVE_TIMEOUT          MEDUSA_TCPSOCKET_EVENT_RESOLVE_TIMEOUT
#define MEDUSA_TCPSOCKET_EVENT_RESOLVED                 MEDUSA_TCPSOCKET_EVENT_RESOLVED
#define MEDUSA_TCPSOCKET_EVENT_CONNECTING               MEDUSA_TCPSOCKET_EVENT_CONNECTING
#define MEDUSA_TCPSOCKET_EVENT_CONNECT_TIMEOUT          MEDUSA_TCPSOCKET_EVENT_CONNECT_TIMEOUT
#define MEDUSA_TCPSOCKET_EVENT_CONNECTED                MEDUSA_TCPSOCKET_EVENT_CONNECTED
#define MEDUSA_TCPSOCKET_EVENT_IN                       MEDUSA_TCPSOCKET_EVENT_IN
#define MEDUSA_TCPSOCKET_EVENT_IN_TIMEOUT               MEDUSA_TCPSOCKET_EVENT_IN_TIMEOUT
#define MEDUSA_TCPSOCKET_EVENT_OUT                      MEDUSA_TCPSOCKET_EVENT_OUT
#define MEDUSA_TCPSOCKET_EVENT_BUFFERED_READ            MEDUSA_TCPSOCKET_EVENT_BUFFERED_READ
#define MEDUSA_TCPSOCKET_EVENT_BUFFERED_READ_TIMEOUT    MEDUSA_TCPSOCKET_EVENT_BUFFERED_READ_TIMEOUT
#define MEDUSA_TCPSOCKET_EVENT_BUFFERED_WRITE           MEDUSA_TCPSOCKET_EVENT_BUFFERED_WRITE
#define MEDUSA_TCPSOCKET_EVENT_BUFFERED_WRITE_TIMEOUT   MEDUSA_TCPSOCKET_EVENT_BUFFERED_WRITE_TIMEOUT
#define MEDUSA_TCPSOCKET_EVENT_BUFFERED_WRITE_FINISHED  MEDUSA_TCPSOCKET_EVENT_BUFFERED_WRITE_FINISHED
#define MEDUSA_TCPSOCKET_EVENT_DISCONNECTED             MEDUSA_TCPSOCKET_EVENT_DISCONNECTED
#define MEDUSA_TCPSOCKET_EVENT_ERROR                    MEDUSA_TCPSOCKET_EVENT_ERROR
#define MEDUSA_TCPSOCKET_EVENT_DESTROY                  MEDUSA_TCPSOCKET_EVENT_DESTROY
};

enum {
        MEDUSA_TCPSOCKET_STATE_UNKNOWN                  = 0,
        MEDUSA_TCPSOCKET_STATE_DISCONNECTED             = 1,
        MEDUSA_TCPSOCKET_STATE_BINDING                  = 2,
        MEDUSA_TCPSOCKET_STATE_BOUND                    = 3,
        MEDUSA_TCPSOCKET_STATE_LISTENING                = 4,
        MEDUSA_TCPSOCKET_STATE_RESOLVING                = 5,
        MEDUSA_TCPSOCKET_STATE_RESOLVED                 = 6,
        MEDUSA_TCPSOCKET_STATE_CONNECTING               = 7,
        MEDUSA_TCPSOCKET_STATE_CONNECTED                = 8
#define MEDUSA_TCPSOCKET_STATE_UNKNOWN                  MEDUSA_TCPSOCKET_STATE_UNKNOWN
#define MEDUSA_TCPSOCKET_STATE_BINDING                  MEDUSA_TCPSOCKET_STATE_BINDING
#define MEDUSA_TCPSOCKET_STATE_BOUND                    MEDUSA_TCPSOCKET_STATE_BOUND
#define MEDUSA_TCPSOCKET_STATE_LISTENING                MEDUSA_TCPSOCKET_STATE_LISTENING
#define MEDUSA_TCPSOCKET_STATE_DISCONNECTED             MEDUSA_TCPSOCKET_STATE_DISCONNECTED
#define MEDUSA_TCPSOCKET_STATE_RESOLVING                MEDUSA_TCPSOCKET_STATE_RESOLVING
#define MEDUSA_TCPSOCKET_STATE_RESOLVED                 MEDUSA_TCPSOCKET_STATE_RESOLVED
#define MEDUSA_TCPSOCKET_STATE_CONNECTING               MEDUSA_TCPSOCKET_STATE_CONNECTING
#define MEDUSA_TCPSOCKET_STATE_CONNECTED                MEDUSA_TCPSOCKET_STATE_CONNECTED
};

struct medusa_tcpsocket_init_options {
        struct medusa_monitor *monitor;
        int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...);
        void *context;
        int nonblocking;
        int reuseaddr;
        int reuseport;
        int backlog;
        int nodelay;
        int buffered;
        int enabled;
};

struct medusa_tcpsocket_accept_options {
        int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...);
        void *context;
        int nonblocking;
        int nodelay;
        int buffered;
        int enabled;
};

struct medusa_tcpsocket_bind_options {
        unsigned int protocol;
        const char *address;
        unsigned short port;
};

struct medusa_tcpsocket_connect_options {
        unsigned int protocol;
        const char *address;
        unsigned short port;
};

struct medusa_tcpsocket_attach_options {
        int fd;
};

#ifdef __cplusplus
extern "C"
{
#endif

int medusa_tcpsocket_init_options_default (struct medusa_tcpsocket_init_options *options);

struct medusa_tcpsocket * medusa_tcpsocket_create (struct medusa_monitor *monitor, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...), void *context);
struct medusa_tcpsocket * medusa_tcpsocket_create_with_options (const struct medusa_tcpsocket_init_options *options);
void medusa_tcpsocket_destroy (struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_get_state (const struct medusa_tcpsocket *tcpsocket);
int medusa_tcpsocket_get_error (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_set_enabled (struct medusa_tcpsocket *tcpsocket, int enabled);
int medusa_tcpsocket_get_enabled (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_enable (struct medusa_tcpsocket *tcpsocket);
int medusa_tcpsocket_disable (struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_set_buffered (struct medusa_tcpsocket *tcpsocket, int enabled);
int medusa_tcpsocket_get_buffered (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_set_nonblocking (struct medusa_tcpsocket *tcpsocket, int enabled);
int medusa_tcpsocket_get_nonblocking (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_set_nodelay (struct medusa_tcpsocket *tcpsocket, int enabled);
int medusa_tcpsocket_get_nodelay (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_set_reuseaddr (struct medusa_tcpsocket *tcpsocket, int enabled);
int medusa_tcpsocket_get_reuseaddr (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_set_reuseport (struct medusa_tcpsocket *tcpsocket, int enabled);
int medusa_tcpsocket_get_reuseport (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_set_backlog (struct medusa_tcpsocket *tcpsocket, int backlog);
int medusa_tcpsocket_get_backlog (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_set_connect_timeout (struct medusa_tcpsocket *tcpsocket, double timeout);
double medusa_tcpsocket_get_connect_timeout (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_set_read_timeout (struct medusa_tcpsocket *tcpsocket, double timeout);
double medusa_tcpsocket_get_read_timeout (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_get_fd (const struct medusa_tcpsocket *tcpsocket);
struct medusa_buffer * medusa_tcpsocket_get_read_buffer (const struct medusa_tcpsocket *tcpsocket);
struct medusa_buffer * medusa_tcpsocket_get_write_buffer (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_set_events (struct medusa_tcpsocket *tcpsocket, unsigned int events);
int medusa_tcpsocket_add_events (struct medusa_tcpsocket *tcpsocket, unsigned int events);
int medusa_tcpsocket_del_events (struct medusa_tcpsocket *tcpsocket, unsigned int events);
unsigned int medusa_tcpsocket_get_events (const struct medusa_tcpsocket *io);

int medusa_tcpsocket_bind_options_default (struct medusa_tcpsocket_bind_options *options);
int medusa_tcpsocket_bind (struct medusa_tcpsocket *tcpsocket, unsigned int protocol, const char *address, unsigned short port);
int medusa_tcpsocket_bind_with_options (struct medusa_tcpsocket *tcpsocket, const struct medusa_tcpsocket_bind_options *options);
;
int medusa_tcpsocket_connect_options_default (struct medusa_tcpsocket_connect_options *options);
int medusa_tcpsocket_connect (struct medusa_tcpsocket *tcpsocket, unsigned int protocol, const char *address, unsigned short port);
int medusa_tcpsocket_connect_with_options (struct medusa_tcpsocket *tcpsocket, const struct medusa_tcpsocket_connect_options *options);

int medusa_tcpsocket_attach_options_default (struct medusa_tcpsocket_attach_options *options);
int medusa_tcpsocket_attach (struct medusa_tcpsocket *tcpsocket, int fd);
int medusa_tcpsocket_attach_with_options (struct medusa_tcpsocket *tcpsocket, const struct medusa_tcpsocket_attach_options *options);

int medusa_tcpsocket_accept_options_default (struct medusa_tcpsocket_accept_options *options);
struct medusa_tcpsocket * medusa_tcpsocket_accept (struct medusa_tcpsocket *tcpsocket, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...), void *context);
struct medusa_tcpsocket * medusa_tcpsocket_accept_with_options (struct medusa_tcpsocket *tcpsocket, const struct medusa_tcpsocket_accept_options *options);

int medusa_tcpsocket_set_userdata (struct medusa_tcpsocket *tcpsocket, void *userdata);
void * medusa_tcpsocket_get_userdata (struct medusa_tcpsocket *tcpsocket);

struct medusa_monitor * medusa_tcpsocket_get_monitor (struct medusa_tcpsocket *tcpsocket);

const char * medusa_tcpsocket_state_string (unsigned int state);
const char * medusa_tcpsocket_event_string (unsigned int events);

#ifdef __cplusplus
}
#endif

#endif
