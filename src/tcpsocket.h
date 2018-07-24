
struct medusa_monitor;
struct medusa_tcpsocket;

enum {
        MEDUSA_TCPSOCKET_EVENT_RESOLVING        = 0x00000001,
        MEDUSA_TCPSOCKET_EVENT_RESOLVED         = 0x00000002,
        MEDUSA_TCPSOCKET_EVENT_CONNECTING       = 0x00000004,
        MEDUSA_TCPSOCKET_EVENT_CONNECTED        = 0x00000008,
        MEDUSA_TCPSOCKET_EVENT_WRITTEN          = 0x00000010,
        MEDUSA_TCPSOCKET_EVENT_READ             = 0x00000020,
        MEDUSA_TCPSOCKET_EVENT_DESTROY          = 0x00000040
#define MEDUSA_TCPSOCKET_EVENT_RESOLVING        MEDUSA_TCPSOCKET_EVENT_RESOLVING
#define MEDUSA_TCPSOCKET_EVENT_RESOLVED         MEDUSA_TCPSOCKET_EVENT_RESOLVED
#define MEDUSA_TCPSOCKET_EVENT_CONNECTING       MEDUSA_TCPSOCKET_EVENT_CONNECTING
#define MEDUSA_TCPSOCKET_EVENT_CONNECTED        MEDUSA_TCPSOCKET_EVENT_CONNECTED
#define MEDUSA_TCPSOCKET_EVENT_WRITTEN          MEDUSA_TCPSOCKET_EVENT_WRITTEN
#define MEDUSA_TCPSOCKET_EVENT_READ             MEDUSA_TCPSOCKET_EVENT_READ
#define MEDUSA_TCPSOCKET_EVENT_DESTROY          MEDUSA_TCPSOCKET_EVENT_DESTROY
};

enum {
        MEDUSA_TCPSOCKET_STATE_UNKNWON          = 0,
        MEDUSA_TCPSOCKET_STATE_INITIAL          = 1,
        MEDUSA_TCPSOCKET_STATE_RESOLVING        = 1,
        MEDUSA_TCPSOCKET_STATE_CONNECTING       = 2,
        MEDUSA_TCPSOCKET_STATE_CONNECTED        = 3,
        MEDUSA_TCPSOCKET_STATE_LISTENING        = 4,
        MEDUSA_TCPSOCKET_STATE_CLOSING          = 5
#define MEDUSA_TCPSOCKET_STATE_UNKNWON          MEDUSA_TCPSOCKET_STATE_UNKNWON
#define MEDUSA_TCPSOCKET_STATE_INITIAL          MEDUSA_TCPSOCKET_STATE_INITIAL
#define MEDUSA_TCPSOCKET_STATE_RESOLVING        MEDUSA_TCPSOCKET_STATE_RESOLVING
#define MEDUSA_TCPSOCKET_STATE_CONNECTING       MEDUSA_TCPSOCKET_STATE_CONNECTING
#define MEDUSA_TCPSOCKET_STATE_CONNECTED        MEDUSA_TCPSOCKET_STATE_CONNECTED
#define MEDUSA_TCPSOCKET_STATE_LISTENING        MEDUSA_TCPSOCKET_STATE_LISTENING
#define MEDUSA_TCPSOCKET_STATE_CLOSING          MEDUSA_TCPSOCKET_STATE_CLOSING
};

struct medusa_tcpsocket * medusa_tcpsocket_create (struct medusa_monitor *monitor, int (*callback) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context), void *context);
void medusa_tcpsocket_destroy (struct medusa_tcpsocket *tcpsocket);

unsigned int medusa_tcpspcket_get_state (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_set_nonblocking (struct medusa_tcpsocket *tcpsocket, int enabled);
int medusa_tcpsocket_get_nonblocking (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_set_reuseaddr (struct medusa_tcpsocket *tcpsocket, int enabled);
int medusa_tcpsocket_get_reuseaddr (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_set_reuseport (struct medusa_tcpsocket *tcpsocket, int enabled);
int medusa_tcpsocket_get_reuseport (const struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_bind (struct medusa_tcpsocket *tcpsocket, const char *address, unsigned int port);
int medusa_tcpsocket_connect (struct medusa_tcpsocket *tcpsocket, const char *address, unsigned int port);

int medusa_tcpsocket_read (struct medusa_tcpsocket *tcpsocket, void *data, int size);
int medusa_tcpsocket_write (struct medusa_tcpsocket *tcpsocket, const void *data, int size);
