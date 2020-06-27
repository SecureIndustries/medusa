
#if !defined(MEDUSA_WEBSOCKETSERVER_H)
#define MEDUSA_WEBSOCKETSERVER_H

struct medusa_monitor;
struct medusa_websocketserver;
struct medusa_websocketserver_client;

enum {
        MEDUSA_WEBSOCKETSERVER_PROTOCOL_ANY                     = 0,
        MEDUSA_WEBSOCKETSERVER_PROTOCOL_IPV4                    = 1,
        MEDUSA_WEBSOCKETSERVER_PROTOCOL_IPV6                    = 2
#define MEDUSA_WEBSOCKETSERVER_PROTOCOL_ANY                     MEDUSA_WEBSOCKETSERVER_PROTOCOL_ANY
#define MEDUSA_WEBSOCKETSERVER_PROTOCOL_IPV4                    MEDUSA_WEBSOCKETSERVER_PROTOCOL_IPV4
#define MEDUSA_WEBSOCKETSERVER_PROTOCOL_IPV6                    MEDUSA_WEBSOCKETSERVER_PROTOCOL_IPV6
};

enum {
        MEDUSA_WEBSOCKETSERVER_EVENT_STARTED                    = (1 << 0),
        MEDUSA_WEBSOCKETSERVER_EVENT_STOPPED                    = (1 << 1),
        MEDUSA_WEBSOCKETSERVER_EVENT_BINDING                    = (1 << 2),
        MEDUSA_WEBSOCKETSERVER_EVENT_BOUND                      = (1 << 3),
        MEDUSA_WEBSOCKETSERVER_EVENT_LISTENING                  = (1 << 4),
        MEDUSA_WEBSOCKETSERVER_EVENT_CONNECTION                 = (1 << 5),
        MEDUSA_WEBSOCKETSERVER_EVENT_ERROR                      = (1 << 6),
        MEDUSA_WEBSOCKETSERVER_EVENT_DESTROY                    = (1 << 7)
#define MEDUSA_WEBSOCKETSERVER_EVENT_STARTED                    MEDUSA_WEBSOCKETSERVER_EVENT_STARTED
#define MEDUSA_WEBSOCKETSERVER_EVENT_STOPPED                    MEDUSA_WEBSOCKETSERVER_EVENT_STOPPED
#define MEDUSA_WEBSOCKETSERVER_EVENT_BINDING                    MEDUSA_WEBSOCKETSERVER_EVENT_BINDING
#define MEDUSA_WEBSOCKETSERVER_EVENT_BOUND                      MEDUSA_WEBSOCKETSERVER_EVENT_BOUND
#define MEDUSA_WEBSOCKETSERVER_EVENT_LISTENING                  MEDUSA_WEBSOCKETSERVER_EVENT_LISTENING
#define MEDUSA_WEBSOCKETSERVER_EVENT_CONNECTION                 MEDUSA_WEBSOCKETSERVER_EVENT_CONNECTION
#define MEDUSA_WEBSOCKETSERVER_EVENT_ERROR                      MEDUSA_WEBSOCKETSERVER_EVENT_ERROR
#define MEDUSA_WEBSOCKETSERVER_EVENT_DESTROY                    MEDUSA_WEBSOCKETSERVER_EVENT_DESTROY
};

enum {
        MEDUSA_WEBSOCKETSERVER_STATE_UNKNOWN                    = 0,
        MEDUSA_WEBSOCKETSERVER_STATE_STOPPED                    = 1,
        MEDUSA_WEBSOCKETSERVER_STATE_STARTED                    = 2,
        MEDUSA_WEBSOCKETSERVER_STATE_BINDING                    = 3,
        MEDUSA_WEBSOCKETSERVER_STATE_BOUND                      = 4,
        MEDUSA_WEBSOCKETSERVER_STATE_LISTENING                  = 5
#define MEDUSA_WEBSOCKETSERVER_STATE_UNKNOWN                    MEDUSA_WEBSOCKETSERVER_STATE_UNKNOWN
#define MEDUSA_WEBSOCKETSERVER_STATE_STOPPED                    MEDUSA_WEBSOCKETSERVER_STATE_STOPPED
#define MEDUSA_WEBSOCKETSERVER_STATE_STARTED                    MEDUSA_WEBSOCKETSERVER_STATE_STARTED
#define MEDUSA_WEBSOCKETSERVER_STATE_BINDING                    MEDUSA_WEBSOCKETSERVER_STATE_BINDING
#define MEDUSA_WEBSOCKETSERVER_STATE_BOUND                      MEDUSA_WEBSOCKETSERVER_STATE_BOUND
#define MEDUSA_WEBSOCKETSERVER_STATE_LISTENING                  MEDUSA_WEBSOCKETSERVER_STATE_LISTENING
};

enum {
        MEDUSA_WEBSOCKETSERVER_CLIENT_EVENT_ERROR               = (1 << 0),
        MEDUSA_WEBSOCKETSERVER_CLIENT_EVENT_DESTROY             = (1 << 1)
#define MEDUSA_WEBSOCKETSERVER_CLIENT_EVENT_ERROR               MEDUSA_WEBSOCKETSERVER_CLIENT_EVENT_ERROR
#define MEDUSA_WEBSOCKETSERVER_CLIENT_EVENT_DESTROY             MEDUSA_WEBSOCKETSERVER_CLIENT_EVENT_DESTROY
};

enum {
        MEDUSA_WEBSOCKETSERVER_CLIENT_STATE_UNKNOWN             = 0,
        MEDUSA_WEBSOCKETSERVER_CLIENT_STATE_DISCONNECTED        = 1
#define MEDUSA_WEBSOCKETSERVER_CLIENT_STATE_UNKNOWN             MEDUSA_WEBSOCKETSERVER_CLIENT_STATE_UNKNOWN
#define MEDUSA_WEBSOCKETSERVER_CLIENT_STATE_DISCONNECTED        MEDUSA_WEBSOCKETSERVER_CLIENT_STATE_DISCONNECTED
};

struct medusa_websocketserver_init_options {
        struct medusa_monitor *monitor;
        unsigned int protocol;
        const char *address;
        unsigned short port;
        const char *servername;
        int buffered;
        int enabled;
        int (*onevent) (struct medusa_websocketserver *websocketserver, unsigned int events, void *context, void *param);
        void *context;
};

struct medusa_websocketserver_accept_options {
        int buffered;
        int enabled;
        int (*onevent) (struct medusa_websocketserver_client *websocketserver_client, unsigned int events, void *context, void *param);
        void *context;
};

#ifdef __cplusplus
extern "C"
{
#endif

int medusa_websocketserver_init_options_default (struct medusa_websocketserver_init_options *options);

struct medusa_websocketserver * medusa_websocketserver_create (struct medusa_monitor *monitor, unsigned int protocol, const char *address, unsigned short port, int (*onevent) (struct medusa_websocketserver *websocketserver, unsigned int events, void *context, void *param), void *context);
struct medusa_websocketserver * medusa_websocketserver_create_with_options (const struct medusa_websocketserver_init_options *options);
void medusa_websocketserver_destroy (struct medusa_websocketserver *websocketserver);

unsigned int medusa_websocketserver_get_state (const struct medusa_websocketserver *websocketserver);

int medusa_websocketserver_set_buffered (struct medusa_websocketserver *websocketserver, int buffered);
int medusa_websocketserver_get_buffered (const struct medusa_websocketserver *websocketserver);

int medusa_websocketserver_set_enabled (struct medusa_websocketserver *websocketserver, int enabled);
int medusa_websocketserver_get_enabled (const struct medusa_websocketserver *websocketserver);

int medusa_websocketserver_start (struct medusa_websocketserver *websocketserver);
int medusa_websocketserver_stop (struct medusa_websocketserver *websocketserver);

int medusa_websocketserver_set_context (struct medusa_websocketserver *websocketserver, void *context);
void * medusa_websocketserver_get_context (struct medusa_websocketserver *websocketserver);

int medusa_websocketserver_set_userdata (struct medusa_websocketserver *websocketserver, void *userdata);
void * medusa_websocketserver_get_userdata (struct medusa_websocketserver *websocketserver);

int medusa_websocketserver_set_userdata_ptr (struct medusa_websocketserver *websocketserver, void *userdata);
void * medusa_websocketserver_get_userdata_ptr (struct medusa_websocketserver *websocketserver);

int medusa_websocketserver_set_userdata_int (struct medusa_websocketserver *websocketserver, int userdara);
int medusa_websocketserver_get_userdata_int (struct medusa_websocketserver *websocketserver);

int medusa_websocketserver_set_userdata_uint (struct medusa_websocketserver *websocketserver, unsigned int userdata);
unsigned int medusa_websocketserver_get_userdata_uint (struct medusa_websocketserver *websocketserver);

int medusa_websocketserver_onevent (struct medusa_websocketserver *websocketserver, unsigned int events, void *param);
struct medusa_monitor * medusa_websocketserver_get_monitor (struct medusa_websocketserver *websocketserver);

const char * medusa_websocketserver_event_string (unsigned int events);
const char * medusa_websocketserver_state_string (unsigned int state);

int medusa_websocketserver_accept_options_default (struct medusa_websocketserver_accept_options *options);

struct medusa_websocketserver_client * medusa_websocketserver_accept (struct medusa_websocketserver *websocketserver, int (*onevent) (struct medusa_websocketserver_client *websocketserver_client, unsigned int events, void *context, void *param), void *context);
struct medusa_websocketserver_client * medusa_websocketserver_accept_with_options (struct medusa_websocketserver *websocketserver, struct medusa_websocketserver_accept_options *options);
void medusa_websocketserver_client_destroy (struct medusa_websocketserver_client *websocketserver_client);

unsigned int medusa_websocketserver_client_get_state (const struct medusa_websocketserver_client *websocketserver_client);

int medusa_websocketserver_client_set_enabled (struct medusa_websocketserver_client *websocketserver_client, int enabled);
int medusa_websocketserver_client_get_enabled (struct medusa_websocketserver_client *websocketserver_client);

int medusa_websocketserver_client_start (struct medusa_websocketserver_client *websocketserver_client);
int medusa_websocketserver_client_stop (struct medusa_websocketserver_client *websocketserver_client);

int medusa_websocketserver_client_set_context (struct medusa_websocketserver_client *websocketserver_client, void *context);
void * medusa_websocketserver_client_get_context (struct medusa_websocketserver_client *websocketserver_client);

int medusa_websocketserver_client_set_userdata (struct medusa_websocketserver_client *websocketserver_client, void *userdata);
void * medusa_websocketserver_client_get_userdata (struct medusa_websocketserver_client *websocketserver_client);

int medusa_websocketserver_client_set_userdata_ptr (struct medusa_websocketserver_client *websocketserver_client, void *userdata);
void * medusa_websocketserver_client_get_userdata_ptr (struct medusa_websocketserver_client *websocketserver_client);

int medusa_websocketserver_client_set_userdata_int (struct medusa_websocketserver_client *websocketserver_client, int userdara);
int medusa_websocketserver_client_get_userdata_int (struct medusa_websocketserver_client *websocketserver_client);

int medusa_websocketserver_client_set_userdata_uint (struct medusa_websocketserver_client *websocketserver_client, unsigned int userdata);
unsigned int medusa_websocketserver_client_get_userdata_uint (struct medusa_websocketserver_client *websocketserver_client);

int medusa_websocketserver_client_onevent (struct medusa_websocketserver_client *websocketserver_client, unsigned int events, void *param);
struct medusa_monitor * medusa_websocketserver_client_get_monitor (struct medusa_websocketserver_client *websocketserver_client);

const char * medusa_websocketserver_client_event_string (unsigned int events);
const char * medusa_websocketserver_client_state_string (unsigned int state);

#ifdef __cplusplus
}
#endif

#endif
