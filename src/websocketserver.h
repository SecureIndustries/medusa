
#if !defined(MEDUSA_WEBSOCKETSERVER_H)
#define MEDUSA_WEBSOCKETSERVER_H

struct medusa_monitor;
struct medusa_websocketserver;

enum {
        MEDUSA_WEBSOCKETSERVER_PROTOCOL_ANY                     = 0,
        MEDUSA_WEBSOCKETSERVER_PROTOCOL_IPV4                    = 1,
        MEDUSA_WEBSOCKETSERVER_PROTOCOL_IPV6                    = 2
#define MEDUSA_WEBSOCKETSERVER_PROTOCOL_ANY                     MEDUSA_WEBSOCKETSERVER_PROTOCOL_ANY
#define MEDUSA_WEBSOCKETSERVER_PROTOCOL_IPV4                    MEDUSA_WEBSOCKETSERVER_PROTOCOL_IPV4
#define MEDUSA_WEBSOCKETSERVER_PROTOCOL_IPV6                    MEDUSA_WEBSOCKETSERVER_PROTOCOL_IPV6
};

enum {
        MEDUSA_WEBSOCKETSERVER_EVENT_ERROR                      = (1 << 11),
        MEDUSA_WEBSOCKETSERVER_EVENT_DESTROY                    = (1 << 13)
#define MEDUSA_WEBSOCKETSERVER_EVENT_ERROR                      MEDUSA_WEBSOCKETSERVER_EVENT_ERROR
#define MEDUSA_WEBSOCKETSERVER_EVENT_DESTROY                    MEDUSA_WEBSOCKETSERVER_EVENT_DESTROY
};

enum {
        MEDUSA_WEBSOCKETSERVER_STATE_UNKNOWN                    = 0,
        MEDUSA_WEBSOCKETSERVER_STATE_STOPPED                    = 1
#define MEDUSA_WEBSOCKETSERVER_STATE_UNKNOWN                    MEDUSA_WEBSOCKETSERVER_STATE_UNKNOWN
#define MEDUSA_WEBSOCKETSERVER_STATE_STOPPED                    MEDUSA_WEBSOCKETSERVER_STATE_STOPPED
};

struct medusa_websocketserver_init_options {
        struct medusa_monitor *monitor;
        unsigned int protocol;
        const char *address;
        unsigned short port;
        const char *servername;
        int (*onevent) (struct medusa_websocketserver *websocketserver, unsigned int events, void *context, void *param);
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

int medusa_websocketserver_set_enabled (struct medusa_websocketserver *websocketserver, int enabled);
int medusa_websocketserver_get_enabled (struct medusa_websocketserver *websocketserver);

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

#ifdef __cplusplus
}
#endif

#endif