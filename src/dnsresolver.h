
#if !defined(MEDUSA_DNSRESOLVER_H)
#define MEDUSA_DNSRESOLVER_H

struct medusa_monitor;
struct medusa_dnsresolver;

enum {
        MEDUSA_DNSRESOLVER_EVENT_STARTED                = (1 << 0),
        MEDUSA_DNSRESOLVER_EVENT_STOPPED                = (1 << 1),
        MEDUSA_DNSRESOLVER_EVENT_ERROR                  = (1 << 2),
        MEDUSA_DNSRESOLVER_EVENT_STATE_CHANGED          = (1 << 3),
        MEDUSA_DNSRESOLVER_EVENT_DESTROY                = (1 << 4)
#define MEDUSA_DNSRESOLVER_EVENT_STARTED                MEDUSA_DNSRESOLVER_EVENT_STARTED
#define MEDUSA_DNSRESOLVER_EVENT_STOPPED                MEDUSA_DNSRESOLVER_EVENT_STOPPED
#define MEDUSA_DNSRESOLVER_EVENT_ERROR                  MEDUSA_DNSRESOLVER_EVENT_ERROR
#define MEDUSA_DNSRESOLVER_EVENT_STATE_CHANGED          MEDUSA_DNSRESOLVER_EVENT_STATE_CHANGED
#define MEDUSA_DNSRESOLVER_EVENT_DESTROY                MEDUSA_DNSRESOLVER_EVENT_DESTROY
};

enum {
        MEDUSA_DNSRESOLVER_STATE_UNKNOWN                = 0,
        MEDUSA_DNSRESOLVER_STATE_STARTED                = 1,
        MEDUSA_DNSRESOLVER_STATE_STOPPED                = 2,
        MEDUSA_DNSRESOLVER_STATE_ERROR                  = 3
#define MEDUSA_DNSRESOLVER_STATE_UNKNOWN                MEDUSA_DNSRESOLVER_STATE_UNKNOWN
#define MEDUSA_DNSRESOLVER_STATE_STARTED                MEDUSA_DNSRESOLVER_STATE_STARTED
#define MEDUSA_DNSRESOLVER_STATE_STOPPED                MEDUSA_DNSRESOLVER_STATE_STOPPED
#define MEDUSA_DNSRESOLVER_STATE_ERROR                  MEDUSA_DNSRESOLVER_STATE_ERROR
};

struct medusa_dnsresolver_init_options {
        struct medusa_monitor *monitor;
        int (*onevent) (struct medusa_dnsresolver *dnsresolver, unsigned int events, void *context, void *param);
        void *context;
        const char *nameserver;
};

struct medusa_dnsresolver_event_error {
        unsigned int state;
        unsigned int error;
};

struct medusa_dnsresolver_event_state_changed {
        unsigned int pstate;
        unsigned int state;
        unsigned int error;
};

#ifdef __cplusplus
extern "C"
{
#endif

int medusa_dnsresolver_init_options_default (struct medusa_dnsresolver_init_options *options);

struct medusa_dnsresolver * medusa_dnsresolver_create (struct medusa_monitor *monitor, int (*onevent) (struct medusa_dnsresolver *dnsresolver, unsigned int events, void *context, void *param), void *context);
struct medusa_dnsresolver * medusa_dnsresolver_create_with_options (const struct medusa_dnsresolver_init_options *options);
void medusa_dnsresolver_destroy (struct medusa_dnsresolver *dnsresolver);

unsigned int medusa_dnsresolver_get_state (const struct medusa_dnsresolver *dnsresolver);

int medusa_dnsresolver_set_nameserver (struct medusa_dnsresolver *dnsresolver, const char *nameserver);
const char * medusa_dnsresolver_get_nameserver (struct medusa_dnsresolver *dnsresolver);

void * medusa_dnsresolver_get_context (struct medusa_dnsresolver *dnsresolver);
int medusa_dnsresolver_set_context (struct medusa_dnsresolver *dnsresolver, void *context);

void * medusa_dnsresolver_get_userdata (struct medusa_dnsresolver *dnsresolver);
int medusa_dnsresolver_set_userdata (struct medusa_dnsresolver *dnsresolver, void *userdata);

int medusa_dnsresolver_set_userdata_ptr (struct medusa_dnsresolver *dnsresolver, void *userdata);
void * medusa_dnsresolver_get_userdata_ptr (struct medusa_dnsresolver *dnsresolver);

int medusa_dnsresolver_set_userdata_int (struct medusa_dnsresolver *dnsresolver, int userdara);
int medusa_dnsresolver_get_userdata_int (struct medusa_dnsresolver *dnsresolver);

int medusa_dnsresolver_set_userdata_uint (struct medusa_dnsresolver *dnsresolver, unsigned int userdata);
unsigned int medusa_dnsresolver_get_userdata_uint (struct medusa_dnsresolver *dnsresolver);

int medusa_dnsresolver_start (struct medusa_dnsresolver *dnsresolver);
int medusa_dnsresolver_stop (struct medusa_dnsresolver *dnsresolver);

int medusa_dnsresolver_onevent (struct medusa_dnsresolver *dnsresolver, unsigned int events, void *param);
struct medusa_monitor * medusa_dnsresolver_get_monitor (struct medusa_dnsresolver *dnsresolver);

const char * medusa_dnsresolver_event_string (unsigned int events);
const char * medusa_dnsresolver_state_string (unsigned int state);

#ifdef __cplusplus
}
#endif

#endif
