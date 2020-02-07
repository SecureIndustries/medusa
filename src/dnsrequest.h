
#if !defined(MEDUSA_DNSREQUEST_H)
#define MEDUSA_DNSREQUEST_H

struct medusa_monitor;
struct medusa_dnsrequest;

enum {
        MEDUSA_DNSREQUEST_EVENT_RESOLVING               = (1 << 0),
        MEDUSA_DNSREQUEST_EVENT_RESOLVE_TIMEOUT         = (1 << 1),
        MEDUSA_DNSREQUEST_EVENT_RESOLVED                = (1 << 2),
        MEDUSA_DNSREQUEST_EVENT_CONNECTING              = (1 << 3),
        MEDUSA_DNSREQUEST_EVENT_CONNECT_TIMEOUT         = (1 << 4),
        MEDUSA_DNSREQUEST_EVENT_CONNECTED               = (1 << 5),
        MEDUSA_DNSREQUEST_EVENT_ERROR                   = (1 << 6),
        MEDUSA_DNSREQUEST_EVENT_DESTROY                 = (1 << 7)
#define MEDUSA_DNSREQUEST_EVENT_RESOLVING               MEDUSA_DNSREQUEST_EVENT_RESOLVING
#define MEDUSA_DNSREQUEST_EVENT_RESOLVE_TIMEOUT         MEDUSA_DNSREQUEST_EVENT_RESOLVE_TIMEOUT
#define MEDUSA_DNSREQUEST_EVENT_RESOLVED                MEDUSA_DNSREQUEST_EVENT_RESOLVED
#define MEDUSA_DNSREQUEST_EVENT_CONNECTING              MEDUSA_DNSREQUEST_EVENT_CONNECTING
#define MEDUSA_DNSREQUEST_EVENT_CONNECT_TIMEOUT         MEDUSA_DNSREQUEST_EVENT_CONNECT_TIMEOUT
#define MEDUSA_DNSREQUEST_EVENT_CONNECTED               MEDUSA_DNSREQUEST_EVENT_CONNECTED
#define MEDUSA_DNSREQUEST_EVENT_ERROR                   MEDUSA_DNSREQUEST_EVENT_ERROR
#define MEDUSA_DNSREQUEST_EVENT_DESTROY                 MEDUSA_DNSREQUEST_EVENT_DESTROY
};

enum {
        MEDUSA_DNSREQUEST_STATE_UNKNOWN                 = 0,
        MEDUSA_DNSREQUEST_STATE_DISCONNECTED            = 1,
        MEDUSA_DNSREQUEST_STATE_RESOLVING               = 2,
        MEDUSA_DNSREQUEST_STATE_RESOLVED                = 3,
        MEDUSA_DNSREQUEST_STATE_CONNECTING              = 4,
        MEDUSA_DNSREQUEST_STATE_CONNECTED               = 5
#define MEDUSA_DNSREQUEST_STATE_UNKNOWN                 MEDUSA_DNSREQUEST_STATE_UNKNOWN
#define MEDUSA_DNSREQUEST_STATE_RESOLVING               MEDUSA_DNSREQUEST_STATE_RESOLVING
#define MEDUSA_DNSREQUEST_STATE_RESOLVED                MEDUSA_DNSREQUEST_STATE_RESOLVED
#define MEDUSA_DNSREQUEST_STATE_CONNECTING              MEDUSA_DNSREQUEST_STATE_CONNECTING
#define MEDUSA_DNSREQUEST_STATE_CONNECTED               MEDUSA_DNSREQUEST_STATE_CONNECTED
#define MEDUSA_DNSREQUEST_STATE_DISCONNECTED            MEDUSA_DNSREQUEST_STATE_DISCONNECTED
};

enum {
        MEDUSA_DNSREQUEST_RECORD_TYPE_INVALID           = 0,
        MEDUSA_DNSREQUEST_RECORD_TYPE_A                 = 1,
        MEDUSA_DNSREQUEST_RECORD_TYPE_NS                = 2,
        MEDUSA_DNSREQUEST_RECORD_TYPE_CNAME             = 5,
        MEDUSA_DNSREQUEST_RECORD_TYPE_PTR               = 12,
        MEDUSA_DNSREQUEST_RECORD_TYPE_MX                = 15,
        MEDUSA_DNSREQUEST_RECORD_TYPE_TXT               = 16,
        MEDUSA_DNSREQUEST_RECORD_TYPE_AAAA              = 28,
        MEDUSA_DNSREQUEST_RECORD_TYPE_SRV               = 33,
        MEDUSA_DNSREQUEST_RECORD_TYPE_ANY               = 255,
        MEDUSA_DNSREQUEST_RECORD_TYPE_UNKNOWN           = 65280
#define MEDUSA_DNSREQUEST_RECORD_TYPE_INVALID           MEDUSA_DNSREQUEST_RECORD_TYPE_INVALID
#define MEDUSA_DNSREQUEST_RECORD_TYPE_A                 MEDUSA_DNSREQUEST_RECORD_TYPE_A
#define MEDUSA_DNSREQUEST_RECORD_TYPE_NS                MEDUSA_DNSREQUEST_RECORD_TYPE_NS
#define MEDUSA_DNSREQUEST_RECORD_TYPE_CNAME             MEDUSA_DNSREQUEST_RECORD_TYPE_CNAME
#define MEDUSA_DNSREQUEST_RECORD_TYPE_PTR               MEDUSA_DNSREQUEST_RECORD_TYPE_PTR
#define MEDUSA_DNSREQUEST_RECORD_TYPE_MX                MEDUSA_DNSREQUEST_RECORD_TYPE_MX
#define MEDUSA_DNSREQUEST_RECORD_TYPE_TXT               MEDUSA_DNSREQUEST_RECORD_TYPE_TXT
#define MEDUSA_DNSREQUEST_RECORD_TYPE_AAAA              MEDUSA_DNSREQUEST_RECORD_TYPE_AAAA
#define MEDUSA_DNSREQUEST_RECORD_TYPE_SRV               MEDUSA_DNSREQUEST_RECORD_TYPE_SRV
#define MEDUSA_DNSREQUEST_RECORD_TYPE_ANY               MEDUSA_DNSREQUEST_RECORD_TYPE_ANY
#define MEDUSA_DNSREQUEST_RECORD_TYPE_UNKNOWN           MEDUSA_DNSREQUEST_RECORD_TYPE_UNKNOWN
};

struct medusa_dnsrequest_init_options {
        struct medusa_monitor *monitor;
        int (*onevent) (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *context, void *param);
        void *context;
        const char *nameserver;
        unsigned int type;
        const char *name;
};

#ifdef __cplusplus
extern "C"
{
#endif

int medusa_dnsrequest_init_options_default (struct medusa_dnsrequest_init_options *options);

struct medusa_dnsrequest * medusa_dnsrequest_create (struct medusa_monitor *monitor, int (*onevent) (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *context, void *param), void *context);
struct medusa_dnsrequest * medusa_dnsrequest_create_with_options (const struct medusa_dnsrequest_init_options *options);
void medusa_dnsrequest_destroy (struct medusa_dnsrequest *dnsrequest);

unsigned int medusa_dnsrequest_get_state (const struct medusa_dnsrequest *dnsrequest);

int medusa_dnsrequest_set_connect_timeout (struct medusa_dnsrequest *dnsrequest, double timeout);
double medusa_dnsrequest_get_connect_timeout (const struct medusa_dnsrequest *dnsrequest);

int medusa_dnsrequest_set_read_timeout (struct medusa_dnsrequest *dnsrequest, double timeout);
double medusa_dnsrequest_get_read_timeout (const struct medusa_dnsrequest *dnsrequest);

int medusa_dnsrequest_set_nameserver (struct medusa_dnsrequest *dnsrequest, const char *nameserver);
const char * medusa_dnsrequest_get_nameserver (struct medusa_dnsrequest *dnsrequest);

int medusa_dnsrequest_set_type (struct medusa_dnsrequest *dnsrequest, unsigned int type);
int medusa_dnsrequest_get_type (struct medusa_dnsrequest *dnsrequest);

int medusa_dnsrequest_set_name (struct medusa_dnsrequest *dnsrequest, const char *name);
const char * medusa_dnsrequest_get_name (struct medusa_dnsrequest *dnsrequest);

int medusa_dnsrequest_lookup (struct medusa_dnsrequest *dnsrequest);
int medusa_dnsrequest_cancel (struct medusa_dnsrequest *dnsrequest);
int medusa_dnsrequest_abort (struct medusa_dnsrequest *dnsrequest);

int medusa_dnsrequest_onevent (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *param);
struct medusa_monitor * medusa_dnsrequest_get_monitor (struct medusa_dnsrequest *dnsrequest);

unsigned int medusa_dnsrequest_record_type_value (const char *type);
const char * medusa_dnsrequest_record_type_string (unsigned int type);

const char * medusa_dnsrequest_event_string (unsigned int events);
const char * medusa_dnsrequest_state_string (unsigned int state);

#ifdef __cplusplus
}
#endif

#endif
