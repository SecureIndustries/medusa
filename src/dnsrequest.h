
#if !defined(MEDUSA_DNSREQUEST_H)
#define MEDUSA_DNSREQUEST_H

struct medusa_monitor;
struct medusa_dnsrequest;

enum {
        MEDUSA_DNSREQUEST_EVENT_ERROR                  = (1 << 0),
        MEDUSA_DNSREQUEST_EVENT_DESTROY                = (1 << 1)
#define MEDUSA_DNSREQUEST_EVENT_ERROR                  MEDUSA_DNSREQUEST_EVENT_ERROR
#define MEDUSA_DNSREQUEST_EVENT_DESTROY                MEDUSA_DNSREQUEST_EVENT_DESTROY
};

enum {
        MEDUSA_DNSREQUEST_STATE_UNKNWON                = 0,
#define MEDUSA_DNSREQUEST_STATE_UNKNWON                MEDUSA_DNSREQUEST_STATE_UNKNWON
};

struct medusa_dnsrequest_init_options {
        struct medusa_monitor *monitor;
        int (*onevent) (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *context, void *param);
        void *context;
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

int medusa_dnsrequest_set_method (struct medusa_dnsrequest *dnsrequest, const char *method);

int medusa_dnsrequest_add_header (struct medusa_dnsrequest *dnsrequest, const char *key, const char *value, ...) __attribute__((format(printf, 3, 4)));
int medusa_dnsrequest_add_vheader (struct medusa_dnsrequest *dnsrequest, const char *key, const char *value, va_list va);

int medusa_dnsrequest_make_post (struct medusa_dnsrequest *dnsrequest, const char *url, const void *data, int64_t length);
int medusa_dnsrequest_make_post_string (struct medusa_dnsrequest *dnsrequest, const char *url, const char *data);

int medusa_dnsrequest_onevent (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *param);
struct medusa_monitor * medusa_dnsrequest_get_monitor (struct medusa_dnsrequest *dnsrequest);

const struct medusa_dnsrequest_reply * medusa_dnsrequest_get_reply (const struct medusa_dnsrequest *dnsrequest);

const struct medusa_dnsrequest_reply_status * medusa_dnsrequest_reply_get_status (const struct medusa_dnsrequest_reply *reply);
int64_t medusa_dnsrequest_reply_status_get_code (const struct medusa_dnsrequest_reply_status *status);
const char * medusa_dnsrequest_reply_status_get_value (const struct medusa_dnsrequest_reply_status *status);

const struct medusa_dnsrequest_reply_headers * medusa_dnsrequest_reply_get_headers (const struct medusa_dnsrequest_reply *reply);
int64_t medusa_dnsrequest_reply_headers_get_count (const struct medusa_dnsrequest_reply_headers *headers);
const struct medusa_dnsrequest_reply_header * medusa_dnsrequest_reply_headers_get_first (const struct medusa_dnsrequest_reply_headers *headers);

const char * medusa_dnsrequest_reply_header_get_key (const struct medusa_dnsrequest_reply_header *header);
const char * medusa_dnsrequest_reply_header_get_value (const struct medusa_dnsrequest_reply_header *header);
const struct medusa_dnsrequest_reply_header * medusa_dnsrequest_reply_header_get_next (const struct medusa_dnsrequest_reply_header *header);

const struct medusa_dnsrequest_reply_body * medusa_dnsrequest_reply_get_body (const struct medusa_dnsrequest_reply *reply);
int64_t medusa_dnsrequest_reply_body_get_length (const struct medusa_dnsrequest_reply_body *body);
const void * medusa_dnsrequest_reply_body_get_value (const struct medusa_dnsrequest_reply_body *body);

const char * medusa_dnsrequest_event_string (unsigned int events);
const char * medusa_dnsrequest_state_string (unsigned int state);

#ifdef __cplusplus
}
#endif

#endif
