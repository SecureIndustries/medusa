
#if !defined(MEDUSA_HTTP_REQUEST_H)
#define MEDUSA_HTTP_REQUEST_H

struct medusa_monitor;
struct medusa_http_request;

enum {
        MEDUSA_HTTP_REQUEST_PROTOCOL_ANY                = 0,
        MEDUSA_HTTP_REQUEST_PROTOCOL_IPV4               = 1,
        MEDUSA_HTTP_REQUEST_PROTOCOL_IPV6               = 2
#define MEDUSA_HTTP_REQUEST_PROTOCOL_ANY                MEDUSA_HTTP_REQUEST_PROTOCOL_ANY
#define MEDUSA_HTTP_REQUEST_PROTOCOL_IPV4               MEDUSA_HTTP_REQUEST_PROTOCOL_IPV4
#define MEDUSA_HTTP_REQUEST_PROTOCOL_IPV6               MEDUSA_HTTP_REQUEST_PROTOCOL_IPV6
};

enum {
        MEDUSA_HTTP_REQUEST_EVENT_RESOLVING             = 0x00000001,
        MEDUSA_HTTP_REQUEST_EVENT_RESOLVE_TIMEOUT       = 0x00000002,
        MEDUSA_HTTP_REQUEST_EVENT_RESOLVED              = 0x00000004,
        MEDUSA_HTTP_REQUEST_EVENT_CONNECTING            = 0x00000008,
        MEDUSA_HTTP_REQUEST_EVENT_CONNECT_TIMEOUT       = 0x00000010,
        MEDUSA_HTTP_REQUEST_EVENT_CONNECTED             = 0x00000020,
        MEDUSA_HTTP_REQUEST_EVENT_WRITE_TIMEOUT         = 0x00000040,
        MEDUSA_HTTP_REQUEST_EVENT_WRITTEN               = 0x00000080,
        MEDUSA_HTTP_REQUEST_EVENT_WRITE_FINISHED        = 0x00000100,
        MEDUSA_HTTP_REQUEST_EVENT_READ_TIMEOUT          = 0x00000200,
        MEDUSA_HTTP_REQUEST_EVENT_READ                  = 0x00000400,
        MEDUSA_HTTP_REQUEST_EVENT_DISCONNECTED          = 0x00000800,
        MEDUSA_HTTP_REQUEST_EVENT_DESTROY               = 0x00001000
#define MEDUSA_HTTP_REQUEST_EVENT_RESOLVING             MEDUSA_HTTP_REQUEST_EVENT_RESOLVING
#define MEDUSA_HTTP_REQUEST_EVENT_RESOLVE_TIMEOUT       MEDUSA_HTTP_REQUEST_EVENT_RESOLVE_TIMEOUT
#define MEDUSA_HTTP_REQUEST_EVENT_RESOLVED              MEDUSA_HTTP_REQUEST_EVENT_RESOLVED
#define MEDUSA_HTTP_REQUEST_EVENT_CONNECTING            MEDUSA_HTTP_REQUEST_EVENT_CONNECTING
#define MEDUSA_HTTP_REQUEST_EVENT_CONNECT_TIMEOUT       MEDUSA_HTTP_REQUEST_EVENT_CONNECT_TIMEOUT
#define MEDUSA_HTTP_REQUEST_EVENT_CONNECTED             MEDUSA_HTTP_REQUEST_EVENT_CONNECTED
#define MEDUSA_HTTP_REQUEST_EVENT_WRITE_TIMEOUT         MEDUSA_HTTP_REQUEST_EVENT_WRITE_TIMEOUT
#define MEDUSA_HTTP_REQUEST_EVENT_WRITTEN               MEDUSA_HTTP_REQUEST_EVENT_WRITTEN
#define MEDUSA_HTTP_REQUEST_EVENT_WRITE_FINISHED        MEDUSA_HTTP_REQUEST_EVENT_WRITE_FINISHED
#define MEDUSA_HTTP_REQUEST_EVENT_READ_TIMEOUT          MEDUSA_HTTP_REQUEST_EVENT_READ_TIMEOUT
#define MEDUSA_HTTP_REQUEST_EVENT_READ                  MEDUSA_HTTP_REQUEST_EVENT_READ
#define MEDUSA_HTTP_REQUEST_EVENT_DISCONNECTED          MEDUSA_HTTP_REQUEST_EVENT_DISCONNECTED
#define MEDUSA_HTTP_REQUEST_EVENT_DESTROY               MEDUSA_HTTP_REQUEST_EVENT_DESTROY
};

enum {
        MEDUSA_HTTP_REQUEST_STATE_UNKNWON               = 0,
        MEDUSA_HTTP_REQUEST_STATE_DISCONNECTED          = 1,
        MEDUSA_HTTP_REQUEST_STATE_RESOLVING             = 2,
        MEDUSA_HTTP_REQUEST_STATE_RESOLVED              = 3,
        MEDUSA_HTTP_REQUEST_STATE_CONNECTING            = 4,
        MEDUSA_HTTP_REQUEST_STATE_CONNECTED             = 5
#define MEDUSA_HTTP_REQUEST_STATE_UNKNWON               MEDUSA_HTTP_REQUEST_STATE_UNKNWON
#define MEDUSA_HTTP_REQUEST_STATE_DISCONNECTED          MEDUSA_HTTP_REQUEST_STATE_DISCONNECTED
#define MEDUSA_HTTP_REQUEST_STATE_RESOLVING             MEDUSA_HTTP_REQUEST_STATE_RESOLVING
#define MEDUSA_HTTP_REQUEST_STATE_RESOLVED              MEDUSA_HTTP_REQUEST_STATE_RESOLVED
#define MEDUSA_HTTP_REQUEST_STATE_CONNECTING            MEDUSA_HTTP_REQUEST_STATE_CONNECTING
#define MEDUSA_HTTP_REQUEST_STATE_CONNECTED             MEDUSA_HTTP_REQUEST_STATE_CONNECTED
};

struct medusa_http_request_init_options {
        struct medusa_monitor *monitor;
        int (*onevent) (struct medusa_http_request *http_request, unsigned int events, void *context, ...);
        void *context;
};

#ifdef __cplusplus
extern "C"
{
#endif

int medusa_http_request_init_options_default (struct medusa_http_request_init_options *options);

struct medusa_http_request * medusa_http_request_create (struct medusa_monitor *monitor, int (*onevent) (struct medusa_http_request *http_request, unsigned int events, void *context, ...), void *context);
struct medusa_http_request * medusa_http_request_create_with_options (const struct medusa_http_request_init_options *options);
void medusa_http_request_destroy (struct medusa_http_request *http_request);

unsigned int medusa_http_request_get_state (const struct medusa_http_request *http_request);

int medusa_http_request_set_connect_timeout (struct medusa_http_request *http_request, double timeout);
double medusa_http_request_get_connect_timeout (const struct medusa_http_request *http_request);

int medusa_http_request_set_read_timeout (struct medusa_http_request *http_request, double timeout);
double medusa_http_request_get_read_timeout (const struct medusa_http_request *http_request);

int medusa_http_request_set_write_timeout (struct medusa_http_request *http_request, double timeout);
double medusa_http_request_get_write_timeout (const struct medusa_http_request *http_request);

int medusa_http_request_set_write_finished_timeout (struct medusa_http_request *http_request, double timeout);
double medusa_http_request_get_write_finished_timeout (const struct medusa_http_request *http_request);

int medusa_http_request_onevent (struct medusa_http_request *http_request, unsigned int events);
struct medusa_monitor * medusa_http_request_get_monitor (struct medusa_http_request *http_request);

#ifdef __cplusplus
}
#endif

#endif
