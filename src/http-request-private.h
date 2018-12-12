
#if !defined(MEDUSA_HTTP_REQUEST_PRIVATE_H)
#define MEDUSA_HTTP_REQUEST_PRIVATE_H

struct medusa_http_request;

int medusa_http_request_init_unlocked (struct medusa_http_request *http_request, struct medusa_monitor *monitor, int (*onevent) (struct medusa_http_request *http_request, unsigned int events, void *context, ...), void *context);
int medusa_http_request_init_with_options_unlocked (struct medusa_http_request *http_request, const struct medusa_http_request_init_options *options);

struct medusa_http_request * medusa_http_request_create_unlocked (struct medusa_monitor *monitor, int (*onevent) (struct medusa_http_request *http_request, unsigned int events, void *context, ...), void *context);
struct medusa_http_request * medusa_http_request_create_with_options_unlocked (const struct medusa_http_request_init_options *options);

void medusa_http_request_uninit_unlocked (struct medusa_http_request *http_request);
void medusa_http_request_destroy_unlocked (struct medusa_http_request *http_request);

unsigned int medusa_http_request_get_state_unlocked (const struct medusa_http_request *http_request);

int medusa_http_request_set_connect_timeout_unlocked (struct medusa_http_request *http_request, double timeout);
double medusa_http_request_get_connect_timeout_unlocked (const struct medusa_http_request *http_request);

int medusa_http_request_set_read_timeout_unlocked (struct medusa_http_request *http_request, double timeout);
double medusa_http_request_get_read_timeout_unlocked (const struct medusa_http_request *http_request);

int medusa_http_request_onevent_unlocked (struct medusa_http_request *http_request, unsigned int events);
struct medusa_monitor * medusa_http_request_get_monitor_unlocked (struct medusa_http_request *http_request);

#endif
