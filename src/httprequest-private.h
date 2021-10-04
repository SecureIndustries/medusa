
#if !defined(MEDUSA_HTTPREQUEST_PRIVATE_H)
#define MEDUSA_HTTPREQUEST_PRIVATE_H

struct medusa_httprequest;

struct medusa_httprequest * medusa_httprequest_create_unlocked (struct medusa_monitor *monitor, int (*onevent) (struct medusa_httprequest *httprequest, unsigned int events, void *context, void *param), void *context);
struct medusa_httprequest * medusa_httprequest_create_with_options_unlocked (const struct medusa_httprequest_init_options *options);
void medusa_httprequest_destroy_unlocked (struct medusa_httprequest *httprequest);

unsigned int medusa_httprequest_get_state_unlocked (const struct medusa_httprequest *httprequest);

int medusa_httprequest_set_resolve_timeout_unlocked (struct medusa_httprequest *httprequest, double timeout);
double medusa_httprequest_get_resolve_timeout_unlocked (const struct medusa_httprequest *httprequest);

int medusa_httprequest_set_connect_timeout_unlocked (struct medusa_httprequest *httprequest, double timeout);
double medusa_httprequest_get_connect_timeout_unlocked (const struct medusa_httprequest *httprequest);

int medusa_httprequest_set_read_timeout_unlocked (struct medusa_httprequest *httprequest, double timeout);
double medusa_httprequest_get_read_timeout_unlocked (const struct medusa_httprequest *httprequest);

int medusa_httprequest_set_method_unlocked (struct medusa_httprequest *httprequest, const char *method);

int medusa_httprequest_set_url_unlocked (struct medusa_httprequest *httprequest, const char *url, ...) __attribute__((format(printf, 2, 3)));
int medusa_httprequest_set_vurl_unlocked (struct medusa_httprequest *httprequest, const char *url, va_list va);
const char * medusa_httprequest_get_url_unlocked (const struct medusa_httprequest *httprequest);

int medusa_httprequest_add_header_unlocked (struct medusa_httprequest *httprequest, const char *key, const char *value, ...);
int medusa_httprequest_add_headerv_unlocked (struct medusa_httprequest *httprequest, const char *key, const char *value, va_list va);

int medusa_httprequest_add_raw_header_unlocked (struct medusa_httprequest *httprequest, const char *value, ...) __attribute__((format(printf, 2, 3)));
int medusa_httprequest_add_raw_headerv_unlocked (struct medusa_httprequest *httprequest, const char *value, va_list va);

int medusa_httprequest_make_post_unlocked (struct medusa_httprequest *httprequest, const void *data, int64_t length);
int medusa_httprequest_make_postf_unlocked (struct medusa_httprequest *httprequest, const char *data, ...) __attribute__((format(printf, 2, 3)));
int medusa_httprequest_make_postv_unlocked (struct medusa_httprequest *httprequest, const char *data, va_list va);

int medusa_httprequest_onevent_unlocked (struct medusa_httprequest *httprequest, unsigned int events, void *param);
struct medusa_monitor * medusa_httprequest_get_monitor_unlocked (struct medusa_httprequest *httprequest);

#endif
