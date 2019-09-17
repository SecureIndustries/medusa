
#if !defined(MEDUSA_HTTPREQUEST_PRIVATE_H)
#define MEDUSA_HTTPREQUEST_PRIVATE_H

struct medusa_httprequest;

int medusa_httprequest_init_unlocked (struct medusa_httprequest *httprequest, struct medusa_monitor *monitor, int (*onevent) (struct medusa_httprequest *httprequest, unsigned int events, void *context, void *param), void *context);
int medusa_httprequest_init_with_options_unlocked (struct medusa_httprequest *httprequest, const struct medusa_httprequest_init_options *options);

struct medusa_httprequest * medusa_httprequest_create_unlocked (struct medusa_monitor *monitor, int (*onevent) (struct medusa_httprequest *httprequest, unsigned int events, void *context, void *param), void *context);
struct medusa_httprequest * medusa_httprequest_create_with_options_unlocked (const struct medusa_httprequest_init_options *options);

void medusa_httprequest_uninit_unlocked (struct medusa_httprequest *httprequest);
void medusa_httprequest_destroy_unlocked (struct medusa_httprequest *httprequest);

unsigned int medusa_httprequest_get_state_unlocked (const struct medusa_httprequest *httprequest);

int medusa_httprequest_set_connect_timeout_unlocked (struct medusa_httprequest *httprequest, double timeout);
double medusa_httprequest_get_connect_timeout_unlocked (const struct medusa_httprequest *httprequest);

int medusa_httprequest_add_header_unlocked (struct medusa_httprequest *httprequest, const char *key, const char *value, ...);
int medusa_httprequest_add_vheader_unlocked (struct medusa_httprequest *httprequest, const char *key, const char *value, va_list va);

int medusa_httprequest_make_post_unlocked (struct medusa_httprequest *httprequest, const char *url, const void *data, int64_t length);

int medusa_httprequest_onevent_unlocked (struct medusa_httprequest *httprequest, unsigned int events, void *param);
struct medusa_monitor * medusa_httprequest_get_monitor_unlocked (struct medusa_httprequest *httprequest);

#endif
