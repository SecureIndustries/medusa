
#if !defined(MEDUSA_DNSREQUEST_PRIVATE_H)
#define MEDUSA_DNSREQUEST_PRIVATE_H

struct medusa_dnsrequest;

int medusa_dnsrequest_init_unlocked (struct medusa_dnsrequest *dnsrequest, struct medusa_monitor *monitor, int (*onevent) (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *context, void *param), void *context);
int medusa_dnsrequest_init_with_options_unlocked (struct medusa_dnsrequest *dnsrequest, const struct medusa_dnsrequest_init_options *options);

struct medusa_dnsrequest * medusa_dnsrequest_create_unlocked (struct medusa_monitor *monitor, int (*onevent) (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *context, void *param), void *context);
struct medusa_dnsrequest * medusa_dnsrequest_create_with_options_unlocked (const struct medusa_dnsrequest_init_options *options);

void medusa_dnsrequest_uninit_unlocked (struct medusa_dnsrequest *dnsrequest);
void medusa_dnsrequest_destroy_unlocked (struct medusa_dnsrequest *dnsrequest);

unsigned int medusa_dnsrequest_get_state_unlocked (const struct medusa_dnsrequest *dnsrequest);

int medusa_dnsrequest_set_connect_timeout_unlocked (struct medusa_dnsrequest *dnsrequest, double timeout);
double medusa_dnsrequest_get_connect_timeout_unlocked (const struct medusa_dnsrequest *dnsrequest);

int medusa_dnsrequest_set_method_unlocked (struct medusa_dnsrequest *dnsrequest, const char *method);
int medusa_dnsrequest_add_header_unlocked (struct medusa_dnsrequest *dnsrequest, const char *key, const char *value, ...);
int medusa_dnsrequest_add_vheader_unlocked (struct medusa_dnsrequest *dnsrequest, const char *key, const char *value, va_list va);

int medusa_dnsrequest_make_post_unlocked (struct medusa_dnsrequest *dnsrequest, const char *url, const void *data, int64_t length);

int medusa_dnsrequest_onevent_unlocked (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *param);
struct medusa_monitor * medusa_dnsrequest_get_monitor_unlocked (struct medusa_dnsrequest *dnsrequest);

#endif
