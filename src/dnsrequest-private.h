
#if !defined(MEDUSA_DNSREQUEST_PRIVATE_H)
#define MEDUSA_DNSREQUEST_PRIVATE_H

struct medusa_dnsrequest;

int medusa_dnsrequest_init_unlocked (struct medusa_dnsrequest *dnsrequest, struct medusa_monitor *monitor, int (*onevent) (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *context, void *param), void *context);
int medusa_dnsrequest_init_with_options_unlocked (struct medusa_dnsrequest *dnsrequest, const struct medusa_dnsrequest_init_options *options);

struct medusa_dnsrequest * medusa_dnsrequest_create_lookup_unlocked (struct medusa_monitor *monitor, const char *nameserver, unsigned int type, const char *name, int (*onevent) (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *context, void *param), void *context);

struct medusa_dnsrequest * medusa_dnsrequest_create_unlocked (struct medusa_monitor *monitor, int (*onevent) (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *context, void *param), void *context);
struct medusa_dnsrequest * medusa_dnsrequest_create_with_options_unlocked (const struct medusa_dnsrequest_init_options *options);

void medusa_dnsrequest_uninit_unlocked (struct medusa_dnsrequest *dnsrequest);
void medusa_dnsrequest_destroy_unlocked (struct medusa_dnsrequest *dnsrequest);

unsigned int medusa_dnsrequest_get_state_unlocked (const struct medusa_dnsrequest *dnsrequest);

int medusa_dnsrequest_set_connect_timeout_unlocked (struct medusa_dnsrequest *dnsrequest, double timeout);
double medusa_dnsrequest_get_connect_timeout_unlocked (const struct medusa_dnsrequest *dnsrequest);

int medusa_dnsrequest_set_read_timeout_unlocked (struct medusa_dnsrequest *dnsrequest, double timeout);
double medusa_dnsrequest_get_read_timeout_unlocked (const struct medusa_dnsrequest *dnsrequest);

int medusa_dnsrequest_set_nameserver_unlocked (struct medusa_dnsrequest *dnsrequest, const char *nameserver);
const char * medusa_dnsrequest_get_nameserver_unlocked (struct medusa_dnsrequest *dnsrequest);

int medusa_dnsrequest_set_type_unlocked (struct medusa_dnsrequest *dnsrequest, unsigned int type);
int medusa_dnsrequest_get_type_unlocked (struct medusa_dnsrequest *dnsrequest);

int medusa_dnsrequest_set_name_unlocked (struct medusa_dnsrequest *dnsrequest, const char *name);
const char * medusa_dnsrequest_get_name_unlocked (struct medusa_dnsrequest *dnsrequest);

int medusa_dnsrequest_lookup_unlocked (struct medusa_dnsrequest *dnsrequest);
int medusa_dnsrequest_cancel_unlocked (struct medusa_dnsrequest *dnsrequest);
int medusa_dnsrequest_abort_unlocked (struct medusa_dnsrequest *dnsrequest);

const struct medusa_dnsrequest_reply * medusa_dnsrequest_get_reply_unlocked (struct medusa_dnsrequest *dnsrequest);

int medusa_dnsrequest_lookup_unlocked (struct medusa_dnsrequest *dnsrequest);

int medusa_dnsrequest_onevent_unlocked (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *param);
struct medusa_monitor * medusa_dnsrequest_get_monitor_unlocked (struct medusa_dnsrequest *dnsrequest);

#endif
