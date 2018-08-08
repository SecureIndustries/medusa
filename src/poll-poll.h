
#if !defined(MEDUSA_POLL_POLL_H)
#define MEDUSA_POLL_POLL_H

struct medusa_monitor_poll_init_options {

};

struct medusa_poll_backend * medusa_monitor_poll_create (const struct medusa_monitor_poll_init_options *options);

#endif
