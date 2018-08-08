
#if !defined(MEDUSA_POLL_SELECT_H)
#define MEDUSA_POLL_SELECT_H

struct medusa_monitor_select_init_options {

};

struct medusa_poll_backend * medusa_monitor_select_create (const struct medusa_monitor_select_init_options *options);

#endif
