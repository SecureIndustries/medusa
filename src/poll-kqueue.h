
#if !defined(MEDUSA_POLL_KQUEUE_H)
#define MEDUSA_POLL_KQUEUE_H

struct medusa_monitor_kqueue_init_options {

};

struct medusa_poll_backend * medusa_monitor_kqueue_create (const struct medusa_monitor_kqueue_init_options *options);

#endif
