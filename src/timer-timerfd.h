
#if !defined(MEDUSA_TIMER_TIMERFD_H)
#define MEDUSA_TIMER_TIMERFD_H

struct medusa_timer_timerfd_init_options {

};

struct medusa_timer_backend * medusa_timer_timerfd_create (const struct medusa_timer_timerfd_init_options *options);

#endif
