
#if !defined(MEDUSA_TIMER_PRIVATE_H)
#define MEDUSA_TIMER_PRIVATE_H

struct medusa_timer;

void medusa_timer_uninit_unlocked (struct medusa_timer *timer);
void medusa_timer_destroy_unlocked (struct medusa_timer *timer);

int medusa_timer_set_initial_unlocked (struct medusa_timer *timer, double initial);
int medusa_timer_set_initial_timeval_unlocked (struct medusa_timer *timer, const struct timeval *initial);
int medusa_timer_set_initial_timespec_unlocked (struct medusa_timer *timer, const struct timespec *initial);
double medusa_timer_get_initial_unlocked (const struct medusa_timer *timer);

int medusa_timer_set_interval_unlocked (struct medusa_timer *timer, double interval);
int medusa_timer_set_interval_timeval_unlocked (struct medusa_timer *timer, const struct timeval *interval);
int medusa_timer_set_interval_timespec_unlocked (struct medusa_timer *timer, const struct timespec *interval);
double medusa_timer_get_interval_unlocked (const struct medusa_timer *timer);

double medusa_timer_get_remaining_time_unlocked (const struct medusa_timer *timer);
int medusa_timer_get_remaining_timeval_unlocked (const struct medusa_timer *timer, struct timeval *timeval);
int medusa_timer_get_remaining_timespec_unlocked (const struct medusa_timer *timer, struct timespec *timespec);

int medusa_timer_set_singleshot_unlocked (struct medusa_timer *timer, int singleshot);
int medusa_timer_get_singleshot_unlocked (const struct medusa_timer *timer);

int medusa_timer_set_resolution_unlocked (struct medusa_timer *timer, unsigned int resolution);
unsigned int medusa_timer_get_resolution_unlocked (const struct medusa_timer *timer);

int medusa_timer_set_enabled_unlocked (struct medusa_timer *timer, int enabled);
int medusa_timer_get_enabled_unlocked (const struct medusa_timer *timer);

int medusa_timer_update_timespec_unlocked (struct medusa_timer *timer, struct timespec *now);

struct medusa_monitor * medusa_timer_get_monitor_unlocked (const struct medusa_timer *timer);

int medusa_timer_onevent_unlocked (struct medusa_timer *timer, unsigned int events);
int medusa_timer_is_valid_unlocked (const struct medusa_timer *timer);

#endif
