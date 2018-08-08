
#if !defined(MEDUSA_TIMER_PRIVATE_H)
#define MEDUSA_TIMER_PRIVATE_H

struct medusa_timer;

int medusa_timer_onevent (struct medusa_timer *timer, unsigned int events);
int medusa_timer_is_valid (const struct medusa_timer *timer);

#endif
