
#if !defined(MEDUSA_TIMER_STRUCT_H)
#define MEDUSA_TIMER_STRUCT_H

struct medusa_monitor;
struct medusa_timer_init_options;

struct medusa_timer {
        struct medusa_subject subject;
        unsigned int flags;
        struct timespec initial;
        struct timespec interval;
        int (*onevent) (struct medusa_timer *timer, unsigned int events, void *context, void *param);
        void *context;
        struct timespec _timespec;
        unsigned int _position;
        void *userdata;
};

int medusa_timer_init (struct medusa_timer *timer, struct medusa_monitor *monitor, int (*onevent) (struct medusa_timer *timer, unsigned int events, void *context, void *param), void *context);
int medusa_timer_init_with_options (struct medusa_timer *timer, const struct medusa_timer_init_options *options);
void medusa_timer_uninit (struct medusa_timer *timer);

#endif
