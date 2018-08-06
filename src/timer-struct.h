
struct medusa_timer {
        struct medusa_subject subject;

        unsigned int flags;

        struct timespec initial;
        struct timespec interval;
        int (*onevent) (struct medusa_timer *timer, unsigned int events, void *context);
        void *context;

        struct timespec _timespec;
        unsigned int _position;
};

int medusa_timer_init (struct medusa_monitor *monitor, struct medusa_timer *timer, int (*onevent) (struct medusa_timer *timer, unsigned int events, void *context), void *context);
void medusa_timer_uninit (struct medusa_timer *timer);
