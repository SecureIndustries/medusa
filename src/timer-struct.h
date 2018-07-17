
struct medusa_timer {
        struct medusa_subject subject;
        struct timespec initial;
        struct timespec interval;
        int single_shot;
        unsigned int type;
        int enabled;
        int (*callback) (struct medusa_timer *timer, unsigned int events, void *context);
        void *context;

        struct timespec _timespec;
        unsigned int _position;
};

int medusa_timer_init (struct medusa_monitor *monitor, struct medusa_timer *timer);
void medusa_timer_uninit (struct medusa_timer *timer);
