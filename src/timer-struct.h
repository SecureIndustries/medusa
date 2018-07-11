
struct medusa_timer {
        struct medusa_subject subject;
        struct medusa_timespec initial;
        struct medusa_timespec interval;
        int single_shot;
        unsigned int type;
        int active;
        void (*timeout) (struct medusa_timer *timer, void *context);
        void *context;

        struct medusa_timespec _timespec;
        unsigned int _position;
        int _fired;
};
