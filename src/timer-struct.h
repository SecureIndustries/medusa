
struct medusa_timer {
        struct medusa_subject subject;
        struct timespec initial;
        struct timespec interval;
        int single_shot;
        unsigned int type;
        int active;
        int (*callback) (struct medusa_timer *timer, unsigned int events, void *context);
        void *context;

        struct timespec _timespec;
        unsigned int _position;
};
