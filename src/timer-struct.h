
struct medusa_timer {
        struct medusa_subject subject;
        struct timespec initial;
        struct timespec interval;
        int single_shot;
        unsigned int type;
        int active;
        void (*timeout) (struct medusa_timer *timer);
        void *context;

        struct timespec _timespec;
        unsigned int _position;
};
