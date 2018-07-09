
struct medusa_timespec {
        unsigned long long seconds;
        unsigned long long nanoseconds;
};

struct medusa_timerspec {
        struct medusa_timespec timespec;
        struct medusa_timespec interval;
};
