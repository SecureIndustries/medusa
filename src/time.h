
struct medusa_timespec {
        long long seconds;
        long long nanoseconds;
};

struct medusa_timerspec {
        struct medusa_timespec timespec;
        struct medusa_timespec interval;
};

#define medusa_timespec_isset(mts)      ((mts)->seconds || (mts)->nanoseconds)
#define medusa_timespec_clear(mts)      ((mts)->seconds = (mts)->nanoseconds = 0)

#define medusa_timespec_compare(a, b, CMP)                                    \
        (((a)->seconds == (b)->seconds) ?                                     \
                ((a)->nanoseconds CMP (b)->nanoseconds) :                     \
                ((a)->seconds CMP (b)->seconds))

#define medusa_timespec_add(a, b, result)                                     \
        do {                                                                  \
                (result)->seconds = (a)->seconds + (b)->seconds;              \
                (result)->nanoseconds = (a)->nanoseconds + (b)->nanoseconds;  \
                if ((result)->nanoseconds >= 1000000000) {                    \
                        ++(result)->seconds;                                  \
                        (result)->nanoseconds -= 1000000000;                  \
                }                                                             \
        } while (0)

#define medusa_timespec_sub(a, b, result)                                     \
        do {                                                                  \
                (result)->seconds = (a)->seconds - (b)->seconds;              \
                (result)->nanoseconds = (a)->nanoseconds - (b)->nanoseconds;  \
                if ((result)->nanoseconds < 0) {                              \
                        --(result)->seconds;                                  \
                        (result)->nanoseconds += 1000000000;                  \
                }                                                             \
        } while (0)
