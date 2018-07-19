
struct timespec;

#define medusa_timespec_isset(mts)      ((mts)->tv_sec || (mts)->tv_nsec)
#define medusa_timespec_clear(mts)      ((mts)->tv_sec = (mts)->tv_nsec = 0)

#define medusa_timespec_compare(a, b, CMP)                              \
        (((a)->tv_sec == (b)->tv_sec) ?                                 \
                ((a)->tv_nsec CMP (b)->tv_nsec) :                       \
                ((a)->tv_sec CMP (b)->tv_sec))

#define medusa_timespec_add(a, b, result)                               \
        do {                                                            \
                (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;           \
                (result)->tv_nsec = (a)->tv_nsec + (b)->tv_nsec;        \
                if ((result)->tv_nsec >= 1000000000) {                  \
                        ++(result)->tv_sec;                             \
                        (result)->tv_nsec -= 1000000000;                \
                }                                                       \
        } while (0)

#define medusa_timespec_sub(a, b, result)                               \
        do {                                                            \
                (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;           \
                (result)->tv_nsec = (a)->tv_nsec - (b)->tv_nsec;        \
                if ((result)->tv_nsec < 0) {                            \
                        --(result)->tv_sec;                             \
                        (result)->tv_nsec += 1000000000;                \
                }                                                       \
        } while (0)

int medusa_clock_monotonic (struct timespec *timespec);
int medusa_clock_monotonic_raw (struct timespec *timespec);
int medusa_clock_monotonic_coarse (struct timespec *timespec);
