
#if !defined(MEDUSA_CLOCK_H)
#define MEDUSA_CLOCK_H

struct timeval;
struct timespec;

#define medusa_timeval_isset(mts)      ((mts)->tv_sec || (mts)->tv_usec)
#define medusa_timeval_clear(mts)      ((mts)->tv_sec = (mts)->tv_usec = 0)

#define medusa_timeval_compare(a, b, CMP)                               \
        (((a)->tv_sec == (b)->tv_sec) ?                                 \
                ((a)->tv_usec CMP (b)->tv_usec) :                       \
                ((a)->tv_sec CMP (b)->tv_sec))

#define medusa_timeval_add(a, b, result)                                \
        do {                                                            \
                (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;           \
                (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;        \
                if ((result)->tv_usec >= 1000000) {                     \
                        ++(result)->tv_sec;                             \
                        (result)->tv_usec -= 1000000;                   \
                }                                                       \
        } while (0)

#define medusa_timeval_sub(a, b, result)                                \
        do {                                                            \
                (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;           \
                (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;        \
                if ((result)->tv_usec < 0) {                            \
                        --(result)->tv_sec;                             \
                        (result)->tv_usec += 1000000;                   \
                }                                                       \
        } while (0)


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

#ifdef __cplusplus
extern "C"
{
#endif

int medusa_clock_realtime (struct timespec *timespec);
int medusa_clock_monotonic (struct timespec *timespec);
int medusa_clock_monotonic_raw (struct timespec *timespec);

#ifdef __cplusplus
}
#endif

#endif
