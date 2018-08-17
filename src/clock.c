
#include <time.h>

__attribute__ ((visibility ("default"))) int medusa_clock_monotonic (struct timespec *timespec)
{
        return clock_gettime(CLOCK_MONOTONIC, timespec);
}

__attribute__ ((visibility ("default"))) int medusa_clock_monotonic_raw (struct timespec *timespec)
{
        return clock_gettime(CLOCK_MONOTONIC_RAW, timespec);
}
