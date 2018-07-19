
#include <time.h>
#include "time.h"

int medusa_clock_monotonic (struct timespec *timespec)
{
        return clock_gettime(CLOCK_MONOTONIC, timespec);
}

int medusa_clock_monotonic_raw (struct timespec *timespec)
{
        return clock_gettime(CLOCK_MONOTONIC_RAW, timespec);
}

int medusa_clock_monotonic_coarse (struct timespec *timespec)
{
        return clock_gettime(CLOCK_MONOTONIC_COARSE, timespec);
}
