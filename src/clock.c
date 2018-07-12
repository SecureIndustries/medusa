
#include <time.h>
#include "time.h"

int clock_monotonic (struct timespec *timespec)
{
        return clock_gettime(CLOCK_MONOTONIC, timespec);
}

int clock_monotonic_raw (struct timespec *timespec)
{
        return clock_gettime(CLOCK_MONOTONIC_RAW, timespec);
}

int clock_boottime (struct timespec *timespec)
{
        return clock_gettime(CLOCK_BOOTTIME, timespec);
}
