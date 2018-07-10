
#include <time.h>
#include "time.h"

int clock_monotonic (struct medusa_timespec *timespec)
{
        struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
		return -1;
	}
	timespec->seconds = ts.tv_sec;
	timespec->nanoseconds = ts.tv_nsec;
	return 0;
}

int clock_monotonic_raw (struct medusa_timespec *timespec)
{
        struct timespec ts;
        if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) < 0) {
                return -1;
        }
        timespec->seconds = ts.tv_sec;
        timespec->nanoseconds = ts.tv_nsec;
        return 0;
}

int clock_boottime (struct medusa_timespec *timespec)
{
        struct timespec ts;
        if (clock_gettime(CLOCK_BOOTTIME, &ts) < 0) {
                return -1;
        }
        timespec->seconds = ts.tv_sec;
        timespec->nanoseconds = ts.tv_nsec;
        return 0;
}
