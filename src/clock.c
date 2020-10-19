
#include <errno.h>
#include <time.h>

#include "error.h"

__attribute__ ((visibility ("default"))) int medusa_clock_realtime (struct timespec *timespec)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(timespec)) {
                return -EINVAL;
        }
        rc = clock_gettime(CLOCK_REALTIME, timespec);
        if (rc < 0) {
                return errno;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_clock_realtime_coarse (struct timespec *timespec)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(timespec)) {
                return -EINVAL;
        }
        rc = clock_gettime(CLOCK_REALTIME_COARSE, timespec);
        if (rc < 0) {
                return errno;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_clock_monotonic (struct timespec *timespec)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(timespec)) {
                return -EINVAL;
        }
        rc = clock_gettime(CLOCK_MONOTONIC, timespec);
        if (rc < 0) {
                return errno;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_clock_monotonic_raw (struct timespec *timespec)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(timespec)) {
                return -EINVAL;
        }
        rc = clock_gettime(CLOCK_MONOTONIC_RAW, timespec);
        if (rc < 0) {
                return errno;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_clock_monotonic_coarse (struct timespec *timespec)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(timespec)) {
                return -EINVAL;
        }
        rc = clock_gettime(CLOCK_MONOTONIC_COARSE, timespec);
        if (rc < 0) {
                return errno;
        }
        return 0;
}
