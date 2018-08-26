
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "clock.h"
#include "error.h"
#include "pool.h"
#include "queue.h"
#include "monitor.h"
#include "monitor-private.h"
#include "subject-struct.h"
#include "timer-struct.h"
#include "timer-private.h"

#include "timer.h"

#define MEDUSA_TIMER_USE_POOL   1
#if defined(MEDUSA_TIMER_USE_POOL) && (MEDUSA_TIMER_USE_POOL == 1)
static struct medusa_pool *g_pool;
#endif

enum {
        MEDUSA_TIMER_FLAG_ENABLED       = 0x00000001,
        MEDUSA_TIMER_FLAG_SINGLE_SHOT   = 0x00000002,
        MEDUSA_TIMER_FLAG_AUTO_DESTROY  = 0x00000004,
        MEDUSA_TIMER_FLAG_NANOSECONDS   = 0x00000008,
        MEDUSA_TIMER_FLAG_MICROSECONDS  = 0x00000010,
        MEDUSA_TIMER_FLAG_MILLISECONDS  = 0x00000020,
        MEDUSA_TIMER_FLAG_SECONDS       = 0x00000040
#define MEDUSA_TIMER_FLAG_ENABLED       MEDUSA_TIMER_FLAG_ENABLED
#define MEDUSA_TIMER_FLAG_SINGLE_SHOT   MEDUSA_TIMER_FLAG_SINGLE_SHOT
#define MEDUSA_TIMER_FLAG_AUTO_DESTROY  MEDUSA_TIMER_FLAG_AUTO_DESTROY
#define MEDUSA_TIMER_FLAG_NANOSECONDS   MEDUSA_TIMER_FLAG_NANOSECONDS
#define MEDUSA_TIMER_FLAG_MICROSECONDS  MEDUSA_TIMER_FLAG_MICROSECONDS
#define MEDUSA_TIMER_FLAG_MILLISECONDS  MEDUSA_TIMER_FLAG_MILLISECONDS
#define MEDUSA_TIMER_FLAG_SECONDS       MEDUSA_TIMER_FLAG_SECONDS
};

__attribute__ ((visibility ("default"))) int medusa_timer_init (struct medusa_timer *timer, struct medusa_monitor *monitor, int (*onevent) (struct medusa_timer *timer, unsigned int events, void *context, ...), void *context)
{
        int rc;
        struct medusa_timer_init_options options;
        rc = medusa_timer_init_options_default(&options);
        if (rc < 0) {
                return rc;
        }
        options.monitor = monitor;
        options.onevent = onevent;
        options.context = context;
        return medusa_timer_init_with_options(timer, &options);
}

__attribute__ ((visibility ("default"))) int medusa_timer_init_with_options (struct medusa_timer *timer, const struct medusa_timer_init_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                return -EINVAL;
        }
        memset(timer, 0, sizeof(struct medusa_timer));
        timer->onevent = options->onevent;
        timer->context = options->context;
        timer->flags |= MEDUSA_TIMER_FLAG_MILLISECONDS;
        medusa_timespec_clear(&timer->initial);
        medusa_timespec_clear(&timer->interval);
        timer->subject.flags = MEDUSA_SUBJECT_TYPE_TIMER;
        timer->subject.monitor = NULL;
        return medusa_monitor_add(options->monitor, &timer->subject);
}

__attribute__ ((visibility ("default"))) void medusa_timer_uninit (struct medusa_timer *timer)
{
        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                return;
        }
        if ((timer->subject.flags & MEDUSA_SUBJECT_TYPE_TIMER) == 0) {
                return;
        }
        if (timer->subject.monitor != NULL) {
                medusa_monitor_del(&timer->subject);
        } else {
                medusa_timer_onevent(timer, MEDUSA_TIMER_EVENT_DESTROY);
        }
}

__attribute__ ((visibility ("default"))) int medusa_timer_init_options_default (struct medusa_timer_init_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_timer_init_options));
        options->resolution = MEDUSA_TIMER_RESOLUTION_DEFAULT;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_timer_create_singleshot (struct medusa_monitor *monitor, double interval, int (*onevent) (struct medusa_timer *timer, unsigned int events, void *context, ...), void *context)
{
        struct timespec timespec;
        if (monitor == NULL) {
                return -EINVAL;
        }
        if (interval < 0) {
                return -EINVAL;
        }
        if (onevent == NULL) {
                return -EINVAL;
        }
        timespec.tv_sec = (long long) interval;
        timespec.tv_nsec = (long long) ((interval - timespec.tv_sec) * 1e9);
        return medusa_timer_create_singleshot_timespec(monitor, &timespec, onevent, context);
}

__attribute__ ((visibility ("default"))) int medusa_timer_create_singleshot_timeval (struct medusa_monitor *monitor, const struct timeval *timeval, int (*onevent) (struct medusa_timer *timer, unsigned int events, void *context, ...), void *context)
{
        struct timespec timespec;
        if (monitor == NULL) {
                return -EINVAL;
        }
        if (timeval == NULL) {
                return -EINVAL;
        }
        if (onevent == NULL) {
                return -EINVAL;
        }
        timespec.tv_sec = timeval->tv_sec;
        timespec.tv_nsec = timeval->tv_usec * 1e3;
        return medusa_timer_create_singleshot_timespec(monitor, &timespec, onevent, context);
}

__attribute__ ((visibility ("default"))) int medusa_timer_create_singleshot_timespec (struct medusa_monitor *monitor, const struct timespec *timespec, int (*onevent) (struct medusa_timer *timer, unsigned int events, void *context, ...), void *context)
{
        int rc;
        struct medusa_timer *timer;
        if (monitor == NULL) {
                return -EINVAL;
        }
        if (timespec == NULL) {
                return -EINVAL;
        }
        if (onevent == NULL) {
                return -EINVAL;
        }
        timer = medusa_timer_create(monitor, onevent, context);
        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                return -EIO;
        }
        rc = medusa_timer_set_singleshot(timer, 1);
        if (rc < 0) {
                medusa_timer_destroy(timer);
                return rc;
        }
        rc = medusa_timer_set_interval_timespec(timer, timespec);
        if (rc < 0) {
                medusa_timer_destroy(timer);
                return rc;
        }
        rc = medusa_timer_set_enabled(timer, 1);
        if (rc < 0) {
                medusa_timer_destroy(timer);
                return rc;
        }
        timer->flags |= MEDUSA_TIMER_FLAG_AUTO_DESTROY;
        return 0;
}

__attribute__ ((visibility ("default"))) struct medusa_timer * medusa_timer_create (struct medusa_monitor *monitor, int (*onevent) (struct medusa_timer *timer, unsigned int events, void *context, ...), void *context)
{
        int rc;
        struct medusa_timer_init_options options;
        rc = medusa_timer_init_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.monitor = monitor;
        options.onevent = onevent;
        options.context = context;
        return medusa_timer_create_with_options(&options);
}

__attribute__ ((visibility ("default"))) struct medusa_timer * medusa_timer_create_with_options (const struct medusa_timer_init_options *options)
{
        int rc;
        struct medusa_timer *timer;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
#if defined(MEDUSA_TIMER_USE_POOL) && (MEDUSA_TIMER_USE_POOL == 1)
        timer = medusa_pool_malloc(g_pool);
#else
        timer = malloc(sizeof(struct medusa_timer));
#endif
        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        rc = medusa_timer_init_with_options(timer, options);
        if (rc < 0) {
                medusa_timer_destroy(timer);
                return MEDUSA_ERR_PTR(rc);
        }
        timer->subject.flags |= MEDUSA_SUBJECT_FLAG_ALLOC;
        return timer;
}

__attribute__ ((visibility ("default"))) void medusa_timer_destroy (struct medusa_timer *timer)
{
        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                return;
        }
        medusa_timer_uninit(timer);
}

__attribute__ ((visibility ("default"))) int medusa_timer_set_initial (struct medusa_timer *timer, double initial)
{
        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                return -EINVAL;
        }
        if (initial < 0) {
                return -EINVAL;
        }
        timer->initial.tv_sec = (long long) initial;
        timer->initial.tv_nsec = (long long) ((initial - timer->initial.tv_sec) * 1e9);
        if (timer->subject.monitor != NULL) {
                return medusa_monitor_mod(&timer->subject);
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_timer_set_initial_timeval (struct medusa_timer *timer, const struct timeval *timeval)
{
        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(timeval)) {
                return -EINVAL;
        }
        timer->initial.tv_sec = timeval->tv_sec;
        timer->initial.tv_nsec = timeval->tv_usec * 1e3;
        if (timer->subject.monitor != NULL) {
                return medusa_monitor_mod(&timer->subject);
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_timer_set_initial_timespec (struct medusa_timer *timer, const struct timespec *timespec)
{
        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(timespec)) {
                return -EINVAL;
        }
        timer->initial.tv_sec = timespec->tv_sec;
        timer->initial.tv_nsec = timespec->tv_nsec;
        if (timer->subject.monitor != NULL) {
                return medusa_monitor_mod(&timer->subject);
        }
        return 0;
}

__attribute__ ((visibility ("default"))) double medusa_timer_get_initial (const struct medusa_timer *timer)
{
        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                return -EINVAL;
        }
        return timer->initial.tv_sec + timer->initial.tv_nsec * 1e-9;
}

__attribute__ ((visibility ("default"))) int medusa_timer_set_interval (struct medusa_timer *timer, double interval)
{
        struct timespec timespec;
        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                return -EINVAL;
        }
        if (interval < 0) {
                return -EINVAL;
        }
        timespec.tv_sec = (long long) interval;
        timespec.tv_nsec = (long long) ((interval - timespec.tv_sec) * 1e9);
        return medusa_timer_set_interval_timespec(timer, &timespec);
}

__attribute__ ((visibility ("default"))) int medusa_timer_set_interval_timeval (struct medusa_timer *timer, const struct timeval *timeval)
{
        struct timespec timespec;
        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(timeval)) {
                return -EINVAL;
        }
        timespec.tv_sec = timeval->tv_sec;
        timespec.tv_nsec = timeval->tv_usec * 1e3;
        return medusa_timer_set_interval_timespec(timer, &timespec);
}

__attribute__ ((visibility ("default"))) int medusa_timer_set_interval_timespec (struct medusa_timer *timer, const struct timespec *timespec)
{
        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(timespec)) {
                return -EINVAL;
        }
        timer->interval.tv_sec = timespec->tv_sec;
        timer->interval.tv_nsec = timespec->tv_nsec;
        if (!medusa_timespec_isset(&timer->interval)) {
                timer->interval.tv_nsec = 1;
        }
        if (timer->subject.monitor != NULL) {
                return medusa_monitor_mod(&timer->subject);
        }
        return 0;
}

__attribute__ ((visibility ("default"))) double medusa_timer_get_interval (const struct medusa_timer *timer)
{
        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                return -EINVAL;
        }
        return timer->interval.tv_sec + timer->interval.tv_nsec * 1e-9;
}

__attribute__ ((visibility ("default"))) double medusa_timer_get_remaining_time (const struct medusa_timer *timer)
{
        int rc;
        struct timespec rem;
        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                return -EINVAL;
        }
        if (!medusa_timer_get_enabled(timer)) {
                return -EAGAIN;
        }
        rc = medusa_timer_get_remaining_timespec(timer, &rem);
        if (rc < 0) {
                return rc;
        }
        return rem.tv_sec + rem.tv_nsec * 1e-9;
}

__attribute__ ((visibility ("default"))) int medusa_timer_get_remaining_timeval (const struct medusa_timer *timer, struct timeval *timeval)
{
        int rc;
        struct timespec rem;
        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                return -EINVAL;
        }
        if (!medusa_timer_get_enabled(timer)) {
                return -EAGAIN;
        }
        rc = medusa_timer_get_remaining_timespec(timer, &rem);
        if (rc < 0) {
                return rc;
        }
        timeval->tv_sec = rem.tv_sec;
        timeval->tv_usec = (rem.tv_nsec + 500) / 1000;
        if (timeval->tv_usec >= 1000000) {
                timeval->tv_sec++;
                timeval->tv_usec -= 1000000;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_timer_get_remaining_timespec (const struct medusa_timer *timer, struct timespec *timespec)
{
        int rc;
        struct timespec now;
        struct timespec rem;
        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                return -EINVAL;
        }
        if (!medusa_timer_get_enabled(timer)) {
                return -EAGAIN;
        }
        rc = medusa_clock_monotonic(&now);
        if (rc < 0) {
                return rc;
        }
        if (!medusa_timespec_compare(&timer->_timespec, &now, >)) {
                medusa_timespec_clear(timespec);
                return 0;
        }
        medusa_timespec_sub(&timer->_timespec, &now, &rem);
        timespec->tv_sec = rem.tv_sec;
        timespec->tv_nsec = rem.tv_nsec;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_timer_set_singleshot (struct medusa_timer *timer, int singleshot)
{
        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                return -EINVAL;
        }
        if (singleshot) {
                timer->flags |= MEDUSA_TIMER_FLAG_SINGLE_SHOT;
        } else {
                timer->flags &= ~MEDUSA_TIMER_FLAG_SINGLE_SHOT;
        }
        if (timer->subject.monitor != NULL) {
                return medusa_monitor_mod(&timer->subject);
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_timer_get_singleshot (const struct medusa_timer *timer)
{
        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                return -EINVAL;
        }
        return !!(timer->flags & MEDUSA_TIMER_FLAG_SINGLE_SHOT);
}

__attribute__ ((visibility ("default"))) int medusa_timer_set_resolution (struct medusa_timer *timer, unsigned int resolution)
{
        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                return -EINVAL;
        }
        timer->flags &= ~MEDUSA_TIMER_FLAG_NANOSECONDS;
        timer->flags &= ~MEDUSA_TIMER_FLAG_MICROSECONDS;
        timer->flags &= ~MEDUSA_TIMER_FLAG_MILLISECONDS;
        timer->flags &= ~MEDUSA_TIMER_FLAG_SECONDS;
        if (resolution == MEDUSA_TIMER_RESOLUTION_NANOSECOMDS) {
                timer->flags |= MEDUSA_TIMER_FLAG_NANOSECONDS;
        } else if (resolution == MEDUSA_TIMER_RESOLUTION_MICROSECONDS) {
                timer->flags |= MEDUSA_TIMER_FLAG_MICROSECONDS;
        } else if (resolution == MEDUSA_TIMER_RESOLUTION_MILLISECONDS) {
                timer->flags |= MEDUSA_TIMER_FLAG_MILLISECONDS;
        } else if (resolution == MEDUSA_TIMER_RESOLUTION_SECONDS) {
                timer->flags |= MEDUSA_TIMER_FLAG_SECONDS;
        } else {
                timer->flags |= MEDUSA_TIMER_FLAG_MILLISECONDS;
        }
        if (timer->subject.monitor != NULL) {
                return medusa_monitor_mod(&timer->subject);
        }
        return 0;
}

__attribute__ ((visibility ("default"))) unsigned int medusa_timer_get_resolution (const struct medusa_timer *timer)
{
        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                return -EINVAL;
        }
        if (timer->flags & MEDUSA_TIMER_FLAG_NANOSECONDS) {
                return MEDUSA_TIMER_RESOLUTION_NANOSECOMDS;
        } else if (timer->flags & MEDUSA_TIMER_FLAG_MICROSECONDS) {
                return MEDUSA_TIMER_RESOLUTION_MICROSECONDS;
        } else if (timer->flags & MEDUSA_TIMER_FLAG_MILLISECONDS) {
                return MEDUSA_TIMER_RESOLUTION_MILLISECONDS;
        } else if (timer->flags & MEDUSA_TIMER_FLAG_SECONDS) {
                return MEDUSA_TIMER_RESOLUTION_SECONDS;
        }
        return MEDUSA_TIMER_RESOLUTION_DEFAULT;
}

__attribute__ ((visibility ("default"))) int medusa_timer_set_enabled (struct medusa_timer *timer, int enabled)
{
        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                return -EINVAL;
        }
        if (enabled) {
                timer->flags |= MEDUSA_TIMER_FLAG_ENABLED;
        } else {
                timer->flags &= ~MEDUSA_TIMER_FLAG_ENABLED;
        }
        if (timer->subject.monitor != NULL) {
                return medusa_monitor_mod(&timer->subject);
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_timer_get_enabled (const struct medusa_timer *timer)
{
        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                return -EINVAL;
        }
        return !!(timer->flags & MEDUSA_TIMER_FLAG_ENABLED);
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_timer_get_monitor (struct medusa_timer *timer)
{
        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return timer->subject.monitor;
}

int medusa_timer_onevent (struct medusa_timer *timer, unsigned int events)
{
        int rc;
        unsigned int type;
        rc = 0;
        type = timer->subject.flags & MEDUSA_SUBJECT_TYPE_MASK;
        if (timer->onevent != NULL) {
                rc = timer->onevent(timer, events, timer->context);
        }
        if (events & MEDUSA_TIMER_EVENT_TIMEOUT) {
                if (timer->flags & MEDUSA_TIMER_FLAG_AUTO_DESTROY) {
                        medusa_timer_destroy(timer);
                }
        }
        if (events & MEDUSA_TIMER_EVENT_DESTROY) {
                if (type == MEDUSA_SUBJECT_TYPE_TIMER) {
                        if (timer->subject.flags & MEDUSA_SUBJECT_FLAG_ALLOC) {
#if defined(MEDUSA_TIMER_USE_POOL) && (MEDUSA_TIMER_USE_POOL == 1)
                                medusa_pool_free(timer);
#else
                                free(timer);
#endif
                        } else {
                                memset(timer, 0, sizeof(struct medusa_timer));
                        }
                }
        }
        return rc;
}

int medusa_timer_is_valid (const struct medusa_timer *timer)
{
        if (!medusa_timespec_isset(&timer->initial) &&
            !medusa_timespec_isset(&timer->interval)) {
                return 0;
        }
        if ((timer->flags & MEDUSA_TIMER_FLAG_ENABLED) == 0) {
                return 0;
        }
        return 1;
}

__attribute__ ((constructor)) static void timer_constructor (void)
{
#if defined(MEDUSA_TIMER_USE_POOL) && (MEDUSA_TIMER_USE_POOL == 1)
        g_pool = medusa_pool_create("medusa-timer", sizeof(struct medusa_timer), 0, 0, MEDUSA_POOL_FLAG_DEFAULT | MEDUSA_POOL_FLAG_THREAD_SAFE, NULL, NULL, NULL);
#endif
}

__attribute__ ((destructor)) static void timer_destructor (void)
{
#if defined(MEDUSA_TIMER_USE_POOL) && (MEDUSA_TIMER_USE_POOL == 1)
        if (g_pool != NULL) {
                medusa_pool_destroy(g_pool);
        }
#endif
}
