
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "clock.h"
#include "pool.h"
#include "queue.h"
#include "time.h"
#include "monitor.h"
#include "monitor-private.h"
#include "subject-struct.h"
#include "timer-struct.h"

#include "timer.h"

#define MEDUSA_TIMER_USE_POOL   1
#if defined(MEDUSA_TIMER_USE_POOL) && (MEDUSA_TIMER_USE_POOL == 1)
static struct pool *g_pool;
#endif

__attribute__ ((visibility ("default"))) int medusa_timer_init (struct medusa_monitor *monitor, struct medusa_timer *timer, int (*onevent) (struct medusa_timer *timer, unsigned int events, void *context), void *context)
{
        if (monitor == NULL) {
                return -1;
        }
        if (timer == NULL) {
                return -1;
        }
        if (onevent == NULL) {
                return -1;
        }
        memset(timer, 0, sizeof(struct medusa_timer));
        timer->onevent = onevent;
        timer->context = context;
        timer->flags |= MEDUSA_TIMER_FLAG_MILLISECONDS;
        medusa_timespec_clear(&timer->initial);
        medusa_timespec_clear(&timer->interval);
        timer->subject.flags = MEDUSA_SUBJECT_FLAG_TIMER;
        timer->subject.monitor = NULL;
        return medusa_monitor_add(monitor, &timer->subject);
}

__attribute__ ((visibility ("default"))) void medusa_timer_uninit (struct medusa_timer *timer)
{
        if (timer == NULL) {
                return;
        }
        if ((timer->subject.flags & MEDUSA_SUBJECT_FLAG_TIMER) == 0) {
             return;
        }
        if (timer->subject.monitor != NULL) {
                medusa_monitor_del(&timer->subject);
        } else {
                medusa_timer_onevent(timer, MEDUSA_TIMER_EVENT_DESTROY);
        }
}

__attribute__ ((visibility ("default"))) struct medusa_timer * medusa_timer_create (struct medusa_monitor *monitor, int (*onevent) (struct medusa_timer *timer, unsigned int events, void *context), void *context)
{
        int rc;
        struct medusa_timer *timer;
        timer = NULL;
        if (monitor == NULL) {
                goto bail;
        }
        if (onevent == NULL) {
                goto bail;
        }
#if defined(MEDUSA_TIMER_USE_POOL) && (MEDUSA_TIMER_USE_POOL == 1)
        timer = pool_malloc(g_pool);
#else
        timer = malloc(sizeof(struct medusa_timer));
#endif
        if (timer == NULL) {
                goto bail;
        }
        rc = medusa_timer_init(monitor, timer, onevent, context);
        if (rc != 0) {
                goto bail;
        }
        timer->subject.flags |= MEDUSA_SUBJECT_FLAG_ALLOC;
        return timer;
bail:   if (timer != NULL) {
                medusa_timer_destroy(timer);
        }
        return NULL;
}

__attribute__ ((visibility ("default"))) void medusa_timer_destroy (struct medusa_timer *timer)
{
        medusa_timer_uninit(timer);
}

__attribute__ ((visibility ("default"))) int medusa_timer_set_initial (struct medusa_timer *timer, double initial)
{
        timer->initial.tv_sec = (long long) initial;
        timer->initial.tv_nsec = (long long) ((initial - timer->initial.tv_sec) * 1e9);
        return medusa_monitor_mod(&timer->subject);
}

__attribute__ ((visibility ("default"))) double medusa_timer_get_initial (const struct medusa_timer *timer)
{
        return timer->initial.tv_sec + timer->initial.tv_nsec * 1e-9;
}

__attribute__ ((visibility ("default"))) int medusa_timer_set_interval (struct medusa_timer *timer, double interval)
{
        timer->interval.tv_sec = (long long) interval;
        timer->interval.tv_nsec = (long long) ((interval - timer->interval.tv_sec) * 1e9);
        return medusa_monitor_mod(&timer->subject);
}

__attribute__ ((visibility ("default"))) double medusa_timer_get_interval (const struct medusa_timer *timer)
{
        return timer->interval.tv_sec + timer->interval.tv_nsec * 1e-9;
}

__attribute__ ((visibility ("default"))) double medusa_timer_get_remaining_time (const struct medusa_timer *timer)
{
        struct timespec now;
        struct timespec rem;
        medusa_clock_monotonic(&now);
        medusa_timespec_sub(&timer->_timespec, &now, &rem);
        return rem.tv_sec + rem.tv_nsec + 1e-9;
}

__attribute__ ((visibility ("default"))) int medusa_timer_set_single_shot (struct medusa_timer *timer, int single_shot)
{
        if (single_shot) {
                timer->flags |= MEDUSA_TIMER_FLAG_SINGLE_SHOT;
        } else {
                timer->flags &= ~MEDUSA_TIMER_FLAG_SINGLE_SHOT;
        }
        return medusa_monitor_mod(&timer->subject);
}

__attribute__ ((visibility ("default"))) int medusa_timer_get_single_shot (const struct medusa_timer *timer)
{
        return !!(timer->flags & MEDUSA_TIMER_FLAG_SINGLE_SHOT);
}

__attribute__ ((visibility ("default"))) int medusa_timer_set_resolution (struct medusa_timer *timer, unsigned int resolution)
{
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
        return medusa_monitor_mod(&timer->subject);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_timer_get_resolution (const struct medusa_timer *timer)
{
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

__attribute__ ((visibility ("default"))) void * medusa_timer_get_timeout_context (const struct medusa_timer *timer)
{
        return timer->context;
}

__attribute__ ((visibility ("default"))) int medusa_timer_set_enabled (struct medusa_timer *timer, int enabled)
{
        if (enabled) {
                timer->flags |= MEDUSA_TIMER_FLAG_ENABLED;
        } else {
                timer->flags &= ~MEDUSA_TIMER_FLAG_ENABLED;
        }
        return medusa_monitor_mod(&timer->subject);
}

__attribute__ ((visibility ("default"))) int medusa_timer_get_enabled (const struct medusa_timer *timer)
{
        return !!(timer->flags & MEDUSA_TIMER_FLAG_ENABLED);
}

__attribute__ ((visibility ("default"))) int medusa_timer_start (struct medusa_timer *timer)
{
        return medusa_timer_set_enabled(timer, 1);
}

__attribute__ ((visibility ("default"))) int medusa_timer_stop (struct medusa_timer *timer)
{
        return medusa_timer_set_enabled(timer, 0);
}

__attribute__ ((visibility ("default"))) int medusa_timer_onevent (struct medusa_timer *timer, unsigned int events)
{
        int rc;
        rc = 0;
        if (timer->onevent != NULL) {
                rc = timer->onevent(timer, events, timer->context);
        }
        if ((rc != 1) &&
            (events & MEDUSA_TIMER_EVENT_DESTROY)) {
                if (timer->subject.flags & MEDUSA_SUBJECT_FLAG_ALLOC) {
#if defined(MEDUSA_TIMER_USE_POOL) && (MEDUSA_TIMER_USE_POOL == 1)
                        pool_free(timer);
#else
                        free(timer);
#endif
                } else {
                        memset(timer, 0, sizeof(struct medusa_timer));
                }
        }
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_timer_is_valid (const struct medusa_timer *timer)
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

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_timer_get_monitor (struct medusa_timer *timer)
{
        return timer->subject.monitor;
}

__attribute__ ((constructor)) static void timer_constructor (void)
{
#if defined(MEDUSA_TIMER_USE_POOL) && (MEDUSA_TIMER_USE_POOL == 1)
        g_pool = pool_create("medusa-timer", sizeof(struct medusa_timer), 0, 0, POOL_FLAG_DEFAULT, NULL, NULL, NULL);
#endif
}

__attribute__ ((destructor)) static void timer_destructor (void)
{
#if defined(MEDUSA_TIMER_USE_POOL) && (MEDUSA_TIMER_USE_POOL == 1)
        if (g_pool != NULL) {
                pool_destroy(g_pool);
        }
#endif
}
