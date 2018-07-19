
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "clock.h"
#include "queue.h"
#include "time.h"
#include "subject.h"
#include "monitor.h"
#include "subject-struct.h"
#include "timer-struct.h"

#include "timer.h"

static int timer_subject_event (struct medusa_subject *subject, unsigned int events)
{
        struct medusa_timer *timer = (struct medusa_timer *) subject;
        if (timer->callback != NULL) {
                return timer->callback(timer, events, timer->context);
        }
        return 0;
}

static int timer_init (struct medusa_monitor *monitor, struct medusa_timer *timer, void (*destroy) (struct medusa_timer *timer))
{
        memset(timer, 0, sizeof(struct medusa_timer));
        timer->flags |= MEDUSA_TIMER_FLAG_COARSE;
        medusa_timespec_clear(&timer->initial);
        medusa_timespec_clear(&timer->interval);
        timer->subject.event = timer_subject_event;
        timer->subject.destroy = (void (*) (struct medusa_subject *)) destroy;
        timer->subject.flags = MEDUSA_SUBJECT_FLAG_TIMER;
        timer->subject.monitor = NULL;
        return medusa_subject_add(monitor, &timer->subject);
}

static void timer_uninit (struct medusa_timer *timer)
{
        memset(timer, 0, sizeof(struct medusa_timer));
}

static void timer_destroy (struct medusa_timer *timer)
{
        timer_uninit(timer);
        free(timer);
}

__attribute__ ((visibility ("default"))) void medusa_timer_uninit (struct medusa_timer *timer)
{
        medusa_subject_del(&timer->subject);
}

__attribute__ ((visibility ("default"))) int medusa_timer_init (struct medusa_monitor *monitor, struct medusa_timer *timer)
{
        return timer_init(monitor, timer, timer_uninit);
}

__attribute__ ((visibility ("default"))) struct medusa_timer * medusa_timer_create (struct medusa_monitor *monitor)
{
        int rc;
        struct medusa_timer *timer;
        timer = malloc(sizeof(struct medusa_timer));
        if (timer == NULL) {
                goto bail;
        }
        rc = timer_init(monitor, timer, timer_destroy);
        if (rc != 0) {
                goto bail;
        }
        return timer;
bail:   if (timer != NULL) {
                medusa_timer_destroy(timer);
        }
        return NULL;
}

__attribute__ ((visibility ("default"))) void medusa_timer_destroy (struct medusa_timer *timer)
{
        medusa_subject_del(&timer->subject);
}

__attribute__ ((visibility ("default"))) int medusa_timer_set_initial (struct medusa_timer *timer, double initial)
{
        timer->initial.tv_sec = (long long) initial;
        timer->initial.tv_nsec = (long long) ((initial - timer->initial.tv_sec) * 1e9);
        return medusa_subject_mod(&timer->subject);
}

__attribute__ ((visibility ("default"))) double medusa_timer_get_initial (const struct medusa_timer *timer)
{
        return timer->initial.tv_sec + timer->initial.tv_nsec * 1e-9;
}

__attribute__ ((visibility ("default"))) int medusa_timer_set_interval (struct medusa_timer *timer, double interval)
{
        timer->interval.tv_sec = (long long) interval;
        timer->interval.tv_nsec = (long long) ((interval - timer->interval.tv_sec) * 1e9);
        return medusa_subject_mod(&timer->subject);
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
        return medusa_subject_mod(&timer->subject);
}

__attribute__ ((visibility ("default"))) int medusa_timer_get_single_shot (const struct medusa_timer *timer)
{
        return !!(timer->flags & MEDUSA_TIMER_FLAG_SINGLE_SHOT);
}

__attribute__ ((visibility ("default"))) int medusa_timer_set_type (struct medusa_timer *timer, unsigned int type)
{
        timer->flags &= ~MEDUSA_TIMER_FLAG_PRECISE;
        timer->flags &= ~MEDUSA_TIMER_FLAG_COARSE;
        if (type == MEDUSA_TIMER_TYPE_PRECISE) {
                timer->flags |= MEDUSA_TIMER_FLAG_PRECISE;
        } else if (type == MEDUSA_TIMER_TYPE_COARSE) {
                timer->flags |= MEDUSA_TIMER_FLAG_COARSE;
        } else {
                timer->flags |= MEDUSA_TIMER_FLAG_COARSE;
        }
        return medusa_subject_mod(&timer->subject);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_timer_get_type (const struct medusa_timer *timer)
{
        if (timer->flags & MEDUSA_TIMER_FLAG_PRECISE) {
                return MEDUSA_TIMER_TYPE_PRECISE;
        } else if (timer->flags & MEDUSA_TIMER_FLAG_COARSE) {
                return MEDUSA_TIMER_TYPE_COARSE;
        }
        return MEDUSA_TIMER_TYPE_COARSE;
}

__attribute__ ((visibility ("default"))) int medusa_timer_set_callback (struct medusa_timer *timer, int (*callback) (struct medusa_timer *timer, unsigned int events, void *context), void *context)
{
        timer->callback = callback;
        timer->context = context;
        return medusa_subject_mod(&timer->subject);
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
        return medusa_subject_mod(&timer->subject);
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

__attribute__ ((visibility ("default"))) int medusa_timer_is_valid (const struct medusa_timer *timer)
{
        if (!medusa_timespec_isset(&timer->initial) &&
            !medusa_timespec_isset(&timer->interval)) {
                return 0;
        }
        if (timer->callback == NULL) {
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
