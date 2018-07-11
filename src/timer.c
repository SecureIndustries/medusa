
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "clock.h"
#include "queue.h"
#include "time.h"
#include "subject.h"
#include "subject-struct.h"
#include "timer-struct.h"

#include "timer.h"

static int timer_subject_event (struct medusa_subject *subject, unsigned int events)
{
        struct medusa_timer *timer = (struct medusa_timer *) subject;
        (void) events;
        if (timer->timeout != NULL) {
                timer->timeout(timer);
        }
        return 0;
}

static int timer_init (struct medusa_timer *timer, void (*destroy) (struct medusa_timer *timer))
{
        memset(timer, 0, sizeof(struct medusa_timer));
        timer->single_shot = 0;
        timer->type = MEDUSA_TIMER_TYPE_COARSE;
        medusa_timespec_clear(&timer->initial);
        medusa_timespec_clear(&timer->interval);
        timer->active = 0;
        return medusa_subject_set(&timer->subject, MEDUSA_SUBJECT_TYPE_TIMER, timer_subject_event, (void (*) (struct medusa_subject *)) destroy, NULL);
}

static void timer_uninit (struct medusa_timer *timer)
{
        medusa_subject_del(&timer->subject);
        memset(timer, 0, sizeof(struct medusa_timer));
}

static void timer_destroy (struct medusa_timer *timer)
{
        timer_uninit(timer);
        free(timer);
}

int medusa_timer_init (struct medusa_timer *timer)
{
        return timer_init(timer, timer_uninit);
}

struct medusa_timer * medusa_timer_create (void)
{
        int rc;
        struct medusa_timer *timer;
        timer = malloc(sizeof(struct medusa_timer));
        if (timer == NULL) {
                goto bail;
        }
        rc = timer_init(timer, timer_destroy);
        if (rc != 0) {
                goto bail;
        }
        return timer;
bail:   if (timer != NULL) {
                medusa_timer_destroy(timer);
        }
        return NULL;
}

void medusa_timer_destroy (struct medusa_timer *timer)
{
        medusa_subject_destroy(&timer->subject);
}

int medusa_timer_set_initial (struct medusa_timer *timer, double initial)
{
        timer->initial.seconds = (long long) initial;
        timer->initial.nanoseconds = (long long) ((initial - timer->initial.seconds) * 1e9);
        return medusa_subject_mod(&timer->subject);
}

double medusa_timer_get_initial (const struct medusa_timer *timer)
{
        return timer->initial.seconds + timer->initial.nanoseconds * 1e-9;
}

int medusa_timer_set_interval (struct medusa_timer *timer, double interval)
{
        timer->interval.seconds = (long long) interval;
        timer->interval.nanoseconds = (long long) ((interval - timer->interval.seconds) * 1e9);
        return medusa_subject_mod(&timer->subject);
}

double medusa_timer_get_interval (const struct medusa_timer *timer)
{
        return timer->interval.seconds + timer->interval.nanoseconds * 1e-9;
}

double medusa_timer_get_remaining_time (const struct medusa_timer *timer)
{
        struct medusa_timespec now;
        struct medusa_timespec rem;
        clock_boottime(&now);
        medusa_timespec_sub(&timer->_timespec, &now, &rem);
        return rem.seconds + rem.nanoseconds + 1e-9;
}

int medusa_timer_set_single_shot (struct medusa_timer *timer, int single_shot)
{
        timer->single_shot = !!single_shot;
        return medusa_subject_mod(&timer->subject);
}

int medusa_timer_get_single_shot (const struct medusa_timer *timer)
{
        return timer->single_shot;
}

int medusa_timer_set_type (struct medusa_timer *timer, unsigned int type)
{
        if (type == MEDUSA_TIMER_TYPE_PRECISE ||
            type == MEDUSA_TIMER_TYPE_COARSE) {
                timer->type = type;
        } else {
                timer->type = MEDUSA_TIMER_TYPE_COARSE;
        }
        return medusa_subject_mod(&timer->subject);
}

unsigned int medusa_timer_get_type (const struct medusa_timer *timer)
{
        return timer->type;
}

int medusa_timer_set_timeout_callback (struct medusa_timer *timer, void (*timeout) (struct medusa_timer *timer), void *context)
{
        timer->timeout = timeout;
        timer->context = context;
        return medusa_subject_mod(&timer->subject);
}

void * medusa_timer_get_timeout_context (const struct medusa_timer *timer)
{
        return timer->context;
}

int medusa_timer_set_active (struct medusa_timer *timer, int active)
{
        timer->active = !!active;
        return medusa_subject_mod(&timer->subject);
}

int medusa_timer_get_active (const struct medusa_timer *timer)
{
        return timer->active;
}

int medusa_timer_start (struct medusa_timer *timer)
{
        return medusa_timer_set_active(timer, 1);
}

int medusa_timer_stop (struct medusa_timer *timer)
{
        return medusa_timer_set_active(timer, 0);
}

int medusa_timer_is_valid (const struct medusa_timer *timer)
{
        if (!medusa_timespec_isset(&timer->interval)) {
                return 0;
        }
        if (timer->timeout == NULL) {
                return 0;
        }
        if (timer->active == 0) {
                return 0;
        }
        return 1;
}

struct medusa_subject * medusa_timer_get_subject (struct medusa_timer *timer)
{
        return &timer->subject;
}

struct medusa_monitor * medusa_timer_get_monitor (struct medusa_timer *timer)
{
        return timer->subject.monitor;
}
