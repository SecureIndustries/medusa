
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/queue.h>

#include "event.h"
#include "time.h"
#include "subject.h"
#include "subject-private.h"

int medusa_subject_retain (struct medusa_subject *subject)
{
        if (subject == NULL) {
                goto bail;
        }
        subject->internal.refcount += 1;
        return 0;
bail:   return -1;
}

void medusa_subject_uninit (struct medusa_subject *subject)
{
        if (subject == NULL) {
                return;
        }
        memset(subject, 0, sizeof(struct medusa_subject));
}

int medusa_subject_init (struct medusa_subject *subject, const struct medusa_subject_init_options *options)
{
        if (subject == NULL) {
                goto bail;
        }
        if (options == NULL) {
                goto bail;
        }
        if (options->callback.function == NULL) {
                goto bail;
        }
        memset(subject, 0, sizeof(struct medusa_subject));
        subject->internal.refcount = 1;
        switch (options->type) {
                case medusa_subject_type_io:
                        if (options->u.io.fd < 0) {
                                goto bail;
                        }
                        subject->type = medusa_subject_type_io;
                        subject->u.io.fd = options->u.io.fd;
                        subject->callback.function = options->callback.function;
                        subject->callback.context = options->callback.context;
                        break;
                case medusa_subject_type_timer:
                        if (options->u.timer.timerspec.timespec.seconds == 0 &&
                            options->u.timer.timerspec.timespec.nanoseconds == 0 &&
                            options->u.timer.timerspec.interval.seconds == 0 &&
                            options->u.timer.timerspec.interval.nanoseconds == 0) {
                                goto bail;
                        }
                        subject->type = medusa_subject_type_timer;
                        subject->u.timer.timerspec = options->u.timer.timerspec;
                        subject->callback.function = options->callback.function;
                        subject->callback.context = options->callback.context;
                        break;
                case medusa_subject_type_signal:
                        if (options->u.signal.number <= 0) {
                                goto bail;
                        }
                        subject->type = medusa_subject_type_signal;
                        subject->u.signal.number = options->u.signal.number;
                        subject->callback.function = options->callback.function;
                        subject->callback.context = options->callback.context;
                        break;
                default:
                        goto bail;
        }
        return 0;
bail:   if (subject != NULL) {
                medusa_subject_uninit(subject);
        }
        return -1;
}

int medusa_subject_init_io (struct medusa_subject *subject, int fd, int (*callback) (void *context, struct medusa_subject *subject, unsigned int events), void *context)
{
        struct medusa_subject_init_options options;
        options.type = medusa_subject_type_io;
        options.u.io.fd = fd;
        options.callback.function = callback;
        options.callback.context = context;
        return medusa_subject_init(subject, &options);
}

int medusa_subject_init_timer (struct medusa_subject *subject, struct medusa_timerspec timerspec, int (*callback) (void *context, struct medusa_subject *subject, unsigned int events), void *context)
{
        struct medusa_subject_init_options options;
        options.type = medusa_subject_type_timer;
        options.u.timer.timerspec = timerspec;
        options.callback.function = callback;
        options.callback.context = context;
        return medusa_subject_init(subject, &options);
}

int medusa_subject_init_signal (struct medusa_subject *subject, int number, int (*callback) (void *context, struct medusa_subject *subject, unsigned int events), void *context)
{
        struct medusa_subject_init_options options;
        options.type = medusa_subject_type_signal;
        options.u.signal.number = number;
        options.callback.function = callback;
        options.callback.context = context;
        return medusa_subject_init(subject, &options);
}

void medusa_subject_destroy (struct medusa_subject *subject)
{
        if (subject == NULL) {
                return;
        }
        if (--subject->internal.refcount > 0) {
                return;
        }
        if (subject->callback.function != NULL) {
                subject->callback.function(subject->callback.context, subject, medusa_event_destroy);
        }
        free(subject);
}

struct medusa_subject * medusa_subject_create (const struct medusa_subject_init_options *options)
{
        int rc;
        struct medusa_subject *subject;
        subject = (struct medusa_subject *) malloc(sizeof(struct medusa_subject));
        if (subject == NULL) {
                goto bail;
        }
        rc = medusa_subject_init(subject, options);
        if (rc != 0) {
                goto bail;
        }
        return subject;
bail:   if (subject != NULL) {
                medusa_subject_destroy(subject);
        }
        return NULL;
}

struct medusa_subject * medusa_subject_create_io (int fd, int (*callback) (void *context, struct medusa_subject *subject, unsigned int events), void *context)
{
        struct medusa_subject_init_options options;
        options.type = medusa_subject_type_io;
        options.u.io.fd = fd;
        options.callback.function = callback;
        options.callback.context = context;
        return medusa_subject_create(&options);
}

struct medusa_subject * medusa_subject_create_timer (struct medusa_timerspec timerspec, int (*callback) (void *context, struct medusa_subject *subject, unsigned int events), void *context)
{
        struct medusa_subject_init_options options;
        options.type = medusa_subject_type_timer;
        options.u.timer.timerspec = timerspec;
        options.callback.function = callback;
        options.callback.context = context;
        return medusa_subject_create(&options);
}

struct medusa_subject * medusa_subject_create_signal (int number, int (*callback) (void *context, struct medusa_subject *subject, unsigned int events), void *context)
{
        struct medusa_subject_init_options options;
        options.type = medusa_subject_type_signal;
        options.u.signal.number = number;
        options.callback.function = callback;
        options.callback.context = context;
        return medusa_subject_create(&options);
}

unsigned int medusa_subject_get_type (const struct medusa_subject *subject)
{
        if (subject == NULL) {
                goto bail;
        }
        return subject->type;
bail:   return 0;
}

int (*medusa_subject_get_callback_function (const struct medusa_subject *subject)) (void *context, struct medusa_subject *subject, unsigned int events)
{
        if (subject == NULL) {
                goto bail;
        }
        return subject->callback.function;
bail:   return 0;
}

void * medusa_subject_get_callback_context (const struct medusa_subject *subject)
{
        if (subject == NULL) {
                goto bail;
        }
        return subject->callback.context;
bail:   return 0;
}

int medusa_subject_io_get_fd (const struct medusa_subject *subject)
{
        if (subject == NULL) {
                goto bail;
        }
        if (subject->type != medusa_subject_type_io) {
                goto bail;
        }
        return subject->u.io.fd;
bail:   return -1;
}
