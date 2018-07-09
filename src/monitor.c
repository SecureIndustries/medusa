
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "queue.h"

#include "time.h"
#include "event.h"
#include "subject.h"
#include "monitor.h"

#include "subject-private.h"

#include "monitor-epoll.h"
#include "monitor-kqueue.h"
#include "monitor-poll.h"
#include "monitor-select.h"
#include "monitor-backend.h"

struct medusa_monitor {
        struct medusa_subjects subjects;
        struct medusa_monitor_backend *backend;
};

static const struct medusa_monitor_init_options g_init_options = {
        .backend = {
                .type = medusa_monitor_backend_default
        }
};

int medusa_monitor_init_options_default (struct medusa_monitor_init_options *options)
{
        if (options == NULL) {
                goto bail;
        }
        memcpy(options, &g_init_options, sizeof(struct medusa_monitor_init_options));
        return 0;
bail:   return -1;
}

struct medusa_monitor * medusa_monitor_create (const struct medusa_monitor_init_options *options)
{
        struct medusa_monitor *monitor;
        monitor = NULL;
        monitor = malloc(sizeof(struct medusa_monitor));
        if (monitor == NULL) {
                goto bail;
        }
        memset(monitor, 0, sizeof(struct medusa_monitor));
        TAILQ_INIT(&monitor->subjects);
        if (options == NULL) {
                options = &g_init_options;
        }
        if (options->backend.type == medusa_monitor_backend_default) {
                do {
                        monitor->backend = medusa_monitor_epoll_create(NULL);
                        if (monitor->backend != NULL) {
                                break;
                        }
                        monitor->backend = medusa_monitor_kqueue_create(NULL);
                        if (monitor->backend != NULL) {
                                break;
                        }
                        monitor->backend = medusa_monitor_poll_create(NULL);
                        if (monitor->backend != NULL) {
                                break;
                        }
                        monitor->backend = medusa_monitor_select_create(NULL);
                        if (monitor->backend != NULL) {
                                break;
                        }
                } while (0);
        } else if (options->backend.type == medusa_monitor_backend_epoll) {
                monitor->backend = medusa_monitor_epoll_create(NULL);
                if (monitor->backend == NULL) {
                        goto bail;
                }
        } else if (options->backend.type == medusa_monitor_backend_kqueue) {
                monitor->backend = medusa_monitor_kqueue_create(NULL);
                if (monitor->backend == NULL) {
                        goto bail;
                }
        } else if (options->backend.type == medusa_monitor_backend_poll) {
                monitor->backend = medusa_monitor_poll_create(NULL);
                if (monitor->backend == NULL) {
                        goto bail;
                }
        } else if (options->backend.type == medusa_monitor_backend_select) {
                monitor->backend = medusa_monitor_select_create(NULL);
                if (monitor->backend == NULL) {
                        goto bail;
                }
        } else {
                goto bail;
        }
        monitor->backend->monitor = monitor;
        return monitor;
bail:   if (monitor != NULL) {
                medusa_monitor_destroy(monitor);
        }
        return NULL;
}

void medusa_monitor_destroy (struct medusa_monitor *monitor)
{
        struct medusa_subject *subject;
        struct medusa_subject *nsubject;
        if (monitor == NULL) {
                return;
        }
        TAILQ_FOREACH_SAFE(subject, &monitor->subjects, subjects, nsubject) {
                monitor->backend->del(monitor->backend, subject);
                TAILQ_REMOVE(&monitor->subjects, subject, subjects);
                medusa_subject_destroy(subject);
        }
        if (monitor->backend != NULL) {
                monitor->backend->destroy(monitor->backend);
        }
        free(monitor);
}

int medusa_monitor_add (struct medusa_monitor *monitor, struct medusa_subject *subject, ...)
{
        int rc;
        unsigned int events;
        if (monitor == NULL) {
                goto bail;
        }
        if (subject == NULL) {
                goto bail;
        }
        if (medusa_subject_get_type(subject) == medusa_subject_type_io) {
                va_list ap;
                va_start(ap, subject);
                events = va_arg(ap, unsigned int);
                va_end(ap);
                rc = monitor->backend->add(monitor->backend, subject, events);
                if (rc != 0) {
                        goto bail;
                }
        } else if (medusa_subject_get_type(subject) == medusa_subject_type_timer) {
                events = medusa_event_in;
        } else if (medusa_subject_get_type(subject) == medusa_subject_type_signal) {
                events = 0;
        } else {
                goto bail;
        }
        rc = medusa_subject_retain(subject);
        if (rc != 0) {
                goto bail;
        }
        TAILQ_INSERT_TAIL(&monitor->subjects, subject, subjects);
        subject->private.monitor = monitor;
        return 0;
bail:   return -1;
}

int medusa_monitor_mod (struct medusa_monitor *monitor, struct medusa_subject *subject, ...)
{
        int rc;
        unsigned int events;
        if (monitor == NULL) {
                goto bail;
        }
        if (subject == NULL) {
                goto bail;
        }
        if (medusa_subject_get_type(subject) == medusa_subject_type_io) {
                va_list ap;
                va_start(ap, subject);
                events = va_arg(ap, unsigned int);
                va_end(ap);
                rc = monitor->backend->mod(monitor->backend, subject, events);
                if (rc != 0) {
                        goto bail;
                }
        } else if (medusa_subject_get_type(subject) == medusa_subject_type_timer) {
                events = medusa_event_in;
        } else if (medusa_subject_get_type(subject) == medusa_subject_type_signal) {
                events = 0;
        } else {
                goto bail;
        }
        return 0;
bail:   return -1;
}

int medusa_monitor_del (struct medusa_monitor *monitor, struct medusa_subject *subject)
{
        int rc;
        if (monitor == NULL) {
                goto bail;
        }
        if (subject == NULL) {
                goto bail;
        }
        rc = monitor->backend->del(monitor->backend, subject);
        if (rc != 0) {
                goto bail;
        }
        subject->private.monitor = NULL;
        TAILQ_REMOVE(&monitor->subjects, subject, subjects);
        medusa_subject_destroy(subject);
        return 0;
bail:   return -1;
}

int medusa_monitor_run (struct medusa_monitor *monitor, unsigned int flags, ...)
{
        int rc;
        va_list ap;
        struct medusa_timespec *timeout;
        struct medusa_timespec timeout_nowait;
        if (monitor == NULL) {
                goto bail;
        }
        timeout = NULL;
        timeout_nowait.seconds = 0;
        timeout_nowait.nanoseconds = 0;
        va_start(ap, flags);
        if (flags & medusa_monitor_run_timeout) {
                timeout = va_arg(ap, struct medusa_timespec *);
        }
        va_end(ap);

        if (flags & medusa_monitor_run_nowait) {
                timeout = &timeout_nowait;
        }

        while (1) {
                rc = monitor->backend->run(monitor->backend, timeout);
                if (rc != 0) {
                        goto bail;
                }
                if (flags & medusa_monitor_run_once) {
                        break;
                }
        }
        (void) flags;
        return 0;
bail:   return -1;
}
