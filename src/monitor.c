
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>

#include "queue.h"
#include "pqueue.h"

#include "time.h"
#include "clock.h"
#include "event.h"
#include "subject.h"
#include "monitor.h"

#include "subject-struct.h"

#include "poll-epoll.h"
#include "poll-kqueue.h"
#include "poll-poll.h"
#include "poll-select.h"
#include "poll-backend.h"

#include "timer-timerfd.h"
#include "timer-backend.h"

struct medusa_monitor {
        int running;
        struct medusa_subjects subjects;
        struct {
                struct medusa_poll_backend *backend;
        } poll;
        struct {
                struct medusa_timer_backend *backend;
                struct pqueue_head pqueue;
                int dirty;
        } timer;
        int break_fds[2];
};

static const struct medusa_monitor_init_options g_init_options = {
        .poll = {
                .type = medusa_monitor_poll_default,
                .u    = { }
        },
        .timer = {
                .type = medusa_monitor_timer_default,
                .u    = { }
        },
};

static int fd_set_blocking (int fd, int on)
{
        int rc;
        int flags;
        flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0) {
                return -1;
        }
        flags = on ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
        rc = fcntl(fd, F_SETFL, flags);
        if (rc != 0) {
                return -1;
        }
        return 0;
}

static int monitor_break_subject_callback (struct medusa_subject *subject, unsigned int events)
{
        int rc;
        struct medusa_monitor *monitor;
        if (events & medusa_event_in) {
                monitor = medusa_subject_get_monitor(subject);
                rc = read(monitor->break_fds[0], &monitor->running, sizeof(monitor->running));
                if (rc != sizeof(monitor->running)) {
                        goto bail;
                }
        }
        return 0;
bail:   return -1;
}

static int monitor_timer_subject_callback (struct medusa_subject *subject, unsigned int events)
{
        int rc;
        int fd;
        uint64_t value;
        struct medusa_timespec timespec;
        struct medusa_subject *timer;
        struct medusa_monitor *monitor;
        if (events & medusa_event_in) {
                fd = medusa_subject_io_get_fd(subject);
                rc = read(fd, &value, sizeof(value));
                if (rc != sizeof(value)) {
                        goto bail;
                }
                monitor = medusa_subject_get_monitor(subject);
                rc = clock_boottime(&timespec);
                if (rc != 0) {
                        goto bail;
                }
                while (1) {
                        timer = pqueue_peek(&monitor->timer.pqueue);
                        if (timer == NULL) {
                                break;
                        }
                        if (medusa_timespec_compare(&timer->u.timer.timespec, &timespec, >)) {
                                break;
                        }
                        timer = pqueue_pop(&monitor->timer.pqueue);
                        if (timer == NULL) {
                                break;
                        }
                        monitor->timer.dirty = 1;
                        rc = medusa_subject_get_callback_function(timer)(timer, medusa_event_timeout);
                        if (rc != 0) {
                                goto bail;
                        }
                        if (medusa_timespec_isset(&timer->u.timer.timerspec.interval)) {
                                medusa_timespec_add(&timer->u.timer.timespec, &timer->u.timer.timerspec.interval, &timer->u.timer.timespec);
                                if (!medusa_timespec_isset(&timer->u.timer.timespec)) {
                                        goto bail;
                                }
                                rc = pqueue_add(&monitor->timer.pqueue, timer);
                                if (rc != 0) {
                                        goto bail;
                                }
                                monitor->timer.dirty = 1;
                        }
                }

        }
        return 0;
bail:   return -1;
}

static int monitor_timer_subject_compare (void *a, void *b)
{
        struct medusa_subject *sa = a;
        struct medusa_subject *sb = b;
        if (medusa_timespec_compare(&sa->u.timer.timespec, &sb->u.timer.timespec, <)) {
                return -1;
        }
        if (medusa_timespec_compare(&sa->u.timer.timespec, &sb->u.timer.timespec, >)) {
                return 1;
        }
        return 0;
}

static void monitor_timer_subject_position (void *entry, unsigned int position)
{
        struct medusa_subject *subject = entry;
        subject->u.timer.position = position;
}

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
        int rc;
        struct medusa_subject *subject;
        struct medusa_monitor *monitor;
        monitor = NULL;
        monitor = (struct medusa_monitor *) malloc(sizeof(struct medusa_monitor));
        if (monitor == NULL) {
                goto bail;
        }
        memset(monitor, 0, sizeof(struct medusa_monitor));
        TAILQ_INIT(&monitor->subjects);
        pqueue_init(&monitor->timer.pqueue, 0, 64, monitor_timer_subject_compare, monitor_timer_subject_position);
        monitor->running = 1;
        monitor->break_fds[0] = -1;
        monitor->break_fds[1] = -1;
        if (options == NULL) {
                options = &g_init_options;
        }
        if (options->poll.type == medusa_monitor_poll_default) {
                do {
                        monitor->poll.backend = medusa_monitor_epoll_create(NULL);
                        if (monitor->poll.backend != NULL) {
                                break;
                        }
                        monitor->poll.backend = medusa_monitor_kqueue_create(NULL);
                        if (monitor->poll.backend != NULL) {
                                break;
                        }
                        monitor->poll.backend = medusa_monitor_poll_create(NULL);
                        if (monitor->poll.backend != NULL) {
                                break;
                        }
                        monitor->poll.backend = medusa_monitor_select_create(NULL);
                        if (monitor->poll.backend != NULL) {
                                break;
                        }
                } while (0);
        } else if (options->poll.type == medusa_monitor_poll_epoll) {
                monitor->poll.backend = medusa_monitor_epoll_create(NULL);
        } else if (options->poll.type == medusa_monitor_poll_kqueue) {
                monitor->poll.backend = medusa_monitor_kqueue_create(NULL);
        } else if (options->poll.type == medusa_monitor_poll_poll) {
                monitor->poll.backend = medusa_monitor_poll_create(NULL);
        } else if (options->poll.type == medusa_monitor_poll_select) {
                monitor->poll.backend = medusa_monitor_select_create(NULL);
        } else {
                goto bail;
        }
        if (monitor->poll.backend == NULL) {
                goto bail;
        }
        monitor->poll.backend->monitor = monitor;
        if (options->timer.type == medusa_monitor_timer_default) {
                do {
                        monitor->timer.backend = medusa_timer_timerfd_create(NULL);
                        if (monitor->timer.backend != NULL) {
                                break;
                        }
                } while (0);
        } else if (options->timer.type == medusa_monitor_timer_timerfd) {
                monitor->timer.backend = medusa_timer_timerfd_create(NULL);
        } else {
                goto bail;
        }
        if (monitor->timer.backend == NULL) {
                goto bail;
        }
        monitor->timer.backend->monitor = monitor;
        rc = pipe(monitor->break_fds);
        if (rc != 0) {
                goto bail;
        }
        rc = fd_set_blocking(monitor->break_fds[0], 0);
        if (rc != 0) {
                goto bail;
        }
        rc = fd_set_blocking(monitor->break_fds[1], 0);
        if (rc != 0) {
                goto bail;
        }
        subject = medusa_subject_create_io(monitor->break_fds[0], monitor_break_subject_callback, NULL);
        if (subject == NULL) {
                goto bail;
        }
        rc = medusa_monitor_add(monitor, subject, medusa_event_in);
        if (rc != 0) {
                medusa_subject_destroy(subject);
                goto bail;
        }
        medusa_subject_destroy(subject);
        subject = medusa_subject_create_io(monitor->timer.backend->fd(monitor->timer.backend), monitor_timer_subject_callback, NULL);
        if (subject == NULL) {
                goto bail;
        }
        rc = medusa_monitor_add(monitor, subject, medusa_event_in);
        if (rc != 0) {
                medusa_subject_destroy(subject);
                goto bail;
        }
        medusa_subject_destroy(subject);
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
                monitor->poll.backend->del(monitor->poll.backend, subject);
                TAILQ_REMOVE(&monitor->subjects, subject, subjects);
                medusa_subject_destroy(subject);
        }
        if (monitor->poll.backend != NULL) {
                monitor->poll.backend->destroy(monitor->poll.backend);
        }
        if (monitor->timer.backend != NULL) {
                monitor->timer.backend->destroy(monitor->timer.backend);
        }
        if (monitor->break_fds[0] >= 0) {
                close(monitor->break_fds[0]);
        }
        if (monitor->break_fds[1] >= 0) {
                close(monitor->break_fds[1]);
        }
        pqueue_uninit(&monitor->timer.pqueue);
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
                rc = monitor->poll.backend->add(monitor->poll.backend, subject, events);
                if (rc != 0) {
                        goto bail;
                }
        } else if (medusa_subject_get_type(subject) == medusa_subject_type_timer) {
                struct medusa_timespec timespec;
                rc = clock_boottime(&timespec);
                if (rc != 0) {
                        goto bail;
                }
                medusa_timespec_clear(&subject->u.timer.timespec);
                medusa_timespec_add(&subject->u.timer.timerspec.timespec, &timespec, &subject->u.timer.timespec);
                if (!medusa_timespec_isset(&subject->u.timer.timespec)) {
                        goto bail;
                }
                rc = pqueue_add(&monitor->timer.pqueue, subject);
                if (rc != 0) {
                        goto bail;
                }
                monitor->timer.dirty = 1;
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
        subject->internal.monitor = monitor;
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
                rc = monitor->poll.backend->mod(monitor->poll.backend, subject, events);
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
        rc = monitor->poll.backend->del(monitor->poll.backend, subject);
        if (rc != 0) {
                goto bail;
        }
        subject->internal.monitor = NULL;
        TAILQ_REMOVE(&monitor->subjects, subject, subjects);
        medusa_subject_destroy(subject);
        return 0;
bail:   return -1;
}

int medusa_monitor_break (struct medusa_monitor *monitor)
{
        int rc;
        if (monitor == NULL) {
                goto bail;
        }
        monitor->running = 0;
        rc = write(monitor->break_fds[1], &monitor->running, sizeof(monitor->running));
        if (rc != sizeof(monitor->running)) {
                goto bail;
        }
        return 0;
bail:   return -1;
}

int medusa_monitor_continue (struct medusa_monitor *monitor)
{
        int rc;
        if (monitor == NULL) {
                goto bail;
        }
        monitor->running = 1;
        rc = write(monitor->break_fds[1], &monitor->running, sizeof(monitor->running));
        if (rc != sizeof(monitor->running)) {
                goto bail;
        }
        return 0;
bail:   return -1;
}

int medusa_monitor_run (struct medusa_monitor *monitor, unsigned int flags, ...)
{
        int rc;
        va_list ap;
        struct medusa_subject *subject;
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
                flags |= medusa_monitor_run_once;
                timeout = va_arg(ap, struct medusa_timespec *);
        }
        va_end(ap);

        if (flags & medusa_monitor_run_nowait) {
                flags |= medusa_monitor_run_once;
                timeout = &timeout_nowait;
        }

        while (monitor->running) {
                if (monitor->timer.dirty != 0) {
                        subject = pqueue_peek(&monitor->timer.pqueue);
                        if (subject == NULL) {
                                rc = monitor->timer.backend->set(monitor->timer.backend, NULL);
                                if (rc != 0) {
                                        goto bail;
                                }
                        } else {
                                rc = monitor->timer.backend->set(monitor->timer.backend, &subject->u.timer.timespec);
                                if (rc != 0) {
                                        goto bail;
                                }
                        }
                }
                rc = monitor->poll.backend->run(monitor->poll.backend, timeout);
                if (rc != 0) {
                        goto bail;
                }
                if (flags & medusa_monitor_run_once) {
                        break;
                }
        }

        return 0;
bail:   return -1;
}
