
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>

#include "queue.h"

#include "time.h"
#include "event.h"
#include "subject.h"
#include "monitor.h"

#include "subject-private.h"

#include "poll-epoll.h"
#include "poll-kqueue.h"
#include "poll-poll.h"
#include "poll-select.h"
#include "poll-backend.h"

#include "timer-timerfd.h"
#include "timer-backend.h"

struct medusa_monitor {
        int running;
        struct medusa_poll_backend *poll;
        struct medusa_timer_backend *timer;
        struct medusa_subjects subjects;
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
        unsigned char value;
        if (events & medusa_event_in) {
                fd = medusa_subject_io_get_fd(subject);
                rc = read(fd, &value, sizeof(value));
                if (rc != sizeof(value)) {
                        goto bail;
                }
        }
        return 0;
bail:   return -1;
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
        monitor->running = 1;
        monitor->break_fds[0] = -1;
        monitor->break_fds[1] = -1;
        if (options == NULL) {
                options = &g_init_options;
        }
        if (options->poll.type == medusa_monitor_poll_default) {
                do {
                        monitor->poll = medusa_monitor_epoll_create(NULL);
                        if (monitor->poll != NULL) {
                                break;
                        }
                        monitor->poll = medusa_monitor_kqueue_create(NULL);
                        if (monitor->poll != NULL) {
                                break;
                        }
                        monitor->poll = medusa_monitor_poll_create(NULL);
                        if (monitor->poll != NULL) {
                                break;
                        }
                        monitor->poll = medusa_monitor_select_create(NULL);
                        if (monitor->poll != NULL) {
                                break;
                        }
                } while (0);
        } else if (options->poll.type == medusa_monitor_poll_epoll) {
                monitor->poll = medusa_monitor_epoll_create(NULL);
                if (monitor->poll == NULL) {
                        goto bail;
                }
        } else if (options->poll.type == medusa_monitor_poll_kqueue) {
                monitor->poll = medusa_monitor_kqueue_create(NULL);
                if (monitor->poll == NULL) {
                        goto bail;
                }
        } else if (options->poll.type == medusa_monitor_poll_poll) {
                monitor->poll = medusa_monitor_poll_create(NULL);
                if (monitor->poll == NULL) {
                        goto bail;
                }
        } else if (options->poll.type == medusa_monitor_poll_select) {
                monitor->poll = medusa_monitor_select_create(NULL);
                if (monitor->poll == NULL) {
                        goto bail;
                }
        } else {
                goto bail;
        }
        monitor->poll->monitor = monitor;
        if (options->timer.type == medusa_monitor_timer_default) {
                do {
                        monitor->timer = medusa_timer_timerfd_create(NULL);
                        if (monitor->timer != NULL) {
                                break;
                        }
                } while (0);
        } else if (options->timer.type == medusa_monitor_timer_timerfd) {
                monitor->timer = medusa_timer_timerfd_create(NULL);
                if (monitor->timer == NULL) {
                        goto bail;
                }
        } else {
                goto bail;
        }
        monitor->timer->monitor = monitor;
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
        subject = medusa_subject_create_io(monitor->timer->fd(monitor->timer), monitor_timer_subject_callback, NULL);
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
                monitor->poll->del(monitor->poll, subject);
                TAILQ_REMOVE(&monitor->subjects, subject, subjects);
                medusa_subject_destroy(subject);
        }
        if (monitor->poll != NULL) {
                monitor->poll->destroy(monitor->poll);
        }
        if (monitor->timer != NULL) {
                monitor->timer->destroy(monitor->timer);
        }
        if (monitor->break_fds[0] >= 0) {
                close(monitor->break_fds[0]);
        }
        if (monitor->break_fds[1] >= 0) {
                close(monitor->break_fds[1]);
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
                rc = monitor->poll->add(monitor->poll, subject, events);
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
                rc = monitor->poll->mod(monitor->poll, subject, events);
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
        rc = monitor->poll->del(monitor->poll, subject);
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

        while (monitor->running) {
                rc = monitor->poll->run(monitor->poll, timeout);
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
