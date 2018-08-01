
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#include "queue.h"
#include "pqueue.h"

#include "time.h"
#include "clock.h"
#include "io.h"
#include "timer.h"
#include "monitor.h"
#include "monitor-private.h"

#include "subject-struct.h"
#include "timer-struct.h"
#include "io-struct.h"

#include "poll-epoll.h"
#include "poll-kqueue.h"
#include "poll-poll.h"
#include "poll-select.h"
#include "poll-backend.h"

#include "timer-timerfd.h"
#include "timer-backend.h"

enum {
        WAKEUP_REASON_LOOP_BREAK,
        WAKEUP_REASON_LOOP_CONTINUE,
        WAKEUP_REASON_SUBJECT_ADD,
        WAKEUP_REASON_SUBJECT_MOD,
        WAKEUP_REASON_SUBJECT_DEL,
};

struct medusa_monitor {
        int running;
        struct medusa_subjects actives;
        struct medusa_subjects changes;
        struct medusa_subjects deletes;
        struct medusa_subjects rogues;
        struct {
                struct medusa_poll_backend *backend;
        } poll;
        struct {
                struct medusa_timer_backend *backend;
                struct pqueue_head *pqueue;
                int fired;
                int dirty;
                struct medusa_io io;
        } timer;
        struct {
                int fds[2];
                struct medusa_io io;
        } wakeup;
};

static const struct medusa_monitor_init_options g_init_options = {
        .poll = {
                .type = MEDUSA_MONITOR_POLL_DEFAULT,
                .u    = { }
        },
        .timer = {
                .type = MEDUSA_MONITOR_TIMER_DEFAULT,
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

static int monitor_break_io_onevent (struct medusa_io *io, unsigned int events, void *context)
{
        int rc;
        unsigned int reason;
        (void) context;
        if (events & MEDUSA_IO_EVENT_IN) {
                rc = read(io->subject.monitor->wakeup.fds[0], &reason, sizeof(reason));
                if (rc != sizeof(reason)) {
                        goto bail;
                }
                if (reason == WAKEUP_REASON_LOOP_BREAK) {
                        io->subject.monitor->running = 0;
                } else if (reason == WAKEUP_REASON_LOOP_CONTINUE) {
                        io->subject.monitor->running = 1;
                } else {
                        goto bail;
                }
        }
        return 0;
bail:   return -1;
}

static int monitor_timer_io_onevent (struct medusa_io *io, unsigned int events, void *context)
{
        (void) context;
        if (events & MEDUSA_IO_EVENT_IN) {
                int rc;
                uint64_t value;
                rc = read(io->fd, &value, sizeof(value));
                if (rc != sizeof(value)) {
                        goto bail;
                }
                io->subject.monitor->timer.fired = 1;
        }
        return 0;
bail:   return -1;
}

static int monitor_timer_subject_compare (void *a, void *b)
{
        struct medusa_timer *ta = a;
        struct medusa_timer *tb = b;
        if (medusa_timespec_compare(&ta->_timespec, &tb->_timespec, <)) {
                return -1;
        }
        if (medusa_timespec_compare(&ta->_timespec, &tb->_timespec, >)) {
                return 1;
        }
        return 0;
}

static void monitor_timer_subject_set_position (void *entry, unsigned int position)
{
        struct medusa_timer *timer = entry;
        timer->_position = position;
}

static unsigned int monitor_timer_subject_get_position (void *entry)
{
        struct medusa_timer *timer = entry;
        return timer->_position;
}

static int medusa_monitor_process_deletes (struct medusa_monitor *monitor)
{
        int rc;
        struct medusa_io *io;
        struct medusa_timer *timer;
        struct medusa_subject *subject;
        while (!TAILQ_EMPTY(&monitor->deletes)) {
                subject = TAILQ_FIRST(&monitor->deletes);
                TAILQ_REMOVE(&monitor->deletes, subject, subjects);
                subject->monitor = NULL;
                if (subject->flags & MEDUSA_SUBJECT_FLAG_IO) {
                        io = (struct medusa_io *) subject;
                        if (subject->flags & MEDUSA_SUBJECT_FLAG_POLL) {
                                rc = monitor->poll.backend->del(monitor->poll.backend, io);
                                if (rc != 0) {
                                        goto bail;
                                }
                        }
                        medusa_io_onevent(io, MEDUSA_IO_EVENT_DESTROY);
                } else if (subject->flags & MEDUSA_SUBJECT_FLAG_TIMER) {
                        timer = (struct medusa_timer *) subject;
                        if (subject->flags & MEDUSA_SUBJECT_FLAG_HEAP) {
                                rc = pqueue_del(monitor->timer.pqueue, timer);
                                if (rc != 0) {
                                        goto bail;
                                }
                                monitor->timer.dirty = 1;
                        }
                        medusa_timer_onevent(timer, MEDUSA_TIMER_EVENT_DESTROY);
                }
        }
        return 0;
bail:   return -1;
}

static int medusa_monitor_process_changes (struct medusa_monitor *monitor)
{
        int rc;
        struct timespec now;
        struct medusa_io *io;
        struct medusa_timer *timer;
        struct medusa_subject *subject;
        struct medusa_subject *nsubject;
        rc = medusa_clock_monotonic(&now);
        if (rc != 0) {
                goto bail;
        }
        TAILQ_FOREACH_SAFE(subject, &monitor->changes, subjects, nsubject) {
                if (subject->flags & MEDUSA_SUBJECT_FLAG_IO) {
                        io = (struct medusa_io *) subject;
                        if (!medusa_io_is_valid(io)) {
                                if (subject->flags & MEDUSA_SUBJECT_FLAG_POLL) {
                                        rc = monitor->poll.backend->del(monitor->poll.backend, io);
                                        if (rc != 0) {
                                                goto bail;
                                        }
                                }
                                TAILQ_REMOVE(&monitor->changes, subject, subjects);
                                TAILQ_INSERT_TAIL(&monitor->rogues, subject, subjects);
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_MOD;
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_POLL;
                                subject->flags |= MEDUSA_SUBJECT_FLAG_ROGUE;
                        } else {
                                if (subject->flags & MEDUSA_SUBJECT_FLAG_POLL) {
                                        rc = monitor->poll.backend->mod(monitor->poll.backend, io);
                                        if (rc != 0) {
                                                goto bail;
                                        }
                                } else {
                                        rc = monitor->poll.backend->add(monitor->poll.backend, io);
                                        if (rc != 0) {
                                                goto bail;
                                        }
                                }
                                TAILQ_REMOVE(&monitor->changes, subject, subjects);
                                TAILQ_INSERT_TAIL(&monitor->actives, subject, subjects);
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_MOD;
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_ROGUE;
                                subject->flags |= MEDUSA_SUBJECT_FLAG_POLL;
                        }
                } else if (subject->flags & MEDUSA_SUBJECT_FLAG_TIMER) {
                        timer = (struct medusa_timer *) subject;
                        if (!medusa_timer_is_valid(timer) ||
                            (medusa_timespec_isset(&timer->_timespec) && !medusa_timespec_isset(&timer->interval))) {
                                if (subject->flags & MEDUSA_SUBJECT_FLAG_HEAP) {
                                        rc = pqueue_del(monitor->timer.pqueue, timer);
                                        if (rc != 0) {
                                                goto bail;
                                        }
                                        monitor->timer.dirty = 1;
                                }
                                TAILQ_REMOVE(&monitor->changes, subject, subjects);
                                TAILQ_INSERT_TAIL(&monitor->rogues, subject, subjects);
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_MOD;
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_HEAP;
                                subject->flags |= MEDUSA_SUBJECT_FLAG_ROGUE;
                        } else {
                                struct timespec _timespec;
                                medusa_timespec_clear(&_timespec);
                                if (medusa_timespec_isset(&timer->_timespec)) {
                                        _timespec = timer->_timespec;
                                        medusa_timespec_add(&timer->_timespec, &timer->interval, &timer->_timespec);
                                } else {
                                        medusa_timespec_clear(&timer->_timespec);
                                        if (medusa_timespec_isset(&timer->initial)) {
                                                medusa_timespec_add(&timer->initial, &now, &timer->_timespec);
                                        } else {
                                                medusa_timespec_add(&timer->interval, &now, &timer->_timespec);
                                        }
                                }
                                if (!medusa_timespec_isset(&timer->_timespec)) {
                                        goto bail;
                                }
                                if (medusa_timer_get_resolution(timer) == MEDUSA_TIMER_RESOLUTION_MICROSECONDS) {
                                        timer->_timespec.tv_nsec = timer->_timespec.tv_nsec / 1e3;
                                } else if (medusa_timer_get_resolution(timer) == MEDUSA_TIMER_RESOLUTION_MILLISECONDS) {
                                        timer->_timespec.tv_nsec = timer->_timespec.tv_nsec / 1e6;
                                } else if (medusa_timer_get_resolution(timer) == MEDUSA_TIMER_RESOLUTION_SECONDS) {
                                        if (timer->_timespec.tv_nsec >= 500000000) {
                                                timer->_timespec.tv_sec += 1;
                                        }
                                        timer->_timespec.tv_nsec = 0;
                                }
                                if (subject->flags & MEDUSA_SUBJECT_FLAG_HEAP) {
                                        rc = pqueue_mod(monitor->timer.pqueue, timer, medusa_timespec_compare(&_timespec, &timer->_timespec, >));
                                        if (rc != 0) {
                                                goto bail;
                                        }
                                } else {
                                        rc = pqueue_add(monitor->timer.pqueue, subject);
                                        if (rc != 0) {
                                                goto bail;
                                        }
                                }
                                TAILQ_REMOVE(&monitor->changes, subject, subjects);
                                TAILQ_INSERT_TAIL(&monitor->actives, subject, subjects);
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_MOD;
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_ROGUE;
                                subject->flags |= MEDUSA_SUBJECT_FLAG_HEAP;
                                monitor->timer.dirty = 1;
                        }
                }
        }
        return 0;
bail:   return -1;
}

static int medusa_monitor_check_timer (struct medusa_monitor *monitor)
{
        int rc;
        struct timespec now;
        struct medusa_timer *timer;
        rc = medusa_clock_monotonic(&now);
        if (rc != 0) {
                goto bail;
        }
        if (monitor->timer.fired != 0) {
                while (1) {
                        timer = pqueue_peek(monitor->timer.pqueue);
                        if (timer == NULL) {
                                break;
                        }
                        if (medusa_timespec_compare(&timer->_timespec, &now, >)) {
                                break;
                        }
                        timer = pqueue_pop(monitor->timer.pqueue);
                        if (timer == NULL) {
                                break;
                        }
                        timer->subject.flags &= ~MEDUSA_SUBJECT_FLAG_HEAP;
                        if (medusa_timer_get_single_shot(timer) ||
                            !medusa_timespec_isset(&timer->interval)) {
                                rc = medusa_timer_set_enabled(timer, 0);
                                if (rc != 0) {
                                        goto bail;
                                }
                        }
                        monitor->timer.dirty = 1;
                        rc = medusa_monitor_mod(&timer->subject);
                        if (rc != 0) {
                                goto bail;
                        }
                        if (timer->onevent != NULL) {
                                rc = timer->onevent(timer, MEDUSA_TIMER_EVENT_TIMEOUT, timer->context);
                                if (rc != 0) {
                                        goto bail;
                                }
                        }
                }
                monitor->timer.fired = 0;
        }
        return 0;
bail:   return -1;
}

static int medusa_monitor_setup_timer (struct medusa_monitor *monitor)
{
        int rc;
        struct medusa_timer *timer;
        if (monitor->timer.dirty != 0) {
                timer = pqueue_peek(monitor->timer.pqueue);
                rc = monitor->timer.backend->set(monitor->timer.backend, (timer) ? &timer->_timespec : NULL);
                if (rc != 0) {
                        goto bail;
                }
                monitor->timer.dirty = 0;
        }
        return 0;
bail:   return -1;
}

static int medusa_monitor_signal (struct medusa_monitor *monitor, unsigned int reason)
{
        int rc;
        rc = write(monitor->wakeup.fds[1], &reason, sizeof(reason));
        if (rc != sizeof(reason)) {
                goto bail;
        }
        return 0;
bail:   return -1;
}

__attribute__ ((visibility ("default"))) int medusa_monitor_add (struct medusa_monitor *monitor, struct medusa_subject *subject)
{
        if (monitor == NULL) {
                goto bail;
        }
        if (subject == NULL) {
                goto bail;
        }
        if (subject->monitor != NULL) {
                goto bail;
        }
        TAILQ_INSERT_TAIL(&monitor->changes, subject, subjects);
        subject->monitor = monitor;
        subject->flags |= MEDUSA_SUBJECT_FLAG_MOD;
        return 0;
bail:   return -1;
}

__attribute__ ((visibility ("default"))) int medusa_monitor_mod (struct medusa_subject *subject)
{
        if (subject == NULL) {
                goto bail;
        }
        if (subject->monitor == NULL) {
                goto bail;
        }
        if (subject->flags & MEDUSA_SUBJECT_FLAG_DEL) {
        } else if (subject->flags & MEDUSA_SUBJECT_FLAG_MOD) {
        } else if (subject->flags & MEDUSA_SUBJECT_FLAG_ROGUE) {
                TAILQ_REMOVE(&subject->monitor->rogues, subject, subjects);
                TAILQ_INSERT_TAIL(&subject->monitor->changes, subject, subjects);
                subject->flags &= ~MEDUSA_SUBJECT_FLAG_ROGUE;
        } else {
                TAILQ_REMOVE(&subject->monitor->actives, subject, subjects);
                TAILQ_INSERT_TAIL(&subject->monitor->changes, subject, subjects);
        }
        subject->flags |= MEDUSA_SUBJECT_FLAG_MOD;
        return 0;
bail:   return -1;
}

__attribute__ ((visibility ("default"))) int medusa_monitor_del (struct medusa_subject *subject)
{
        int rc;
        if (subject == NULL) {
                goto bail;
        }
        if (subject->monitor == NULL) {
                goto bail;
        }
        if (subject->flags & MEDUSA_SUBJECT_FLAG_DEL) {
        } else if (subject->flags & MEDUSA_SUBJECT_FLAG_MOD) {
                TAILQ_REMOVE(&subject->monitor->changes, subject, subjects);
                TAILQ_INSERT_TAIL(&subject->monitor->deletes, subject, subjects);
        } else if (subject->flags & MEDUSA_SUBJECT_FLAG_ROGUE) {
                TAILQ_REMOVE(&subject->monitor->rogues, subject, subjects);
                TAILQ_INSERT_TAIL(&subject->monitor->deletes, subject, subjects);
                subject->flags &= ~MEDUSA_SUBJECT_FLAG_ROGUE;
        } else {
                TAILQ_REMOVE(&subject->monitor->actives, subject, subjects);
                TAILQ_INSERT_TAIL(&subject->monitor->deletes, subject, subjects);
        }
        subject->flags |= MEDUSA_SUBJECT_FLAG_DEL;
        rc = medusa_monitor_process_deletes(subject->monitor);
        if (rc != 0) {
                goto bail;
        }
        return 0;
bail:   return -1;
}

__attribute__ ((visibility ("default"))) int medusa_monitor_init_options_default (struct medusa_monitor_init_options *options)
{
        if (options == NULL) {
                goto bail;
        }
        memcpy(options, &g_init_options, sizeof(struct medusa_monitor_init_options));
        return 0;
bail:   return -1;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_monitor_create (const struct medusa_monitor_init_options *options)
{
        int rc;
        struct medusa_monitor *monitor;
        monitor = NULL;
        monitor = (struct medusa_monitor *) malloc(sizeof(struct medusa_monitor));
        if (monitor == NULL) {
                goto bail;
        }
        memset(monitor, 0, sizeof(struct medusa_monitor));
        TAILQ_INIT(&monitor->actives);
        TAILQ_INIT(&monitor->changes);
        TAILQ_INIT(&monitor->deletes);
        TAILQ_INIT(&monitor->rogues);
        monitor->running = 1;
        monitor->wakeup.fds[0] = -1;
        monitor->wakeup.fds[1] = -1;
        if (options == NULL) {
                options = &g_init_options;
        }
        if (options->poll.type == MEDUSA_MONITOR_POLL_DEFAULT) {
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
        } else if (options->poll.type == MEDUSA_MONITOR_POLL_EPOLL) {
                monitor->poll.backend = medusa_monitor_epoll_create(NULL);
        } else if (options->poll.type == MEDUSA_MONITOR_POLL_KQUEUE) {
                monitor->poll.backend = medusa_monitor_kqueue_create(NULL);
        } else if (options->poll.type == MEDUSA_MONITOR_POLL_POLL) {
                monitor->poll.backend = medusa_monitor_poll_create(NULL);
        } else if (options->poll.type == MEDUSA_MONITOR_POLL_SELECT) {
                monitor->poll.backend = medusa_monitor_select_create(NULL);
        } else {
                goto bail;
        }
        if (monitor->poll.backend == NULL) {
                goto bail;
        }
        monitor->poll.backend->monitor = monitor;
        if (options->timer.type == MEDUSA_MONITOR_TIMER_DEFAULT) {
                do {
                        monitor->timer.backend = medusa_timer_timerfd_create(NULL);
                        if (monitor->timer.backend != NULL) {
                                break;
                        }
                } while (0);
        } else if (options->timer.type == MEDUSA_MONITOR_TIMER_TIMERFD) {
                monitor->timer.backend = medusa_timer_timerfd_create(NULL);
        } else {
                goto bail;
        }
        if (monitor->timer.backend == NULL) {
                goto bail;
        }
        monitor->timer.backend->monitor = monitor;
        monitor->timer.pqueue = pqueue_create(0, 64, monitor_timer_subject_compare, monitor_timer_subject_set_position, monitor_timer_subject_get_position);
        if (monitor->timer.pqueue == NULL) {
                goto bail;
        }
        rc = pipe(monitor->wakeup.fds);
        if (rc != 0) {
                goto bail;
        }
        rc = fd_set_blocking(monitor->wakeup.fds[0], 0);
        if (rc != 0) {
                goto bail;
        }
        rc = fd_set_blocking(monitor->wakeup.fds[1], 0);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_io_init(monitor, &monitor->wakeup.io, monitor->wakeup.fds[0], monitor_break_io_onevent, NULL);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_io_set_events(&monitor->wakeup.io, MEDUSA_IO_EVENT_IN);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_io_set_enabled(&monitor->wakeup.io, 1);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_io_init(monitor, &monitor->timer.io, monitor->timer.backend->fd(monitor->timer.backend), monitor_timer_io_onevent, NULL);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_io_set_events(&monitor->timer.io, MEDUSA_IO_EVENT_IN);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_io_set_enabled(&monitor->timer.io, 1);
        if (rc != 0) {
                goto bail;
        }
        return monitor;
bail:   if (monitor != NULL) {
                medusa_monitor_destroy(monitor);
        }
        return NULL;
}

__attribute__ ((visibility ("default"))) void medusa_monitor_destroy (struct medusa_monitor *monitor)
{
        struct medusa_io *io;
        struct medusa_timer *timer;
        struct medusa_subject *subject;
        if (monitor == NULL) {
                return;
        }
        while (!TAILQ_EMPTY(&monitor->rogues)) {
                subject = TAILQ_FIRST(&monitor->rogues);
                medusa_monitor_del(subject);
        }
        while (!TAILQ_EMPTY(&monitor->changes)) {
                subject = TAILQ_FIRST(&monitor->changes);
                medusa_monitor_del(subject);
        }
        while (!TAILQ_EMPTY(&monitor->actives)) {
                subject = TAILQ_FIRST(&monitor->actives);
                medusa_monitor_del(subject);
        }
        while (!TAILQ_EMPTY(&monitor->deletes)) {
                subject = TAILQ_FIRST(&monitor->deletes);
                TAILQ_REMOVE(&monitor->deletes, subject, subjects);
                subject->monitor = NULL;
                if (subject->flags & MEDUSA_SUBJECT_FLAG_IO) {
                        io = (struct medusa_io *) subject;
                        if (subject->flags & MEDUSA_SUBJECT_FLAG_POLL) {
                                monitor->poll.backend->del(monitor->poll.backend, io);
                        }
                        medusa_io_onevent(io, MEDUSA_IO_EVENT_DESTROY);
                } else if (subject->flags & MEDUSA_SUBJECT_FLAG_TIMER) {
                        timer = (struct medusa_timer *) subject;
                        if (subject->flags & MEDUSA_SUBJECT_FLAG_HEAP) {
                                pqueue_del(monitor->timer.pqueue, timer);
                        }
                        medusa_timer_onevent(timer, MEDUSA_TIMER_EVENT_DESTROY);
                }
        }
        if (monitor->poll.backend != NULL) {
                monitor->poll.backend->destroy(monitor->poll.backend);
        }
        if (monitor->timer.backend != NULL) {
                monitor->timer.backend->destroy(monitor->timer.backend);
        }
        if (monitor->wakeup.fds[0] >= 0) {
                close(monitor->wakeup.fds[0]);
        }
        if (monitor->wakeup.fds[1] >= 0) {
                close(monitor->wakeup.fds[1]);
        }
        if (monitor->timer.pqueue != NULL) {
                pqueue_destroy(monitor->timer.pqueue);
        }
        free(monitor);
}

__attribute__ ((visibility ("default"))) int medusa_monitor_get_running (struct medusa_monitor *monitor)
{
        if (monitor == NULL) {
                return -1;
        }
        return monitor->running;
}

__attribute__ ((visibility ("default"))) int medusa_monitor_break (struct medusa_monitor *monitor)
{
        return medusa_monitor_signal(monitor, WAKEUP_REASON_LOOP_BREAK);
}

__attribute__ ((visibility ("default"))) int medusa_monitor_continue (struct medusa_monitor *monitor)
{
        return medusa_monitor_signal(monitor, WAKEUP_REASON_LOOP_CONTINUE);
}

__attribute__ ((visibility ("default"))) int medusa_monitor_run_once (struct medusa_monitor *monitor)
{
        int rc;

        if (monitor == NULL) {
                goto bail;
        }

        rc = medusa_monitor_process_deletes(monitor);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_monitor_process_changes(monitor);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_monitor_setup_timer(monitor);
        if (rc != 0) {
                goto bail;
        }
        rc = monitor->poll.backend->run(monitor->poll.backend, NULL);
        if (rc < 0) {
                goto bail;
        }
        rc = medusa_monitor_check_timer(monitor);
        if (rc != 0) {
                goto bail;
        }

        return 0;
bail:   return -1;
}

__attribute__ ((visibility ("default"))) int medusa_monitor_run_timeout (struct medusa_monitor *monitor, double timeout)
{
        int rc;
        int count;
        struct timespec timespec;

        if (monitor == NULL) {
                goto bail;
        }

        timespec.tv_sec = timeout;
        timespec.tv_nsec = (timeout - timespec.tv_sec) * 1e9;

        rc = medusa_monitor_process_deletes(monitor);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_monitor_process_changes(monitor);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_monitor_setup_timer(monitor);
        if (rc != 0) {
                goto bail;
        }
        count = monitor->poll.backend->run(monitor->poll.backend, &timespec);
        if (count < 0) {
                goto bail;
        }
        rc = medusa_monitor_check_timer(monitor);
        if (rc != 0) {
                goto bail;
        }

        return count;
bail:   return -1;
}

__attribute__ ((visibility ("default"))) int medusa_monitor_run (struct medusa_monitor *monitor)
{
        int rc;

        if (monitor == NULL) {
                goto bail;
        }

        while (monitor->running) {
                rc = medusa_monitor_process_deletes(monitor);
                if (rc != 0) {
                        goto bail;
                }
                rc = medusa_monitor_process_changes(monitor);
                if (rc != 0) {
                        goto bail;
                }
                rc = medusa_monitor_setup_timer(monitor);
                if (rc != 0) {
                        goto bail;
                }
                rc = monitor->poll.backend->run(monitor->poll.backend, NULL);
                if (rc < 0) {
                        goto bail;
                }
                rc = medusa_monitor_check_timer(monitor);
                if (rc != 0) {
                        goto bail;
                }
        }

        return 0;
bail:   return -1;
}
