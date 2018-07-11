
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "queue.h"
#include "pqueue.h"

#include "time.h"
#include "clock.h"
#include "event.h"
#include "subject.h"
#include "io.h"
#include "timer.h"
#include "monitor.h"

#include "subject-struct.h"
#include "io-struct.h"
#include "timer-struct.h"

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
        struct medusa_subjects subjects;
        struct medusa_subjects changes;
        struct medusa_subjects rogues;
        struct {
                struct medusa_poll_backend *backend;
        } poll;
        struct {
                struct medusa_timer_backend *backend;
                struct pqueue_head pqueue;
                int dirty;
        } timer;
        int wakeup_fds[2];
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

static void monitor_break_subject_callback (struct medusa_io *io, unsigned int events)
{
        int rc;
        unsigned int reason;
        if (events & MEDUSA_EVENT_IN) {
                rc = read(io->subject.monitor->wakeup_fds[0], &reason, sizeof(reason));
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
        return;
bail:   return;
}

static void monitor_timer_subject_callback (struct medusa_io *io, unsigned int events)
{
        int rc;

        uint64_t value;
        struct medusa_timer *timer;
        struct medusa_timespec now;

        if (events & MEDUSA_EVENT_IN) {
                rc = read(io->fd, &value, sizeof(value));
                if (rc != sizeof(value)) {
                        goto bail;
                }

                rc = clock_boottime(&now);
                if (rc != 0) {
                        goto bail;
                }
                while (1) {
                        timer = pqueue_peek(&io->subject.monitor->timer.pqueue);
                        if (timer == NULL) {
                                break;
                        }
                        if (medusa_timespec_compare(&timer->_timespec, &now, >)) {
                                break;
                        }
                        timer = pqueue_pop(&timer->subject.monitor->timer.pqueue);
                        if (timer == NULL) {
                                break;
                        }
                        timer->subject.flags &= ~MEDUSA_SUBJECT_FLAG_POLL;
                        timer->subject.monitor->timer.dirty = 1;
                        if (timer->single_shot != 0) {
                                timer->active = 0;
                        }
                        rc = medusa_monitor_mod(timer->subject.monitor, &timer->subject);
                        if (rc != 0) {
                                goto bail;
                        }
                        rc = timer->subject.event(&timer->subject, MEDUSA_EVENT_TIMEOUT);
                        if (rc != 0) {
                                goto bail;
                        }
                }

        }
        return;
bail:   return;
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

static void monitor_timer_subject_position (void *entry, unsigned int position)
{
        struct medusa_timer *timer = entry;
        timer->_position = position;
}

static int medusa_monitor_apply_changes (struct medusa_monitor *monitor)
{
        int rc;
        struct medusa_io *io;
        struct medusa_timer *timer;
        struct medusa_subject *subject;
        struct medusa_subject *nsubject;
        struct medusa_timespec now;
        rc = clock_boottime(&now);
        if (rc != 0) {
                goto bail;
        }
        TAILQ_FOREACH_SAFE(subject, &monitor->changes, subjects, nsubject) {
                if (subject->flags & MEDUSA_SUBJECT_FLAG_DEL) {
                        if (subject->type == MEDUSA_SUBJECT_TYPE_IO) {
                                io = (struct medusa_io *) subject;
                                if (subject->flags & MEDUSA_SUBJECT_FLAG_POLL) {
                                        rc = monitor->poll.backend->del(monitor->poll.backend, io);
                                        if (rc != 0) {
                                                goto bail;
                                        }
                                }
                        } else if (subject->type == MEDUSA_SUBJECT_TYPE_TIMER) {
                                timer = (struct medusa_timer *) subject;
                                if (subject->flags & MEDUSA_SUBJECT_FLAG_POLL) {
                                        rc = pqueue_del(&monitor->timer.pqueue, timer->_position);
                                        if (rc != 0) {
                                                goto bail;
                                        }
                                        monitor->timer.dirty = 1;
                                }
                        }
                        TAILQ_REMOVE(&monitor->changes, subject, subjects);
                        medusa_subject_destroy(subject);
                        continue;
                }
                if (subject->type == MEDUSA_SUBJECT_TYPE_IO) {
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
                                TAILQ_INSERT_TAIL(&monitor->subjects, subject, subjects);
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_MOD;
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_ROGUE;
                                subject->flags |= MEDUSA_SUBJECT_FLAG_POLL;
                        }
                } else if (subject->type == MEDUSA_SUBJECT_TYPE_TIMER) {
                        timer = (struct medusa_timer *) subject;
                        if (!medusa_timer_is_valid(timer)) {
                                if (subject->flags & MEDUSA_SUBJECT_FLAG_POLL) {
                                        rc = pqueue_del(&monitor->timer.pqueue, timer->_position);
                                        if (rc != 0) {
                                                goto bail;
                                        }
                                        monitor->timer.dirty = 1;
                                }
                                TAILQ_REMOVE(&monitor->changes, subject, subjects);
                                TAILQ_INSERT_TAIL(&monitor->rogues, subject, subjects);
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_MOD;
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_POLL;
                                subject->flags |= MEDUSA_SUBJECT_FLAG_ROGUE;
                        } else {
                                if (medusa_timespec_isset(&timer->_timespec)) {
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
                                if (subject->flags & MEDUSA_SUBJECT_FLAG_POLL) {
                                        rc = pqueue_del(&monitor->timer.pqueue, timer->_position);
                                        if (rc != 0) {
                                                goto bail;
                                        }
                                        monitor->timer.dirty = 1;
                                }
                                rc = pqueue_add(&monitor->timer.pqueue, subject);
                                if (rc != 0) {
                                        goto bail;
                                }
                                TAILQ_REMOVE(&monitor->changes, subject, subjects);
                                TAILQ_INSERT_TAIL(&monitor->subjects, subject, subjects);
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_MOD;
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_ROGUE;
                                subject->flags |= MEDUSA_SUBJECT_FLAG_POLL;
                                monitor->timer.dirty = 1;
                        }
                }
        }
        if (monitor->timer.dirty != 0) {
                timer = pqueue_peek(&monitor->timer.pqueue);
                if (timer == NULL) {
                        rc = monitor->timer.backend->set(monitor->timer.backend, NULL);
                        if (rc != 0) {
                                goto bail;
                        }
                } else {
                        rc = monitor->timer.backend->set(monitor->timer.backend, &timer->_timespec);
                        if (rc != 0) {
                                goto bail;
                        }
                }
        }
        return 0;
bail:   return -1;
}

static int medusa_monitor_signal (struct medusa_monitor *monitor, unsigned int reason)
{
        int rc;
        rc = write(monitor->wakeup_fds[1], &reason, sizeof(reason));
        if (rc != sizeof(reason)) {
                goto bail;
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
        struct medusa_io *io;
        struct medusa_monitor *monitor;
        monitor = NULL;
        monitor = (struct medusa_monitor *) malloc(sizeof(struct medusa_monitor));
        if (monitor == NULL) {
                goto bail;
        }
        memset(monitor, 0, sizeof(struct medusa_monitor));
        TAILQ_INIT(&monitor->subjects);
        TAILQ_INIT(&monitor->changes);
        TAILQ_INIT(&monitor->rogues);
        pqueue_init(&monitor->timer.pqueue, 0, 64, monitor_timer_subject_compare, monitor_timer_subject_position);
        monitor->running = 1;
        monitor->wakeup_fds[0] = -1;
        monitor->wakeup_fds[1] = -1;
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
        rc = pipe(monitor->wakeup_fds);
        if (rc != 0) {
                goto bail;
        }
        rc = fd_set_blocking(monitor->wakeup_fds[0], 0);
        if (rc != 0) {
                goto bail;
        }
        rc = fd_set_blocking(monitor->wakeup_fds[1], 0);
        if (rc != 0) {
                goto bail;
        }
        io = medusa_io_create();
        if (io == NULL) {
                goto bail;
        }
        rc = medusa_io_set_fd(io, monitor->wakeup_fds[0]);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_io_set_events(io, MEDUSA_EVENT_IN);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_io_set_activated_callback(io, monitor_break_subject_callback, NULL);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_io_set_enabled(io, 1);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_monitor_add(monitor, &io->subject);
        if (rc != 0) {
                goto bail;
        }
        io = medusa_io_create();
        if (io == NULL) {
                goto bail;
        }
        rc = medusa_io_set_fd(io, monitor->timer.backend->fd(monitor->timer.backend));
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_io_set_events(io, MEDUSA_EVENT_IN);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_io_set_activated_callback(io, monitor_timer_subject_callback, NULL);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_io_set_enabled(io, 1);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_monitor_add(monitor, &io->subject);
        if (rc != 0) {
                goto bail;
        }
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
        TAILQ_FOREACH_SAFE(subject, &monitor->rogues, subjects, nsubject) {
                medusa_monitor_del(monitor, subject);
        }
        TAILQ_FOREACH_SAFE(subject, &monitor->subjects, subjects, nsubject) {
                medusa_monitor_del(monitor, subject);
        }
        TAILQ_FOREACH_SAFE(subject, &monitor->changes, subjects, nsubject) {
                subject->flags |= MEDUSA_SUBJECT_FLAG_DEL;
                TAILQ_REMOVE(&monitor->changes, subject, subjects);
                if ((subject->type == MEDUSA_SUBJECT_TYPE_IO) &&
                    (subject->flags & MEDUSA_SUBJECT_FLAG_POLL)) {
                        monitor->poll.backend->del(monitor->poll.backend, (struct medusa_io *) subject);
                }
                medusa_subject_destroy(subject);
        }
        if (monitor->poll.backend != NULL) {
                monitor->poll.backend->destroy(monitor->poll.backend);
        }
        if (monitor->timer.backend != NULL) {
                monitor->timer.backend->destroy(monitor->timer.backend);
        }
        if (monitor->wakeup_fds[0] >= 0) {
                close(monitor->wakeup_fds[0]);
        }
        if (monitor->wakeup_fds[1] >= 0) {
                close(monitor->wakeup_fds[1]);
        }
        pqueue_uninit(&monitor->timer.pqueue);
        free(monitor);
}

int medusa_monitor_add (struct medusa_monitor *monitor, struct medusa_subject *subject)
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
        subject->flags = MEDUSA_SUBJECT_FLAG_MOD;
        return 0;
bail:   return -1;
}

int medusa_monitor_mod (struct medusa_monitor *monitor, struct medusa_subject *subject)
{
        if (monitor == NULL) {
                goto bail;
        }
        if (subject == NULL) {
                goto bail;
        }
        if (subject->monitor == NULL) {
                goto bail;
        }
        if (subject->flags & MEDUSA_SUBJECT_FLAG_MOD) {
                TAILQ_REMOVE(&monitor->changes, subject, subjects);
                TAILQ_INSERT_TAIL(&monitor->changes, subject, subjects);
                subject->flags &= ~MEDUSA_SUBJECT_FLAG_MOD;
        } else if (subject->flags & MEDUSA_SUBJECT_FLAG_ROGUE) {
                TAILQ_REMOVE(&monitor->rogues, subject, subjects);
                TAILQ_INSERT_TAIL(&monitor->changes, subject, subjects);
                subject->flags &= ~MEDUSA_SUBJECT_FLAG_ROGUE;
        } else {
                TAILQ_REMOVE(&monitor->subjects, subject, subjects);
                TAILQ_INSERT_TAIL(&monitor->changes, subject, subjects);
        }
        subject->flags |= MEDUSA_SUBJECT_FLAG_MOD;
        return 0;
bail:   return -1;
}

int medusa_monitor_del (struct medusa_monitor *monitor, struct medusa_subject *subject)
{
        if (monitor == NULL) {
                goto bail;
        }
        if (subject == NULL) {
                goto bail;
        }
        if (subject->monitor == NULL) {
                goto bail;
        }
        if (subject->flags & MEDUSA_SUBJECT_FLAG_DEL) {
                return 0;
        }
        if (subject->flags & MEDUSA_SUBJECT_FLAG_MOD) {
                TAILQ_REMOVE(&monitor->changes, subject, subjects);
                TAILQ_INSERT_TAIL(&monitor->changes, subject, subjects);
                subject->flags &= ~MEDUSA_SUBJECT_FLAG_MOD;
        } else if (subject->flags & MEDUSA_SUBJECT_FLAG_ROGUE) {
                TAILQ_REMOVE(&monitor->rogues, subject, subjects);
                TAILQ_INSERT_TAIL(&monitor->changes, subject, subjects);
                subject->flags &= ~MEDUSA_SUBJECT_FLAG_ROGUE;
        } else {
                TAILQ_REMOVE(&monitor->subjects, subject, subjects);
                TAILQ_INSERT_TAIL(&monitor->changes, subject, subjects);
        }
        subject->flags |= MEDUSA_SUBJECT_FLAG_DEL;
        return 0;
bail:   return -1;
}

int medusa_monitor_break (struct medusa_monitor *monitor)
{
        return medusa_monitor_signal(monitor, WAKEUP_REASON_LOOP_BREAK);
}

int medusa_monitor_continue (struct medusa_monitor *monitor)
{
        return medusa_monitor_signal(monitor, WAKEUP_REASON_LOOP_CONTINUE);
}

int medusa_monitor_run (struct medusa_monitor *monitor)
{
        int rc;

        if (monitor == NULL) {
                goto bail;
        }

        while (monitor->running) {
                rc = medusa_monitor_apply_changes(monitor);
                if (rc != 0) {
                        goto bail;
                }
                rc = monitor->poll.backend->run(monitor->poll.backend, NULL);
                if (rc != 0) {
                        goto bail;
                }
        }

        return 0;
bail:   return -1;
}

int medusa_monitor_run_once (struct medusa_monitor *monitor)
{
        int rc;

        if (monitor == NULL) {
                goto bail;
        }

        rc = medusa_monitor_apply_changes(monitor);
        if (rc != 0) {
                goto bail;
        }
        rc = monitor->poll.backend->run(monitor->poll.backend, NULL);
        if (rc != 0) {
                goto bail;
        }

        return 0;
bail:   return -1;
}

int medusa_monitor_run_timeout (struct medusa_monitor *monitor, double timeout)
{
        int rc;
        struct medusa_timespec timeout_timespec;

        if (monitor == NULL) {
                goto bail;
        }

        timeout_timespec.seconds = timeout;
        timeout_timespec.nanoseconds = (timeout - timeout_timespec.seconds) * 1e9;

        rc = medusa_monitor_apply_changes(monitor);
        if (rc != 0) {
                goto bail;
        }
        rc = monitor->poll.backend->run(monitor->poll.backend, &timeout_timespec);
        if (rc != 0) {
                goto bail;
        }

        return 0;
bail:   return -1;
}
