
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>

#include "queue.h"
#include "pqueue.h"

#include "error.h"
#include "clock.h"
#include "io.h"
#include "io-private.h"
#include "timer.h"
#include "timer-private.h"
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
        WAKEUP_REASON_NONE,
        WAKEUP_REASON_LOOP_BREAK,
        WAKEUP_REASON_LOOP_CONTINUE,
        WAKEUP_REASON_SUBJECT_ADD,
        WAKEUP_REASON_SUBJECT_MOD,
        WAKEUP_REASON_SUBJECT_DEL,
};

struct medusa_monitor {
        int running;
        unsigned int flags;
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
                int fired;
                struct medusa_io io;
        } wakeup;
        pthread_mutex_t mutex;
};

static const struct medusa_monitor_init_options g_init_options = {
        .flags  = MEDUSA_MONITOR_FLAG_DEFAULT,
        .poll   = {
                .type   = MEDUSA_MONITOR_POLL_DEFAULT,
                .u      = { }
        },
        .timer  = {
                .type   = MEDUSA_MONITOR_TIMER_DEFAULT,
                .u      = { }
        },
};

static int fd_set_blocking (int fd, int on)
{
        int rc;
        int flags;
        if (fd < 0) {
                return -EINVAL;
        }
        flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0) {
                return -errno;
        }
        flags = on ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
        rc = fcntl(fd, F_SETFL, flags);
        if (rc != 0) {
                return -errno;
        }
        return 0;
}

static int monitor_wakeup_io_onevent (struct medusa_io *io, unsigned int events, void *context, ...)
{
        int rc;
        unsigned int reason;
        struct medusa_monitor *monitor = (struct medusa_monitor *) context;
        if (events & MEDUSA_IO_EVENT_IN) {
                while (1) {
                        rc = read(io->fd, &reason, sizeof(reason));
                        if (rc == 0) {
                                break;
                        } else if (rc < 0) {
                                if (errno == EAGAIN ||
                                    errno == EWOULDBLOCK ||
                                    errno == EINTR) {
                                        break;
                                }
                                goto bail;
                        } else if (rc != sizeof(reason)) {
                                goto bail;
                        }
                }
                medusa_monitor_lock(monitor);
                monitor->wakeup.fired = 0;
                medusa_monitor_unlock(monitor);
        }
        return 0;
bail:   return -1;
}

static int monitor_timer_io_onevent (struct medusa_io *io, unsigned int events, void *context, ...)
{
        int rc;
        uint64_t value;
        struct medusa_monitor *monitor = context;
        if (events & MEDUSA_IO_EVENT_IN) {
                while (1) {
                        rc = read(io->fd, &value, sizeof(value));
                        if (rc == 0) {
                                break;
                        } else if (rc < 0) {
                                if (errno == EAGAIN ||
                                    errno == EWOULDBLOCK ||
                                    errno == EINTR) {
                                        break;
                                }
                                goto bail;
                        } else if (rc != sizeof(value)) {
                                goto bail;
                        }
                }
                medusa_monitor_lock(monitor);
                monitor->timer.fired = 1;
                medusa_monitor_unlock(monitor);
        }
        return 0;
bail:   return -1;
}

static int monitor_timer_subject_compare (void *a, void *b)
{
        struct medusa_timer *ta = a;
        struct medusa_timer *tb = b;
        return medusa_timespec_compare(&ta->_timespec, &tb->_timespec, >);
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

static int monitor_process_deletes (struct medusa_monitor *monitor)
{
        int rc;
        struct medusa_io *io;
        struct medusa_timer *timer;
        struct medusa_subject *subject;
        while (!TAILQ_EMPTY(&monitor->deletes)) {
                subject = TAILQ_FIRST(&monitor->deletes);
                TAILQ_REMOVE(&monitor->deletes, subject, list);
                subject->monitor = NULL;
                if (subject->flags & MEDUSA_SUBJECT_TYPE_IO) {
                        io = (struct medusa_io *) subject;
                        if (subject->flags & MEDUSA_SUBJECT_FLAG_POLL) {
                                rc = monitor->poll.backend->del(monitor->poll.backend, io);
                                if (rc != 0) {
                                        goto bail;
                                }
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_POLL;
                        }
                        medusa_monitor_unlock(monitor);
                        rc = medusa_io_onevent_unlocked(io, MEDUSA_IO_EVENT_DESTROY);
                        medusa_monitor_lock(monitor);
                        if (rc < 0) {
                                goto bail;
                        }
                } else if (subject->flags & MEDUSA_SUBJECT_TYPE_TIMER) {
                        timer = (struct medusa_timer *) subject;
                        if (subject->flags & MEDUSA_SUBJECT_FLAG_HEAP) {
                                rc = pqueue_del(monitor->timer.pqueue, timer);
                                if (rc != 0) {
                                        goto bail;
                                }
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_HEAP;
                                monitor->timer.dirty = 1;
                        }
                        medusa_monitor_unlock(monitor);
                        rc = medusa_timer_onevent_unlocked(timer, MEDUSA_TIMER_EVENT_DESTROY);
                        medusa_monitor_lock(monitor);
                        if (rc < 0) {
                                goto bail;
                        }
                }
        }
        return 0;
bail:   return -1;
}

static int monitor_process_changes (struct medusa_monitor *monitor)
{
        int rc;
        struct timespec now;
        struct medusa_io *io;
        struct medusa_timer *timer;
        struct medusa_subject *subject;
        struct medusa_subject *nsubject;
        rc = medusa_clock_monotonic(&now);
        if (rc < 0) {
                goto bail;
        }
        TAILQ_FOREACH_SAFE(subject, &monitor->changes, list, nsubject) {
                if (subject->flags & MEDUSA_SUBJECT_TYPE_IO) {
                        io = (struct medusa_io *) subject;
                        if (!medusa_io_is_valid_unlocked(io)) {
                                if (subject->flags & MEDUSA_SUBJECT_FLAG_POLL) {
                                        rc = monitor->poll.backend->del(monitor->poll.backend, io);
                                        if (rc != 0) {
                                                goto bail;
                                        }
                                }
                                TAILQ_REMOVE(&monitor->changes, subject, list);
                                TAILQ_INSERT_TAIL(&monitor->rogues, subject, list);
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
                                TAILQ_REMOVE(&monitor->changes, subject, list);
                                TAILQ_INSERT_TAIL(&monitor->actives, subject, list);
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_MOD;
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_ROGUE;
                                subject->flags |= MEDUSA_SUBJECT_FLAG_POLL;
                        }
                } else if (subject->flags & MEDUSA_SUBJECT_TYPE_TIMER) {
                        timer = (struct medusa_timer *) subject;
                        if (!medusa_timer_is_valid_unlocked(timer) ||
                            (medusa_timespec_isset(&timer->_timespec) && !medusa_timespec_isset(&timer->interval))) {
                                if (subject->flags & MEDUSA_SUBJECT_FLAG_HEAP) {
                                        rc = pqueue_del(monitor->timer.pqueue, timer);
                                        if (rc != 0) {
                                                goto bail;
                                        }
                                        monitor->timer.dirty = 1;
                                }
                                medusa_timespec_clear(&timer->_timespec);
                                TAILQ_REMOVE(&monitor->changes, subject, list);
                                TAILQ_INSERT_TAIL(&monitor->rogues, subject, list);
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_MOD;
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_HEAP;
                                subject->flags |= MEDUSA_SUBJECT_FLAG_ROGUE;
                        } else {
                                unsigned int resolution;
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
                                resolution = medusa_timer_get_resolution_unlocked(timer);
                                if (resolution == MEDUSA_TIMER_RESOLUTION_NANOSECOMDS) {
                                } else if (resolution == MEDUSA_TIMER_RESOLUTION_MICROSECONDS) {
                                        timer->_timespec.tv_nsec += 500;
                                        timer->_timespec.tv_nsec /= 1e3;
                                        timer->_timespec.tv_nsec *= 1e3;
                                } else if (resolution == MEDUSA_TIMER_RESOLUTION_MILLISECONDS) {
                                        timer->_timespec.tv_nsec += 500000;
                                        timer->_timespec.tv_nsec /= 1e6;
                                        timer->_timespec.tv_nsec *= 1e6;
                                } else if (resolution == MEDUSA_TIMER_RESOLUTION_SECONDS) {
                                        timer->_timespec.tv_nsec += 500000000;
                                        timer->_timespec.tv_nsec /= 1e9;
                                        timer->_timespec.tv_nsec *= 1e9;
                                }
                                if (timer->_timespec.tv_nsec >= 1000000000) {
                                        timer->_timespec.tv_sec++;
                                        timer->_timespec.tv_nsec -= 1000000000;
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
                                TAILQ_REMOVE(&monitor->changes, subject, list);
                                TAILQ_INSERT_TAIL(&monitor->actives, subject, list);
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

static int monitor_setup_timer (struct medusa_monitor *monitor)
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

static __attribute__ ((__unused__))  int monitor_hit_timer (void *context, void *a)
{
        int rc;
        struct medusa_timer *timer = a;
        struct medusa_monitor *monitor = context;
        (void) monitor;
        if (medusa_timer_get_singleshot_unlocked(timer) ||
            !medusa_timespec_isset(&timer->interval)) {
                rc = medusa_timer_set_enabled_unlocked(timer, 0);
                if (rc < 0) {
                        goto bail;
                }
        }
        rc = medusa_monitor_mod_unlocked(&timer->subject);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_timer_onevent_unlocked(timer, MEDUSA_TIMER_EVENT_TIMEOUT);
        if (rc != 0) {
                goto bail;
        }
        return 0;
bail:   return -1;
}

static int monitor_check_timer (struct medusa_monitor *monitor)
{
        int rc;
        struct timespec now;
        rc = medusa_clock_monotonic(&now);
        if (rc < 0) {
                goto bail;
        }
        if (monitor->timer.fired != 0) {
#if 0
                struct medusa_timer *timer;
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
                        monitor->timer.dirty = 1;
                        if (medusa_timer_get_singleshot_unlocked(timer) ||
                            !medusa_timespec_isset(&timer->interval)) {
                                rc = medusa_timer_set_enabled_unlocked(timer, 0);
                                if (rc < 0) {
                                        goto bail;
                                }
                        }
                        rc = medusa_monitor_mod_unlocked(&timer->subject);
                        if (rc != 0) {
                                goto bail;
                        }
                        rc = medusa_timer_onevent_unlocked(timer, MEDUSA_TIMER_EVENT_TIMEOUT);
                        if (rc != 0) {
                                goto bail;
                        }
                }
#else
                struct medusa_timer tk;
                tk._timespec = now;
                rc = pqueue_search(monitor->timer.pqueue, &tk, monitor_hit_timer, monitor);
                if (rc != 0) {
                        goto bail;
                }
#endif
                monitor->timer.fired = 0;
        }
        return 0;
bail:   return -1;
}

static int monitor_signal (struct medusa_monitor *monitor, unsigned int reason)
{
        int rc;
        if (monitor->wakeup.fired == 0) {
                rc = write(monitor->wakeup.fds[1], &reason, sizeof(reason));
                if (rc != sizeof(reason)) {
                        goto bail;
                }
                monitor->wakeup.fired = 1;
        }
        if (reason == WAKEUP_REASON_LOOP_BREAK) {
                monitor->running = 0;
        } else if (reason == WAKEUP_REASON_LOOP_CONTINUE) {
                monitor->running = 1;
        }
        return 0;
bail:   return -1;
}

__attribute__ ((visibility ("default"))) int medusa_monitor_lock (struct medusa_monitor *monitor)
{
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return -EINVAL;
        }
        if (monitor->flags & MEDUSA_MONITOR_FLAG_THREAD_SAFE) {
                pthread_mutex_lock(&monitor->mutex);
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_monitor_unlock (struct medusa_monitor *monitor)
{
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return -EINVAL;
        }
        if (monitor->flags & MEDUSA_MONITOR_FLAG_THREAD_SAFE) {
                pthread_mutex_unlock(&monitor->mutex);
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_monitor_add_unlocked (struct medusa_monitor *monitor, struct medusa_subject *subject)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(subject)) {
                return -EINVAL;
        }
        if (!MEDUSA_IS_ERR_OR_NULL(subject->monitor)) {
                return -EALREADY;
        }
        TAILQ_INSERT_TAIL(&monitor->changes, subject, list);
        subject->monitor = monitor;
        subject->flags |= MEDUSA_SUBJECT_FLAG_MOD;
        rc = monitor_signal(monitor, WAKEUP_REASON_SUBJECT_ADD);
        if (rc < 0) {
                return rc;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_monitor_add (struct medusa_monitor *monitor, struct medusa_subject *subject)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(subject)) {
                return -EINVAL;
        }
        if (!MEDUSA_IS_ERR_OR_NULL(subject->monitor)) {
                return -EALREADY;
        }
        medusa_monitor_lock(monitor);
        rc = medusa_monitor_add_unlocked(monitor, subject);
        medusa_monitor_unlock(monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_monitor_mod_unlocked (struct medusa_subject *subject)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(subject)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(subject->monitor)) {
                return -EINVAL;
        }
        if (subject->flags & MEDUSA_SUBJECT_FLAG_DEL) {
                return 0;
        } else if (subject->flags & MEDUSA_SUBJECT_FLAG_MOD) {
                return 0;
        } else if (subject->flags & MEDUSA_SUBJECT_FLAG_ROGUE) {
                TAILQ_REMOVE(&subject->monitor->rogues, subject, list);
                TAILQ_INSERT_TAIL(&subject->monitor->changes, subject, list);
                subject->flags &= ~MEDUSA_SUBJECT_FLAG_ROGUE;
        } else {
                TAILQ_REMOVE(&subject->monitor->actives, subject, list);
                TAILQ_INSERT_TAIL(&subject->monitor->changes, subject, list);
        }
        subject->flags |= MEDUSA_SUBJECT_FLAG_MOD;
        if (1) {
                rc = 0;
                if (subject->flags & MEDUSA_SUBJECT_TYPE_IO) {
                        struct medusa_io *io;
                        io = (struct medusa_io *) subject;
                        if (!medusa_io_is_valid_unlocked(io) &&
                            (subject->flags & MEDUSA_SUBJECT_FLAG_POLL)) {
                                rc = subject->monitor->poll.backend->del(subject->monitor->poll.backend, io);
                                if (rc < 0) {
                                        goto out;
                                }
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_POLL;
                        }
#if 0
                } else if (subject->flags & MEDUSA_SUBJECT_TYPE_TIMER) {
                        struct medusa_timer *timer;
                        timer = (struct medusa_timer *) subject;
                        if (!medusa_timer_is_valid_unlocked(timer) &&
                            (subject->flags & MEDUSA_SUBJECT_FLAG_HEAP)) {
                                rc = pqueue_del(subject->monitor->timer.pqueue, timer);
                                if (rc < 0) {
                                        goto out;
                                }
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_HEAP;
                                subject->monitor->timer.dirty = 1;
                        }
#endif
                }
        }
        rc = monitor_signal(subject->monitor, WAKEUP_REASON_SUBJECT_MOD);
        if (rc < 0) {
                return rc;
        }
out:    return rc;
}

__attribute__ ((visibility ("default"))) int medusa_monitor_mod (struct medusa_subject *subject)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(subject)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(subject->monitor)) {
                return -EINVAL;
        }
        medusa_monitor_lock(subject->monitor);
        rc = medusa_monitor_mod_unlocked(subject);
        medusa_monitor_unlock(subject->monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_monitor_del_unlocked (struct medusa_subject *subject)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(subject)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(subject->monitor)) {
                return -EINVAL;
        }
        if (subject->flags & MEDUSA_SUBJECT_FLAG_DEL) {
                return 0;
        } else if (subject->flags & MEDUSA_SUBJECT_FLAG_MOD) {
                TAILQ_REMOVE(&subject->monitor->changes, subject, list);
                TAILQ_INSERT_TAIL(&subject->monitor->deletes, subject, list);
        } else if (subject->flags & MEDUSA_SUBJECT_FLAG_ROGUE) {
                TAILQ_REMOVE(&subject->monitor->rogues, subject, list);
                TAILQ_INSERT_TAIL(&subject->monitor->deletes, subject, list);
                subject->flags &= ~MEDUSA_SUBJECT_FLAG_ROGUE;
        } else {
                TAILQ_REMOVE(&subject->monitor->actives, subject, list);
                TAILQ_INSERT_TAIL(&subject->monitor->deletes, subject, list);
        }
        subject->flags |= MEDUSA_SUBJECT_FLAG_DEL;
        {
                rc = 0;
                if (subject->flags & MEDUSA_SUBJECT_TYPE_IO) {
                        struct medusa_io *io;
                        io = (struct medusa_io *) subject;
                        if (subject->flags & MEDUSA_SUBJECT_FLAG_POLL) {
                                rc = subject->monitor->poll.backend->del(subject->monitor->poll.backend, io);
                                if (rc < 0) {
                                        goto out;
                                }
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_POLL;
                        }
                } else if (subject->flags & MEDUSA_SUBJECT_TYPE_TIMER) {
                        struct medusa_timer *timer;
                        timer = (struct medusa_timer *) subject;
                        if (subject->flags & MEDUSA_SUBJECT_FLAG_HEAP) {
                                rc = pqueue_del(subject->monitor->timer.pqueue, timer);
                                if (rc < 0) {
                                        goto out;
                                }
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_HEAP;
                                subject->monitor->timer.dirty = 1;
                        }
                }
        }
        rc = monitor_signal(subject->monitor, WAKEUP_REASON_SUBJECT_DEL);
        if (rc < 0) {
                return rc;
        }
out:    return rc;
}

__attribute__ ((visibility ("default"))) int medusa_monitor_del (struct medusa_subject *subject)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(subject)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(subject->monitor)) {
                return -EINVAL;
        }
        medusa_monitor_lock(subject->monitor);
        rc = medusa_monitor_del_unlocked(subject);
        medusa_monitor_unlock(subject->monitor);
        return rc;
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
        if (options == NULL) {
                options = &g_init_options;
        }
        monitor = (struct medusa_monitor *) malloc(sizeof(struct medusa_monitor));
        if (monitor == NULL) {
                goto bail;
        }
        memset(monitor, 0, sizeof(struct medusa_monitor));
        TAILQ_INIT(&monitor->actives);
        TAILQ_INIT(&monitor->changes);
        TAILQ_INIT(&monitor->deletes);
        TAILQ_INIT(&monitor->rogues);
        monitor->flags = options->flags;
        if (monitor->flags & MEDUSA_MONITOR_FLAG_THREAD_SAFE) {
                pthread_mutex_init(&monitor->mutex, NULL);
        }
        monitor->running = 1;
        monitor->wakeup.fds[0] = -1;
        monitor->wakeup.fds[1] = -1;
        if (options->poll.type == MEDUSA_MONITOR_POLL_DEFAULT) {
                do {
#if defined(__LINUX__) && (__LINUX__ == 1)
                        monitor->poll.backend = medusa_monitor_epoll_create(NULL);
                        if (monitor->poll.backend != NULL) {
                                break;
                        }
#endif
#if defined(__DARWIN__) && (__DARWIN__ == 1)
                        monitor->poll.backend = medusa_monitor_kqueue_create(NULL);
                        if (monitor->poll.backend != NULL) {
                                break;
                        }
#endif
                        monitor->poll.backend = medusa_monitor_poll_create(NULL);
                        if (monitor->poll.backend != NULL) {
                                break;
                        }
                        monitor->poll.backend = medusa_monitor_select_create(NULL);
                        if (monitor->poll.backend != NULL) {
                                break;
                        }
                } while (0);
#if defined(__LINUX__) && (__LINUX__ == 1)
        } else if (options->poll.type == MEDUSA_MONITOR_POLL_EPOLL) {
                monitor->poll.backend = medusa_monitor_epoll_create(NULL);
#endif
#if defined(__DARWIN__) && (__DARWIN__ == 1)
        } else if (options->poll.type == MEDUSA_MONITOR_POLL_KQUEUE) {
                monitor->poll.backend = medusa_monitor_kqueue_create(NULL);
#endif
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
#if defined(__LINUX__) && (__LINUX__ == 1)
                        monitor->timer.backend = medusa_timer_timerfd_create(NULL);
                        if (monitor->timer.backend != NULL) {
                                break;
                        }
#endif
                } while (0);
#if defined(__LINUX__) && (__LINUX__ == 1)
        } else if (options->timer.type == MEDUSA_MONITOR_TIMER_TIMERFD) {
                monitor->timer.backend = medusa_timer_timerfd_create(NULL);
#endif
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
        rc = medusa_io_init(&monitor->wakeup.io, monitor, monitor->wakeup.fds[0], monitor_wakeup_io_onevent, monitor);
        if (rc < 0) {
                goto bail;
        }
        rc = medusa_io_set_events(&monitor->wakeup.io, MEDUSA_IO_EVENT_IN);
        if (rc < 0) {
                goto bail;
        }
        rc = medusa_io_set_enabled(&monitor->wakeup.io, 1);
        if (rc < 0) {
                goto bail;
        }
        rc = medusa_io_init(&monitor->timer.io, monitor, monitor->timer.backend->fd(monitor->timer.backend), monitor_timer_io_onevent, monitor);
        if (rc < 0) {
                goto bail;
        }
        rc = medusa_io_set_events(&monitor->timer.io, MEDUSA_IO_EVENT_IN);
        if (rc < 0) {
                goto bail;
        }
        rc = medusa_io_set_enabled(&monitor->timer.io, 1);
        if (rc < 0) {
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
        medusa_monitor_lock(monitor);
        while (!TAILQ_EMPTY(&monitor->rogues)) {
                subject = TAILQ_FIRST(&monitor->rogues);
                medusa_monitor_del_unlocked(subject);
        }
        while (!TAILQ_EMPTY(&monitor->changes)) {
                subject = TAILQ_FIRST(&monitor->changes);
                medusa_monitor_del_unlocked(subject);
        }
        while (!TAILQ_EMPTY(&monitor->actives)) {
                subject = TAILQ_FIRST(&monitor->actives);
                medusa_monitor_del_unlocked(subject);
        }
        while (!TAILQ_EMPTY(&monitor->deletes)) {
                subject = TAILQ_FIRST(&monitor->deletes);
                TAILQ_REMOVE(&monitor->deletes, subject, list);
                subject->monitor = NULL;
                if (subject->flags & MEDUSA_SUBJECT_TYPE_IO) {
                        io = (struct medusa_io *) subject;
                        if (subject->flags & MEDUSA_SUBJECT_FLAG_POLL) {
                                monitor->poll.backend->del(monitor->poll.backend, io);
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_POLL;
                        }
                        medusa_monitor_unlock(monitor);
                        medusa_io_onevent_unlocked(io, MEDUSA_IO_EVENT_DESTROY);
                        medusa_monitor_lock(monitor);
                } else if (subject->flags & MEDUSA_SUBJECT_TYPE_TIMER) {
                        timer = (struct medusa_timer *) subject;
                        if (subject->flags & MEDUSA_SUBJECT_FLAG_HEAP) {
                                pqueue_del(monitor->timer.pqueue, timer);
                                subject->flags &= ~MEDUSA_SUBJECT_FLAG_HEAP;
                        }
                        medusa_monitor_unlock(monitor);
                        medusa_timer_onevent_unlocked(timer, MEDUSA_TIMER_EVENT_DESTROY);
                        medusa_monitor_lock(monitor);
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
        medusa_monitor_unlock(monitor);
        if (monitor->flags & MEDUSA_MONITOR_FLAG_THREAD_SAFE) {
             pthread_mutex_destroy(&monitor->mutex);
        }
        free(monitor);
}

__attribute__ ((visibility ("default"))) int medusa_monitor_get_running (struct medusa_monitor *monitor)
{
        int running;
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return -EINVAL;
        }
        medusa_monitor_lock(monitor);
        running = monitor->running;
        medusa_monitor_unlock(monitor);
        return running;
}

__attribute__ ((visibility ("default"))) int medusa_monitor_break (struct medusa_monitor *monitor)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return -EINVAL;
        }
        medusa_monitor_lock(monitor);
        rc = monitor_signal(monitor, WAKEUP_REASON_LOOP_BREAK);
        medusa_monitor_unlock(monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_monitor_continue (struct medusa_monitor *monitor)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return -EINVAL;
        }
        medusa_monitor_lock(monitor);
        rc = monitor_signal(monitor, WAKEUP_REASON_LOOP_CONTINUE);
        medusa_monitor_unlock(monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_monitor_run_timeout (struct medusa_monitor *monitor, double timeout)
{
        int rc;
        struct timespec *timespec;
        struct timespec _timespec;

        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return -EINVAL;
        }

        if (timeout < 0) {
                timespec = NULL;
        } else {
                timespec = &_timespec;
                timespec->tv_sec = timeout;
                timespec->tv_nsec = (timeout - timespec->tv_sec) * 1e9;
        }

        medusa_monitor_lock(monitor);

        rc = monitor_process_deletes(monitor);
        if (rc < 0) {
                goto bail;
        }
        rc = monitor_process_changes(monitor);
        if (rc < 0) {
                goto bail;
        }
        rc = monitor_setup_timer(monitor);
        if (rc < 0) {
                goto bail;
        }

        medusa_monitor_unlock(monitor);

        rc = monitor->poll.backend->run(monitor->poll.backend, timespec);

        medusa_monitor_lock(monitor);

        if (rc < 0) {
                goto bail;
        }
        rc = monitor_check_timer(monitor);
        if (rc < 0) {
                goto bail;
        }

        rc = monitor->running;

bail:   medusa_monitor_unlock(monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_monitor_run_once (struct medusa_monitor *monitor)
{
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return -EINVAL;
        }
        return medusa_monitor_run_timeout(monitor, -1);
}

__attribute__ ((visibility ("default"))) int medusa_monitor_run (struct medusa_monitor *monitor)
{
        int rc;

        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return -EINVAL;
        }

        while (1) {
                rc = medusa_monitor_run_once(monitor);
                if (rc == 0) {
                        return rc;
                } else if (rc < 0) {
                        return rc;
                }
        }

        return 0;
}
