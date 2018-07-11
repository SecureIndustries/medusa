
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/epoll.h>

#include "event.h"
#include "time.h"
#include "queue.h"
#include "subject-struct.h"
#include "io-struct.h"

#include "poll-backend.h"
#include "poll-epoll.h"

struct internal {
        struct medusa_poll_backend backend;
        int fd;
        int maxevents;
        struct epoll_event *events;
};

static int internal_add (struct medusa_poll_backend *backend, struct medusa_io *io)
{
        int rc;
        struct epoll_event ev;
        struct internal *internal = (struct internal *) backend;
        if (internal == NULL) {
                goto bail;
        }
        if (io == NULL) {
                goto bail;
        }
        if (io->fd < 0) {
                goto bail;
        }
        if (io->events == 0) {
                goto bail;
        }
        ev.events = 0;
        if (io->events & medusa_event_in) {
                ev.events |= EPOLLIN;
        }
        if (io->events & medusa_event_out) {
                ev.events |= EPOLLOUT;
        }
        if (io->events & medusa_event_pri) {
                ev.events |= EPOLLPRI;
        }
        ev.data.ptr = io;
        rc = epoll_ctl(internal->fd, EPOLL_CTL_ADD, io->fd, &ev);
        if (rc != 0) {
                goto bail;
        }
        return 0;
bail:   return -1;
}

static int internal_mod (struct medusa_poll_backend *backend, struct medusa_io *io)
{
        int rc;
        struct epoll_event ev;
        struct internal *internal = (struct internal *) backend;
        if (internal == NULL) {
                goto bail;
        }
        if (io == NULL) {
                goto bail;
        }
        if (io->fd < 0) {
                goto bail;
        }
        if (io->events == 0) {
                goto bail;
        }
        ev.events = 0;
        if (io->events & medusa_event_in) {
                ev.events |= EPOLLIN;
        }
        if (io->events & medusa_event_out) {
                ev.events |= EPOLLOUT;
        }
        if (io->events & medusa_event_pri) {
                ev.events |= EPOLLPRI;
        }
        ev.data.ptr = io;
        rc = epoll_ctl(internal->fd, EPOLL_CTL_MOD, io->fd, &ev);
        if (rc != 0) {
                goto bail;
        }
        return 0;
bail:   return -1;
}

static int internal_del (struct medusa_poll_backend *backend, struct medusa_io *io)
{
        int rc;
        struct epoll_event ev;
        struct internal *internal = (struct internal *) backend;
        if (internal == NULL) {
                goto bail;
        }
        if (io == NULL) {
                goto bail;
        }
        if (io->fd < 0) {
                goto bail;
        }
        ev.events = 0;
        ev.data.ptr = io;
        rc = epoll_ctl(internal->fd, EPOLL_CTL_DEL, io->fd, &ev);
        if (rc != 0) {
                if (errno != EBADF) {
                        fprintf(stderr, "%d, %s\n", errno, strerror(errno));
                        abort();
                        goto bail;
                }
        }
        return 0;
bail:   return -1;
}

static int internal_run (struct medusa_poll_backend *backend, struct medusa_timespec *timespec)
{
        int i;
        int rc;
        int count;
        int timeout;
        unsigned int events;
        struct epoll_event *ev;
        struct medusa_io *io;
        struct internal *internal = (struct internal *) backend;
        if (internal == NULL) {
                goto bail;
        }
        if (timespec == NULL) {
                timeout = -1;
        } else {
                timeout = timespec->seconds * 1000 + timespec->nanoseconds / 1000000;
        }
        count = epoll_wait(internal->fd, internal->events, internal->maxevents, timeout);
        if (count == 0) {
                goto out;
        }
        if (count < 0) {
                goto bail;
        }
        for (i = 0; i < count; i++) {
                ev = &internal->events[i];
                io = (struct medusa_io *) ev->data.ptr;
                events = 0;
                if (ev->events & EPOLLIN) {
                        events |= medusa_event_in;
                }
                if (ev->events & EPOLLOUT) {
                        events |= medusa_event_out;
                }
                if (ev->events & EPOLLPRI) {
                        events |= medusa_event_pri;
                }
                if (ev->events & EPOLLHUP) {
                        events |= medusa_event_hup;
                }
                if (ev->events & EPOLLERR) {
                        events |= medusa_event_err;
                }
                rc = io->subject.event(&io->subject, events);
                if (rc != 0) {
                        goto bail;
                }
        }
        if (count == internal->maxevents) {
                free(internal->events);
                internal->maxevents += 64;
                internal->events = (struct epoll_event *) malloc(sizeof(struct epoll_event) * internal->maxevents);
                if (internal->events == NULL) {
                        internal->maxevents = 0;
                        goto bail;
                }
        }
out:    return 0;
bail:   return -1;
}

static void internal_destroy (struct medusa_poll_backend *backend)
{
        struct internal *internal = (struct internal *) backend;
        if (internal == NULL) {
                return;
        }
        if (internal->fd >= 0) {
                close(internal->fd);
        }
        if (internal->events != NULL) {
                free(internal->events);
        }
        free(internal);
}

struct medusa_poll_backend * medusa_monitor_epoll_create (const struct medusa_monitor_epoll_init_options *options)
{
        struct internal *internal;
        (void) options;
        internal = (struct internal *) malloc(sizeof(struct internal));
        if (internal == NULL) {
                goto bail;
        }
        memset(internal, 0, sizeof(struct internal));
        internal->fd = epoll_create1(0);
        if (internal->fd < 0) {
                goto bail;
        }
        internal->maxevents = 64;
        internal->events = (struct epoll_event *) malloc(sizeof(struct epoll_event) * internal->maxevents);
        if (internal->events == NULL) {
                goto bail;
        }
        internal->backend.name    = "epoll";
        internal->backend.add     = internal_add;
        internal->backend.mod     = internal_mod;
        internal->backend.del     = internal_del;
        internal->backend.run     = internal_run;
        internal->backend.destroy = internal_destroy;
        return &internal->backend;
bail:   if (internal != NULL) {
                internal_destroy(&internal->backend);
        }
        return NULL;
}
