
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/epoll.h>

#include "event.h"
#include "time.h"
#include "subject.h"
#include "monitor-backend.h"

#include "monitor-epoll.h"

struct private {
        struct medusa_monitor_backend backend;
        int fd;
        int maxevents;
        struct epoll_event *events;
};

static int private_add (struct medusa_monitor_backend *backend, struct medusa_subject *subject, unsigned int events)
{
        int rc;
        int fd;
        struct epoll_event ev;
        struct private *private = (struct private *) backend;
        if (private == NULL) {
                goto bail;
        }
        if (subject == NULL) {
                goto bail;
        }
        if (medusa_subject_get_type(subject) != medusa_subject_type_io) {
                goto bail;
        }
        fd = medusa_subject_io_get_fd(subject);
        if (fd < 0) {
                goto bail;
        }
        if (events == 0) {
                goto bail;
        }
        ev.events = 0;
        if (events & medusa_event_in) {
                ev.events |= EPOLLIN;
        }
        if (events & medusa_event_out) {
                ev.events |= EPOLLOUT;
        }
        if (events & medusa_event_pri) {
                ev.events |= EPOLLPRI;
        }
        rc = medusa_subject_retain(subject);
        if (rc != 0) {
                goto bail;
        }
        ev.data.ptr = subject;
        rc = epoll_ctl(private->fd, EPOLL_CTL_ADD, fd, &ev);
        if (rc != 0) {
                goto bail;
        }
        return 0;
bail:   return -1;
}

static int private_mod (struct medusa_monitor_backend *backend, struct medusa_subject *subject, unsigned int events)
{
        struct private *private = (struct private *) backend;
        if (private == NULL) {
                goto bail;
        }
        if (subject == NULL) {
                goto bail;
        }
        if (events == 0) {
                goto bail;
        }
        return -1;
        return 0;
bail:   return -1;
}

static int private_del (struct medusa_monitor_backend *backend, struct medusa_subject *subject)
{
        int rc;
        int fd;
        struct epoll_event ev;
        struct private *private = (struct private *) backend;
        if (private == NULL) {
                goto bail;
        }
        if (subject == NULL) {
                goto bail;
        }
        if (medusa_subject_get_type(subject) != medusa_subject_type_io) {
                goto bail;
        }
        fd = medusa_subject_io_get_fd(subject);
        if (fd < 0) {
                goto bail;
        }
        fprintf(stderr, "deleting fd: %d\n", fd);
        ev.events = 0;
        ev.data.ptr = subject;
        rc = epoll_ctl(private->fd, EPOLL_CTL_DEL, fd, &ev);
        if (rc != 0) {
                goto bail;
        }
        medusa_subject_destroy(subject);
        return 0;
bail:   return -1;
}

static int private_run (struct medusa_monitor_backend *backend, struct medusa_timespec *timespec)
{
        int i;
        int rc;
        int count;
        int timeout;
        unsigned int events;
        struct epoll_event *event;
        struct medusa_subject *subject;
        struct private *private = (struct private *) backend;
        if (private == NULL) {
                goto bail;
        }
        if (timespec == NULL) {
                timeout = -1;
        } else {
                timeout = timespec->seconds * 1000 + timespec->nanoseconds / 1000000;
        }
        count = epoll_wait(private->fd, private->events, private->maxevents, timeout);
        if (count == 0) {
                goto out;
        }
        if (count < 0) {
                goto bail;
        }
        for (i = 0; i < count; i++) {
                event = &private->events[i];
                subject = event->data.ptr;
                events = 0;
                if (event->events & EPOLLIN) {
                        events |= medusa_event_in;
                }
                if (event->events & EPOLLOUT) {
                        events |= medusa_event_out;
                }
                if (event->events & EPOLLPRI) {
                        events |= medusa_event_pri;
                }
                if (event->events & EPOLLHUP) {
                        events |= medusa_event_hup;
                }
                if (event->events & EPOLLERR) {
                        events |= medusa_event_err;
                }
                rc = medusa_subject_get_callback_function(subject)(medusa_subject_get_callback_context(subject), backend->monitor, subject, events);
                if (rc != 0) {
                        goto bail;
                }
        }
        if (count == private->maxevents) {
                free(private->events);
                private->maxevents += 64;
                private->events = malloc(sizeof(struct epoll_event) * private->maxevents);
                if (private->events == NULL) {
                        private->maxevents = 0;
                        goto bail;
                }
        }
out:    return 0;
bail:   return -1;
}

static void private_destroy (struct medusa_monitor_backend *backend)
{
        struct private *private = (struct private *) backend;
        if (private == NULL) {
                return;
        }
        if (private->fd >= 0) {
                close(private->fd);
        }
        if (private->events != NULL) {
                free(private->events);
        }
        free(private);
}

struct medusa_monitor_backend * medusa_monitor_epoll_create (const struct medusa_monitor_epoll_init_options *options)
{
        struct private *private;
        (void) options;
        private = malloc(sizeof(struct private));
        if (private == NULL) {
                goto bail;
        }
        memset(private, 0, sizeof(struct private));
        private->fd = epoll_create1(0);
        if (private->fd < 0) {
                goto bail;
        }
        private->maxevents = 64;
        private->events = malloc(sizeof(struct epoll_event) * private->maxevents);
        if (private->events == NULL) {
                goto bail;
        }
        private->backend.name    = "epoll";
        private->backend.add     = private_add;
        private->backend.mod     = private_mod;
        private->backend.del     = private_del;
        private->backend.run     = private_run;
        private->backend.destroy = private_destroy;
        return &private->backend;
bail:   if (private != NULL) {
                private_destroy(&private->backend);
        }
        return NULL;
}
