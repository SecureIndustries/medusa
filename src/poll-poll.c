
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#include "event.h"
#include "time.h"
#include "subject.h"
#include "poll-backend.h"

#include "poll-poll.h"

#define MAX(a, b)       (((a) > (b)) ? (a) : (b))

struct internal {
        struct medusa_poll_backend backend;
        struct pollfd *pfds;
        int npfds;
        int spfds;
        struct medusa_subject **subjects;
        int nsubjects;
};

static int internal_add (struct medusa_poll_backend *backend, struct medusa_subject *subject, unsigned int events)
{
        int rc;
        int fd;
        struct pollfd *pfd;
        struct internal *internal = (struct internal *) backend;
        if (internal == NULL) {
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
        if (internal->npfds + 1 >= internal->spfds) {
                struct pollfd *tmp;
                tmp = (struct pollfd *) realloc(internal->pfds, sizeof(struct pollfd) * (internal->spfds + 64));
                if (tmp == NULL) {
                        tmp = (struct pollfd *) malloc(sizeof(struct pollfd) * (internal->spfds + 64));
                        if (tmp == NULL) {
                                goto bail;
                        }
                        memcpy(tmp, internal->pfds, sizeof(struct pollfd) * internal->npfds);
                        free(internal->pfds);
                }
                internal->pfds = tmp;
                internal->spfds = internal->spfds + 64;
        }
        if (fd >= internal->nsubjects) {
                struct medusa_subject **tmp;
                tmp = (struct medusa_subject **) realloc(internal->subjects, sizeof(struct medusa_subject *) * MAX(fd, internal->nsubjects + 64));
                if (tmp == NULL) {
                        tmp = (struct medusa_subject **) malloc(sizeof(struct medusa_subject *) * MAX(fd, internal->nsubjects + 64));
                        if (tmp == NULL) {
                                goto bail;
                        }
                        memcpy(tmp, internal->subjects, sizeof(struct medusa_subject **) * internal->nsubjects);
                        free(internal->subjects);
                }
                internal->subjects = tmp;
                internal->nsubjects = MAX(fd, internal->nsubjects + 64);
        }
        rc = medusa_subject_retain(subject);
        if (rc != 0) {
                goto bail;
        }
        pfd = &internal->pfds[internal->npfds];
        pfd->events = 0;
        if (events & medusa_event_in) {
                pfd->events |= POLLIN;
        }
        if (events & medusa_event_out) {
                pfd->events |= POLLOUT;
        }
        if (events & medusa_event_pri) {
                pfd->events |= POLLPRI;
        }
        pfd->fd = fd;
        internal->subjects[fd] = subject;
        internal->npfds += 1;
        return 0;
bail:   return -1;
}

static int internal_mod (struct medusa_poll_backend *backend, struct medusa_subject *subject, unsigned int events)
{
        int i;
        int fd;
        struct pollfd *pfd;
        struct internal *internal = (struct internal *) backend;
        if (internal == NULL) {
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
        for (i = 0; i < internal->npfds; i++) {
                if (fd == internal->pfds[i].fd) {
                        break;
                }
        }
        if (i >= internal->npfds) {
                goto bail;
        }
        pfd = &internal->pfds[i];
        pfd->events = 0;
        if (events & medusa_event_in) {
                pfd->events |= POLLIN;
        }
        if (events & medusa_event_out) {
                pfd->events |= POLLOUT;
        }
        if (events & medusa_event_pri) {
                pfd->events |= POLLPRI;
        }
        return 0;
bail:   return -1;
}

static int internal_del (struct medusa_poll_backend *backend, struct medusa_subject *subject)
{
        int i;
        int fd;
        struct internal *internal = (struct internal *) backend;
        if (internal == NULL) {
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
        for (i = 0; i < internal->npfds; i++) {
                if (fd == internal->pfds[i].fd) {
                        break;
                }
        }
        if (i >= internal->npfds) {
                goto bail;
        }
        memmove(&internal->pfds[i], &internal->pfds[i + 1], sizeof(struct pollfd) * (internal->npfds - i - 1));
        internal->npfds -= 1;
        internal->subjects[fd] = NULL;
        medusa_subject_destroy(subject);
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
        struct medusa_subject *subject;
        struct internal *internal = (struct internal *) backend;
        if (internal == NULL) {
                goto bail;
        }
        if (timespec == NULL) {
                timeout = -1;
        } else {
                timeout = timespec->seconds * 1000 + timespec->nanoseconds / 1000000;
        }
        for (i = 0; i < internal->npfds; i++) {
                internal->pfds[i].revents = 0;
        }
        count = poll(internal->pfds, internal->npfds, timeout);
        if (count == 0) {
                goto out;
        }
        if (count < 0) {
                goto bail;
        }
        for (i = 0; i < internal->npfds; i++) {
                if (internal->pfds[i].revents == 0) {
                        continue;
                }
                events = 0;
                if (internal->pfds[i].revents & POLLIN) {
                        events |= medusa_event_in;
                }
                if (internal->pfds[i].revents & POLLOUT) {
                        events |= medusa_event_out;
                }
                if (internal->pfds[i].revents & POLLPRI) {
                        events |= medusa_event_pri;
                }
                if (internal->pfds[i].revents & POLLHUP) {
                        events |= medusa_event_hup;
                }
                if (internal->pfds[i].revents & POLLERR) {
                        events |= medusa_event_err;
                }
                if (internal->pfds[i].revents & POLLNVAL) {
                        events |= medusa_event_nval;
                }
                subject = internal->subjects[internal->pfds[i].fd];
                rc = medusa_subject_get_callback_function(subject)(subject, events);
                if (rc != 0) {
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
        if (internal->subjects != NULL) {
                free(internal->subjects);
        }
        if (internal->pfds != NULL) {
                free(internal->pfds);
        }
        free(internal);
}

struct medusa_poll_backend * medusa_monitor_poll_create (const struct medusa_monitor_poll_init_options *options)
{
        struct internal *internal;
        (void) options;
        internal = (struct internal *) malloc(sizeof(struct internal));
        if (internal == NULL) {
                goto bail;
        }
        memset(internal, 0, sizeof(struct internal));
        internal->backend.name    = "poll";
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
