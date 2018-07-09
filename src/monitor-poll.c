
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>

#include "event.h"
#include "time.h"
#include "subject.h"
#include "monitor-backend.h"

#include "monitor-poll.h"

#define MAX(a, b)       (((a) > (b)) ? (a) : (b))

struct private {
        struct medusa_monitor_backend backend;
        struct pollfd *pfds;
        int npfds;
        int spfds;
        struct medusa_subject **subjects;
        int nsubjects;
};

static int private_add (struct medusa_monitor_backend *backend, struct medusa_subject *subject, unsigned int events)
{
        int rc;
        int fd;
        struct pollfd *pfd;
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
        if (private->npfds + 1 >= private->spfds) {
                struct pollfd *tmp;
                tmp = realloc(private->pfds, sizeof(struct pollfd) * (private->spfds + 64));
                if (tmp == NULL) {
                        tmp = malloc(sizeof(struct pollfd) * (private->spfds + 64));
                        if (tmp == NULL) {
                                goto bail;
                        }
                        memcpy(tmp, private->pfds, sizeof(struct pollfd) * private->npfds);
                        free(private->pfds);
                }
                private->pfds = tmp;
                private->spfds = private->spfds + 64;
        }
        if (fd >= private->nsubjects) {
                struct medusa_subject **tmp;
                tmp = realloc(private->subjects, sizeof(struct medusa_subject *) * MAX(fd, private->nsubjects + 64));
                if (tmp == NULL) {
                        tmp = malloc(sizeof(struct medusa_subject *) * MAX(fd, private->nsubjects + 64));
                        if (tmp == NULL) {
                                goto bail;
                        }
                        memcpy(tmp, private->subjects, sizeof(struct medusa_subject **) * private->nsubjects);
                        free(private->subjects);
                }
                private->subjects = tmp;
                private->nsubjects = MAX(fd, private->nsubjects + 64);
        }
        rc = medusa_subject_retain(subject);
        if (rc != 0) {
                goto bail;
        }
        pfd = &private->pfds[private->npfds];
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
        private->subjects[fd] = subject;
        private->npfds += 1;
        return 0;
bail:   return -1;
}

static int private_mod (struct medusa_monitor_backend *backend, struct medusa_subject *subject, unsigned int events)
{
        int i;
        int fd;
        struct pollfd *pfd;
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
        for (i = 0; i < private->npfds; i++) {
                if (fd == private->pfds[i].fd) {
                        break;
                }
        }
        if (i >= private->npfds) {
                goto bail;
        }
        pfd = &private->pfds[i];
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

static int private_del (struct medusa_monitor_backend *backend, struct medusa_subject *subject)
{
        int i;
        int fd;
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
        for (i = 0; i < private->npfds; i++) {
                if (fd == private->pfds[i].fd) {
                        break;
                }
        }
        if (i >= private->npfds) {
                goto bail;
        }
        memmove(&private->pfds[i], &private->pfds[i + 1], sizeof(struct pollfd) * (private->npfds - i - 1));
        private->npfds -= 1;
        private->subjects[fd] = NULL;
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
        for (i = 0; i < private->npfds; i++) {
                private->pfds[i].revents = 0;
        }
        count = poll(private->pfds, private->npfds, timeout);
        if (count == 0) {
                goto out;
        }
        if (count < 0) {
                goto bail;
        }
        for (i = 0; i < count; i++) {
                if (private->pfds[i].revents == 0) {
                        continue;
                }
                events = 0;
                if (private->pfds[i].revents & POLLIN) {
                        events |= medusa_event_in;
                }
                if (private->pfds[i].revents & POLLOUT) {
                        events |= medusa_event_out;
                }
                if (private->pfds[i].revents & POLLPRI) {
                        events |= medusa_event_pri;
                }
                if (private->pfds[i].revents & POLLHUP) {
                        events |= medusa_event_hup;
                }
                if (private->pfds[i].revents & POLLERR) {
                        events |= medusa_event_err;
                }
                if (private->pfds[i].revents & POLLNVAL) {
                        events |= medusa_event_nval;
                }
                subject = private->subjects[private->pfds[i].fd];
                rc = medusa_subject_get_callback_function(subject)(medusa_subject_get_callback_context(subject), subject, events);
                if (rc != 0) {
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
        if (private->subjects != NULL) {
                free(private->subjects);
        }
        if (private->pfds != NULL) {
                free(private->pfds);
        }
        free(private);
}

struct medusa_monitor_backend * medusa_monitor_poll_create (const struct medusa_monitor_poll_init_options *options)
{
        struct private *private;
        (void) options;
        private = malloc(sizeof(struct private));
        if (private == NULL) {
                goto bail;
        }
        memset(private, 0, sizeof(struct private));
        private->backend.name    = "poll";
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
