
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <errno.h>

#include "queue.h"
#include "time.h"
#include "subject-struct.h"
#include "io.h"
#include "io-private.h"
#include "io-struct.h"

#include "poll-backend.h"
#include "poll-select.h"

#define MAX(a, b)       (((a) > (b)) ? (a) : (b))

struct internal {
        struct medusa_poll_backend backend;
        fd_set rfds;
        fd_set wfds;
        fd_set efds;
        fd_set _rfds;
        fd_set _wfds;
        fd_set _efds;
#if defined(__DARWIN__) && (__DARWIN__ == 1)
        struct medusa_io *ios[__DARWIN_FD_SETSIZE];
#else
        struct medusa_io *ios[__FD_SETSIZE];
#endif
};

static int internal_add (struct medusa_poll_backend *backend, struct medusa_io *io)
{
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
        if (medusa_io_get_events(io) == 0) {
                goto bail;
        }
#if defined(__DARWIN__) && (__DARWIN__ == 1)
        if (io->fd >= __DARWIN_FD_SETSIZE) {
#else
        if (io->fd >= __FD_SETSIZE) {
#endif
                goto bail;
        }
        FD_CLR(io->fd, &internal->rfds);
        FD_CLR(io->fd, &internal->wfds);
        FD_CLR(io->fd, &internal->efds);
        if (medusa_io_get_events(io) & MEDUSA_IO_EVENT_IN) {
                FD_SET(io->fd, &internal->rfds);
        }
        if (medusa_io_get_events(io) & MEDUSA_IO_EVENT_OUT) {
                FD_SET(io->fd, &internal->wfds);
        }
        if (medusa_io_get_events(io) & MEDUSA_IO_EVENT_PRI) {
                FD_SET(io->fd, &internal->rfds);
        }
        FD_SET(io->fd, &internal->efds);
        internal->ios[io->fd] = io;
        return 0;
bail:   return -1;
}

static int internal_mod (struct medusa_poll_backend *backend, struct medusa_io *io)
{
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
        if (medusa_io_get_events(io) == 0) {
                goto bail;
        }
        if (internal->ios[io->fd] != io) {
                goto bail;
        }
        FD_CLR(io->fd, &internal->rfds);
        FD_CLR(io->fd, &internal->wfds);
        FD_CLR(io->fd, &internal->efds);
        if (medusa_io_get_events(io) & MEDUSA_IO_EVENT_IN) {
                FD_SET(io->fd, &internal->rfds);
        }
        if (medusa_io_get_events(io) & MEDUSA_IO_EVENT_OUT) {
                FD_SET(io->fd, &internal->wfds);
        }
        if (medusa_io_get_events(io) & MEDUSA_IO_EVENT_PRI) {
                FD_SET(io->fd, &internal->rfds);
        }
        FD_SET(io->fd, &internal->efds);
        return 0;
bail:   return -1;
}

static int internal_del (struct medusa_poll_backend *backend, struct medusa_io *io)
{
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
        if (internal->ios[io->fd] != io) {
                goto bail;
        }
        FD_CLR(io->fd, &internal->rfds);
        FD_CLR(io->fd, &internal->wfds);
        FD_CLR(io->fd, &internal->efds);
        internal->ios[io->fd] = NULL;
        return 0;
bail:   return -1;
}

static int internal_run (struct medusa_poll_backend *backend, struct timespec *timespec)
{
        int i;
        int rc;
        int count;
        unsigned int events;
        struct timeval *timeval;
        struct timeval _timeval;
        struct medusa_io *io;
        struct internal *internal = (struct internal *) backend;
        if (internal == NULL) {
                goto bail;
        }
        if (timespec != NULL) {
                timeval = &_timeval;
                _timeval.tv_sec = timespec->tv_sec;
                _timeval.tv_usec = timespec->tv_nsec / 1000;
        } else {
                timeval = NULL;
        }
        memcpy(&internal->_rfds, &internal->rfds, sizeof(internal->rfds));
        memcpy(&internal->_wfds, &internal->wfds, sizeof(internal->wfds));
        memcpy(&internal->_efds, &internal->efds, sizeof(internal->efds));
#if defined(__DARWIN__) && (__DARWIN__ == 1)
        count = select(__DARWIN_FD_SETSIZE, &internal->_rfds, &internal->_wfds, &internal->_efds, timeval);
#else
        count = select(__FD_SETSIZE, &internal->_rfds, &internal->_wfds, &internal->_efds, timeval);
#endif
        if (count == 0) {
                goto out;
        }
        if (count < 0) {
                goto bail;
        }
#if defined(__DARWIN__) && (__DARWIN__ == 1)
        for (i = 0; i < __DARWIN_FD_SETSIZE; i++) {
#else
        for (i = 0; i < __FD_SETSIZE; i++) {
#endif
                events = 0;
                if (FD_ISSET(i, &internal->_rfds)) {
                        events |= MEDUSA_IO_EVENT_IN;
                }
                if (FD_ISSET(i, &internal->_wfds)) {
                        events |= MEDUSA_IO_EVENT_OUT;
                }
                if (FD_ISSET(i, &internal->_efds)) {
                        events |= MEDUSA_IO_EVENT_ERR;
                }
                if (events == 0) {
                        continue;
                }
                io = internal->ios[i];
                rc = medusa_io_onevent(io, events);
                if (rc < 0) {
                        goto bail;
                }
        }
out:    return count;
bail:   return -1;
}

static void internal_destroy (struct medusa_poll_backend *backend)
{
        struct internal *internal = (struct internal *) backend;
        if (internal == NULL) {
                return;
        }
        free(internal);
}

struct medusa_poll_backend * medusa_monitor_select_create (const struct medusa_monitor_select_init_options *options)
{
        struct internal *internal;
        (void) options;
        internal = (struct internal *) malloc(sizeof(struct internal));
        if (internal == NULL) {
                goto bail;
        }
        memset(internal, 0, sizeof(struct internal));
        internal->backend.name    = "select";
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
