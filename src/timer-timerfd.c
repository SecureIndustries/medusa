
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/timerfd.h>

#include "time.h"
#include "subject.h"
#include "timer-backend.h"

#include "timer-timerfd.h"

struct internal {
        struct medusa_timer_backend backend;
        int tfd;
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

static int internal_fd (struct medusa_timer_backend *backend)
{
        struct internal *internal = (struct internal *) backend;
        if (internal == NULL) {
                goto bail;
        }
        return internal->tfd;
bail:   return -1;
}

static int internal_set (struct medusa_timer_backend *backend, struct medusa_timerspec *timerspec)
{
        struct internal *internal = (struct internal *) backend;
        if (internal == NULL) {
                goto bail;
        }
        if (timerspec == NULL) {
                goto bail;
        }
        return 0;
bail:   return -1;
}

static int internal_get (struct medusa_timer_backend *backend, struct medusa_timerspec *timerspec)
{
        struct internal *internal = (struct internal *) backend;
        if (internal == NULL) {
                goto bail;
        }
        if (timerspec == NULL) {
                goto bail;
        }
        return 0;
bail:   return -1;
}

static void internal_destroy (struct medusa_timer_backend *backend)
{
        struct internal *internal = (struct internal *) backend;
        if (internal == NULL) {
                return;
        }
        if (internal->tfd >= 0) {
                close(internal->tfd);
        }
        free(internal);
}

struct medusa_timer_backend * medusa_timer_timerfd_create (const struct medusa_timer_timerfd_init_options *options)
{
        int rc;
        struct internal *internal;
        (void) options;
        internal = (struct internal *) malloc(sizeof(struct internal));
        if (internal == NULL) {
                goto bail;
        }
        memset(internal, 0, sizeof(struct internal));
        internal->tfd = timerfd_create(CLOCK_MONOTONIC, 0);
        if (internal->tfd < 0) {
                goto bail;
        }
        rc = fd_set_blocking(internal->tfd, 0);
        if (rc != 0) {
                goto bail;
        }
        internal->backend.name    = "select";
        internal->backend.fd      = internal_fd;
        internal->backend.set     = internal_set;
        internal->backend.get     = internal_get;
        internal->backend.destroy = internal_destroy;
        return &internal->backend;
bail:   if (internal != NULL) {
                internal_destroy(&internal->backend);
        }
        return NULL;
}
