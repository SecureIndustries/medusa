
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

#include <sys/signalfd.h>

#include "error.h"
#include "clock.h"
#include "queue.h"
#include "signal-backend.h"
#include "subject-struct.h"
#include "signal-struct.h"

#include "signal-signalfd.h"

struct internal {
        struct medusa_signal_backend backend;
        int sfd;
        sigset_t sigset;
};

static int internal_fd (struct medusa_signal_backend *backend)
{
        struct internal *internal = (struct internal *) backend;
        if (MEDUSA_IS_ERR_OR_NULL(internal)) {
                return -EINVAL;
        }
        return internal->sfd;
}

static int internal_add (struct medusa_signal_backend *backend, struct medusa_signal *signal)
{
        int rc;
        struct internal *internal = (struct internal *) backend;
        if (MEDUSA_IS_ERR_OR_NULL(internal)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return -EINVAL;
        }
        if (signal->number <= 0) {
                return -EINVAL;
        }
        rc = sigismember(&internal->sigset, signal->number);
        if (rc < 0) {
                return -errno;
        } else if (rc != 0) {
                return -EEXIST;
        }
        rc = sigaddset(&internal->sigset, signal->number);
        if (rc < 0) {
                return -errno;
        }
        rc = signalfd(internal->sfd, &internal->sigset, SFD_NONBLOCK);
        if (rc < 0) {
                return -errno;
        }
        return 0;
}

static int internal_del (struct medusa_signal_backend *backend, struct medusa_signal *signal)
{
        int rc;
        struct internal *internal = (struct internal *) backend;
        if (MEDUSA_IS_ERR_OR_NULL(internal)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return -EINVAL;
        }
        if (signal->number <= 0) {
                return -EINVAL;
        }
        rc = sigismember(&internal->sigset, signal->number);
        if (rc < 0) {
                return -errno;
        } else if (rc == 0) {
                return -ENOENT;
        }
        rc = sigdelset(&internal->sigset, signal->number);
        if (rc < 0) {
                return -errno;
        }
        rc = signalfd(internal->sfd, &internal->sigset, 0);
        if (rc < 0) {
                return -errno;
        }
        return 0;
}

static void internal_destroy (struct medusa_signal_backend *backend)
{
        struct internal *internal = (struct internal *) backend;
        if (internal == NULL) {
                return;
        }
        if (internal->sfd >= 0) {
                close(internal->sfd);
        }
        free(internal);
}

struct medusa_signal_backend * medusa_signal_signalfd_create (const struct medusa_signal_signalfd_init_options *options)
{
        struct internal *internal;
        (void) options;
        internal = (struct internal *) malloc(sizeof(struct internal));
        if (internal == NULL) {
                goto bail;
        }
        memset(internal, 0, sizeof(struct internal));
        sigemptyset(&internal->sigset);
        internal->sfd = signalfd(-1, &internal->sigset, SFD_NONBLOCK);
        if (internal->sfd < 0) {
                goto bail;
        }
        internal->backend.name    = "select";
        internal->backend.fd      = internal_fd;
        internal->backend.add     = internal_add;
        internal->backend.del     = internal_del;
        internal->backend.destroy = internal_destroy;
        return &internal->backend;
bail:   if (internal != NULL) {
                internal_destroy(&internal->backend);
        }
        return NULL;
}
