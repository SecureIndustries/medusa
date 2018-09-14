
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
        rc = sigprocmask(SIG_BLOCK, &internal->sigset, NULL);
        if (rc < 0) {
                return -errno;
        }
        rc = signalfd(internal->sfd, &internal->sigset, SFD_NONBLOCK);
        if (rc < 0) {
                return -errno;
        }
        fprintf(stderr, "add: %d\n", signal->number);
        return 0;
}

static int internal_del (struct medusa_signal_backend *backend, struct medusa_signal *signal)
{
        int rc;
        sigset_t sigset;
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
        rc = signalfd(internal->sfd, &internal->sigset, 0);
        if (rc < 0) {
                return -errno;
        }
        sigemptyset(&sigset);
        rc = sigaddset(&sigset, signal->number);
        if (rc < 0) {
                return -errno;
        }
        rc = sigprocmask(SIG_UNBLOCK, &sigset, NULL);
        if (rc < 0) {
                return -errno;
        }
        rc = sigdelset(&internal->sigset, signal->number);
        if (rc < 0) {
                return -errno;
        }
        fprintf(stderr, "del: %d\n", signal->number);
        return 0;
}

static int internal_run (struct medusa_signal_backend *backend)
{
        int rc;
        struct signalfd_siginfo signalfd_siginfo;
        struct internal *internal = (struct internal *) backend;
        if (MEDUSA_IS_ERR_OR_NULL(internal)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return -EINVAL;
        }
        rc = read(internal->sfd, &signalfd_siginfo, sizeof(struct signalfd_siginfo));
        if (rc < 0) {
                if (errno == EINTR) {
                        return 0;
                } else {
                        return -errno;
                }
        }
        if (rc != sizeof(struct signalfd_siginfo)) {
                return -EIO;
        }
        fprintf(stderr, "signal: %d\n", signalfd_siginfo.ssi_signo);
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
        int rc;
        struct internal *internal;
        (void) options;
        internal = (struct internal *) malloc(sizeof(struct internal));
        if (internal == NULL) {
                goto bail;
        }
        memset(internal, 0, sizeof(struct internal));
        sigemptyset(&internal->sigset);
        rc = sigprocmask(SIG_BLOCK, &internal->sigset, NULL);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(-errno);
        }
        internal->sfd = signalfd(-1, &internal->sigset, SFD_NONBLOCK);
        if (internal->sfd < 0) {
                goto bail;
        }
        internal->backend.name    = "signalfd";
        internal->backend.fd      = internal_fd;
        internal->backend.add     = internal_add;
        internal->backend.del     = internal_del;
        internal->backend.run     = internal_run;
        internal->backend.destroy = internal_destroy;
        return &internal->backend;
bail:   if (internal != NULL) {
                internal_destroy(&internal->backend);
        }
        return NULL;
}
