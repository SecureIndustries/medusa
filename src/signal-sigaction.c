
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

#include "error.h"
#include "clock.h"
#include "queue.h"
#include "signal.h"
#include "signal-backend.h"
#include "subject-struct.h"
#include "signal-struct.h"
#include "signal-private.h"

#include "signal-sigaction.h"

TAILQ_HEAD(entries, entry);
struct entry {
        TAILQ_ENTRY(entry) list;
        struct medusa_signal *signal;
        struct sigaction sa;
};

struct internal {
        struct medusa_signal_backend backend;
        int sfd[2];
        struct entries entries;
};

static int g_signal_handler_wakeup_write;
static int g_signal_handler_wakeup_fired;
static pthread_mutex_t g_signal_handler_wakeup_mutex;

static void internal_signal_handler (int number)
{
        (void) number;
}

static int internal_fd (struct medusa_signal_backend *backend)
{
        struct internal *internal = (struct internal *) backend;
        if (MEDUSA_IS_ERR_OR_NULL(internal)) {
                return -EINVAL;
        }
        return internal->sfd[0];
}

static int internal_add (struct medusa_signal_backend *backend, struct medusa_signal *signal)
{
        int rc;
        struct entry *entry;
        struct sigaction sa;
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
        TAILQ_FOREACH(entry, &internal->entries, list) {
                if (entry->signal->number == signal->number) {
                        return -EEXIST;
                }
        }
        entry = malloc(sizeof(struct entry));
        if (entry == NULL) {
                return -ENOMEM;
        }
        entry->signal = signal;
        memset(&sa, 0, sizeof(struct sigaction));
        sa.sa_handler = internal_signal_handler;
        rc = sigaction(signal->number, &sa, &entry->sa);
        if (rc < 0) {
                free(entry);
                return -errno;
        }
        TAILQ_INSERT_TAIL(&internal->entries, entry, list);
        return 0;
}

static int internal_del (struct medusa_signal_backend *backend, struct medusa_signal *signal)
{
        int rc;
        struct entry *entry;
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
        TAILQ_FOREACH(entry, &internal->entries, list) {
                if (entry->signal->number == signal->number) {
                        break;
                }
        }
        if (entry == NULL) {
                return -ENOENT;
        }
        rc = sigaction(signal->number, &entry->sa, NULL);
        if (rc < 0) {
                return -errno;
        }
        TAILQ_REMOVE(&internal->entries, entry, list);
        free(entry);
        return 0;
}

static int internal_run (struct medusa_signal_backend *backend)
{
        int rc;
        struct entry *entry;
        struct entry *nentry;
        struct sigaction_siginfo sigaction_siginfo;
        struct internal *internal = (struct internal *) backend;
        if (MEDUSA_IS_ERR_OR_NULL(internal)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return -EINVAL;
        }
        rc = read(internal->sfd[0], &sigaction_siginfo, sizeof(struct sigaction_siginfo));
        if (rc < 0) {
                if (errno == EINTR) {
                        return 0;
                } else {
                        return -errno;
                }
        }
        if (rc != sizeof(struct sigaction_siginfo)) {
                return -EIO;
        }
        TAILQ_FOREACH_SAFE(entry, &internal->entries, list, nentry) {
                if (entry->signal->number == (int) sigaction_siginfo.ssi_signo) {
                        rc = medusa_signal_onevent(entry->signal, MEDUSA_SIGNAL_EVENT_FIRED);
                        if (rc < 0) {
                                return rc;
                        }
                }
        }
        return 0;
}

static void internal_destroy (struct medusa_signal_backend *backend)
{
        struct entry *entry;
        struct entry *nentry;
        struct internal *internal = (struct internal *) backend;
        if (internal == NULL) {
                return;
        }
        if (internal->sfd[0] >= 0) {
                close(internal->sfd[0]);
        }
        if (internal->sfd[1] >= 0) {
                close(internal->sfd[1]);
        }
        TAILQ_FOREACH_SAFE(entry, &internal->entries, list, nentry) {
                TAILQ_REMOVE(&internal->entries, entry, list);
                free(entry);
        }
        free(internal);
}

struct medusa_signal_backend * medusa_signal_sigaction_create (const struct medusa_signal_sigaction_init_options *options)
{
        int rc;
        struct internal *internal;
        (void) options;
        internal = (struct internal *) malloc(sizeof(struct internal));
        if (internal == NULL) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(internal, 0, sizeof(struct internal));
        TAILQ_INIT(&internal->entries);
        rc = pipe2(internal->sfd, O_NONBLOCK);
        if (rc < 0) {
                internal_destroy(&internal->backend);
                return MEDUSA_ERR_PTR(-errno);
        }
        internal->backend.name    = "sigaction";
        internal->backend.fd      = internal_fd;
        internal->backend.add     = internal_add;
        internal->backend.del     = internal_del;
        internal->backend.run     = internal_run;
        internal->backend.destroy = internal_destroy;
        return &internal->backend;
}
