
#include <stdlib.h>
#include <string.h>

#include "time.h"
#include "subject.h"
#include "poll-backend.h"

#include "poll-kqueue.h"

struct internal {
        struct medusa_poll_backend backend;
};

static int internal_add (struct medusa_poll_backend *backend, struct medusa_subject *subject, unsigned int events)
{
        struct internal *internal = (struct internal *) backend;
        if (internal == NULL) {
                goto bail;
        }
        if (subject == NULL) {
                goto bail;
        }
        if (events == 0) {
                goto bail;
        }
        return 0;
bail:   return -1;
}

static int internal_mod (struct medusa_poll_backend *backend, struct medusa_subject *subject, unsigned int events)
{
        struct internal *internal = (struct internal *) backend;
        if (internal == NULL) {
                goto bail;
        }
        if (subject == NULL) {
                goto bail;
        }
        if (events == 0) {
                goto bail;
        }
        return 0;
bail:   return -1;
}

static int internal_del (struct medusa_poll_backend *backend, struct medusa_subject *subject)
{
        struct internal *internal = (struct internal *) backend;
        if (internal == NULL) {
                goto bail;
        }
        if (subject == NULL) {
                goto bail;
        }
        return 0;
bail:   return -1;
}

static int internal_run (struct medusa_poll_backend *backend, struct medusa_timespec *timespec)
{
        struct internal *internal = (struct internal *) backend;
        if (internal == NULL) {
                goto bail;
        }
        (void) timespec;
        return -1;
        return 0;
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

struct medusa_poll_backend * medusa_monitor_kqueue_create (const struct medusa_monitor_kqueue_init_options *options)
{
        struct internal *internal;
        (void) options;
        internal = (struct internal *) malloc(sizeof(struct internal));
        if (internal == NULL) {
                goto bail;
        }
        memset(internal, 0, sizeof(struct internal));
        internal->backend.name    = "kqueue";
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
