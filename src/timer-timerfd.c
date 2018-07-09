
#include <stdlib.h>
#include <string.h>

#include "time.h"
#include "subject.h"
#include "timer-backend.h"

#include "timer-timerfd.h"

struct internal {
        struct medusa_timer_backend backend;
};

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
        free(internal);
}

struct medusa_timer_backend * medusa_timer_select_create (const struct medusa_timer_timerfd_init_options *options)
{
        struct internal *internal;
        (void) options;
        internal = (struct internal *) malloc(sizeof(struct internal));
        if (internal == NULL) {
                goto bail;
        }
        memset(internal, 0, sizeof(struct internal));
        internal->backend.name    = "select";
        internal->backend.set     = internal_set;
        internal->backend.get     = internal_get;
        return &internal->backend;
bail:   if (internal != NULL) {
                internal_destroy(&internal->backend);
        }
        return NULL;
}
