
#include <stdlib.h>
#include <string.h>

#include "time.h"
#include "subject.h"
#include "monitor-backend.h"

#include "monitor-kqueue.h"

struct private {
        struct medusa_monitor_backend backend;
};

static int private_add (struct medusa_monitor_backend *backend, struct medusa_subject *subject, unsigned int events)
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
        return 0;
bail:   return -1;
}

static int private_del (struct medusa_monitor_backend *backend, struct medusa_subject *subject)
{
        struct private *private = (struct private *) backend;
        if (private == NULL) {
                goto bail;
        }
        if (subject == NULL) {
                goto bail;
        }
        return 0;
bail:   return -1;
}

static void private_destroy (struct medusa_monitor_backend *backend)
{
        struct private *private = (struct private *) backend;
        if (private == NULL) {
                return;
        }
        free(private);
}

struct medusa_monitor_backend * medusa_monitor_kqueue_create (const struct medusa_monitor_kqueue_init_options *options)
{
        struct private *private;
        (void) options;
        private = malloc(sizeof(struct private));
        if (private == NULL) {
                goto bail;
        }
        memset(private, 0, sizeof(struct private));
        private->backend.name    = "kqueue";
        private->backend.add     = private_add;
        private->backend.mod     = private_mod;
        private->backend.del     = private_del;
        private->backend.destroy = private_destroy;
        return &private->backend;
bail:   if (private != NULL) {
                private_destroy(&private->backend);
        }
        return NULL;
}
