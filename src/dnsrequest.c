
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include <inttypes.h>
#include <sys/uio.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <sys/ioctl.h>

#include "error.h"
#include "pool.h"
#include "queue.h"
#include "buffer.h"
#include "subject-struct.h"
#include "udpsocket.h"
#include "udpsocket-private.h"
#include "dnsrequest.h"
#include "dnsrequest-private.h"
#include "dnsrequest-struct.h"
#include "monitor-private.h"

#if !defined(MIN)
#define MIN(a, b)                               (((a) < (b)) ? (a) : (b))
#endif

#define MEDUSA_DNSREQUEST_USE_POOL             1

#if defined(MEDUSA_DNSREQUEST_USE_POOL) && (MEDUSA_DNSREQUEST_USE_POOL == 1)
static struct medusa_pool *g_pool;
#endif

static inline unsigned int dnsrequest_get_state (const struct medusa_dnsrequest *dnsrequest)
{
        return dnsrequest->state;
}

static inline int dnsrequest_set_state (struct medusa_dnsrequest *dnsrequest, unsigned int state)
{
        if (state == MEDUSA_DNSREQUEST_STATE_DISCONNECTED) {
                if (!MEDUSA_IS_ERR_OR_NULL(dnsrequest->udpsocket)) {
                        medusa_udpsocket_destroy_unlocked(dnsrequest->udpsocket);
                        dnsrequest->udpsocket = NULL;
                }
        }
        dnsrequest->state = state;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_init_options_default (struct medusa_dnsrequest_init_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_dnsrequest_init_options));
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_init_unlocked (struct medusa_dnsrequest *dnsrequest, struct medusa_monitor *monitor, int (*onevent) (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *context, void *param), void *context)
{
        int rc;
        struct medusa_dnsrequest_init_options options;
        rc = medusa_dnsrequest_init_options_default(&options);
        if (rc < 0) {
                return rc;
        }
        options.monitor = monitor;
        options.onevent = onevent;
        options.context = context;
        return medusa_dnsrequest_init_with_options_unlocked(dnsrequest, &options);
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_init (struct medusa_dnsrequest *dnsrequest, struct medusa_monitor *monitor, int (*onevent) (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *context, void *param), void *context)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return -EINVAL;
        }
        medusa_monitor_lock(monitor);
        rc = medusa_dnsrequest_init_unlocked(dnsrequest, monitor, onevent, context);
        medusa_monitor_unlock(monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_init_with_options_unlocked (struct medusa_dnsrequest *dnsrequest, const struct medusa_dnsrequest_init_options *options)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                return -EINVAL;
        }
        memset(dnsrequest, 0, sizeof(struct medusa_dnsrequest));
        medusa_subject_set_type(&dnsrequest->subject, MEDUSA_SUBJECT_TYPE_DNSREQUEST);
        dnsrequest->subject.monitor = NULL;
        dnsrequest_set_state(dnsrequest, MEDUSA_DNSREQUEST_STATE_DISCONNECTED);
        dnsrequest->onevent = options->onevent;
        dnsrequest->context = options->context;
        dnsrequest->connect_timeout = -1;
        dnsrequest->read_timeout    = -1;
        if (options->nameserver != NULL) {
                dnsrequest->nameserver = strdup(options->nameserver);
                if (dnsrequest->nameserver == NULL) {
                        return -ENOMEM;
                }
        }
        if (options->name != NULL) {
                dnsrequest->name = strdup(options->name);
                if (dnsrequest->name == NULL) {
                        return -ENOMEM;
                }
        }
        dnsrequest->type = options->type;
        rc = medusa_monitor_add_unlocked(options->monitor, &dnsrequest->subject);
        if (rc < 0) {
                return rc;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_init_with_options (struct medusa_dnsrequest *dnsrequest, const struct medusa_dnsrequest_init_options *options)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return -EINVAL;
        }
        medusa_monitor_lock(options->monitor);
        rc = medusa_dnsrequest_init_with_options_unlocked(dnsrequest, options);
        medusa_monitor_unlock(options->monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void medusa_dnsrequest_uninit_unlocked (struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return;
        }
        if (dnsrequest->subject.monitor != NULL) {
                medusa_monitor_del_unlocked(&dnsrequest->subject);
        } else {
                medusa_dnsrequest_onevent_unlocked(dnsrequest, MEDUSA_DNSREQUEST_EVENT_DESTROY, NULL);
        }
}

__attribute__ ((visibility ("default"))) void medusa_dnsrequest_uninit (struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        medusa_dnsrequest_uninit_unlocked(dnsrequest);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
}

__attribute__ ((visibility ("default"))) struct medusa_dnsrequest * medusa_dnsrequest_create_unlocked (struct medusa_monitor *monitor, int (*onevent) (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *context, void *param), void *context)
{
        int rc;
        struct medusa_dnsrequest_init_options options;
        rc = medusa_dnsrequest_init_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.monitor = monitor;
        options.onevent = onevent;
        options.context = context;
        return medusa_dnsrequest_create_with_options_unlocked(&options);
}

__attribute__ ((visibility ("default"))) struct medusa_dnsrequest * medusa_dnsrequest_create (struct medusa_monitor *monitor, int (*onevent) (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *context, void *param), void *context)
{
        struct medusa_dnsrequest *rc;
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(monitor);
        rc = medusa_dnsrequest_create_unlocked(monitor, onevent, context);
        medusa_monitor_unlock(monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_dnsrequest * medusa_dnsrequest_create_with_options_unlocked (const struct medusa_dnsrequest_init_options *options)
{
        int rc;
        struct medusa_dnsrequest *dnsrequest;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
#if defined(MEDUSA_DNSREQUEST_USE_POOL) && (MEDUSA_DNSREQUEST_USE_POOL == 1)
        dnsrequest = medusa_pool_malloc(g_pool);
#else
        dnsrequest = malloc(sizeof(struct medusa_dnsrequest));
#endif
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(dnsrequest, 0, sizeof(struct medusa_dnsrequest));
        rc = medusa_dnsrequest_init_with_options_unlocked(dnsrequest, options);
        if (rc < 0) {
                medusa_dnsrequest_destroy_unlocked(dnsrequest);
                return MEDUSA_ERR_PTR(rc);
        }
        dnsrequest->subject.flags |= MEDUSA_SUBJECT_FLAG_ALLOC;
        return dnsrequest;
}

__attribute__ ((visibility ("default"))) struct medusa_dnsrequest * medusa_dnsrequest_create_with_options (const struct medusa_dnsrequest_init_options *options)
{
        struct medusa_dnsrequest *rc;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(options->monitor);
        rc = medusa_dnsrequest_create_with_options_unlocked(options);
        medusa_monitor_unlock(options->monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void medusa_dnsrequest_destroy_unlocked (struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return;
        }
        medusa_dnsrequest_uninit_unlocked(dnsrequest);
}

__attribute__ ((visibility ("default"))) void medusa_dnsrequest_destroy (struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        medusa_dnsrequest_destroy_unlocked(dnsrequest);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_dnsrequest_get_state_unlocked (const struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return MEDUSA_DNSREQUEST_STATE_UNKNOWN;
        }
        return dnsrequest_get_state(dnsrequest);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_dnsrequest_get_state (const struct medusa_dnsrequest *dnsrequest)
{
        unsigned int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return MEDUSA_DNSREQUEST_STATE_UNKNOWN;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_get_state_unlocked(dnsrequest);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_set_connect_timeout_unlocked (struct medusa_dnsrequest *dnsrequest, double timeout)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        dnsrequest->connect_timeout = timeout;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_set_connect_timeout (struct medusa_dnsrequest *dnsrequest, double timeout)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_set_connect_timeout_unlocked(dnsrequest, timeout);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) double medusa_dnsrequest_get_connect_timeout_unlocked (const struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        return dnsrequest->connect_timeout;
}

__attribute__ ((visibility ("default"))) double medusa_dnsrequest_get_connect_timeout (const struct medusa_dnsrequest *dnsrequest)
{
        double rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_get_connect_timeout_unlocked(dnsrequest);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_set_read_timeout_unlocked (struct medusa_dnsrequest *dnsrequest, double timeout)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        dnsrequest->read_timeout = timeout;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_set_read_timeout (struct medusa_dnsrequest *dnsrequest, double timeout)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_set_read_timeout_unlocked(dnsrequest, timeout);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) double medusa_dnsrequest_get_read_timeout_unlocked (const struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        return dnsrequest->read_timeout;
}

__attribute__ ((visibility ("default"))) double medusa_dnsrequest_get_read_timeout (const struct medusa_dnsrequest *dnsrequest)
{
        double rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_get_read_timeout_unlocked(dnsrequest);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_set_nameserver_unlocked (struct medusa_dnsrequest *dnsrequest, const char *nameserver)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(nameserver)) {
                return -EINVAL;
        }
        if (dnsrequest->nameserver != NULL) {
                free(dnsrequest->nameserver);
        }
        dnsrequest->nameserver = strdup(nameserver);
        if (dnsrequest->nameserver == NULL) {
                return -ENOMEM;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_set_nameserver (struct medusa_dnsrequest *dnsrequest, const char *nameserver)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(nameserver)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_set_nameserver_unlocked(dnsrequest, nameserver);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsrequest_get_nameserver_unlocked (struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return dnsrequest->nameserver;
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsrequest_get_nameserver (struct medusa_dnsrequest *dnsrequest)
{
        const char *rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_get_nameserver_unlocked(dnsrequest);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_set_type_unlocked (struct medusa_dnsrequest *dnsrequest, unsigned int type)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        dnsrequest->type = type;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_set_type (struct medusa_dnsrequest *dnsrequest, unsigned int type)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_set_type_unlocked(dnsrequest, type);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_get_type_unlocked (struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        return dnsrequest->type;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_get_type (struct medusa_dnsrequest *dnsrequest)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_get_type_unlocked(dnsrequest);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_set_name_unlocked (struct medusa_dnsrequest *dnsrequest, const char *name)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(name)) {
                return -EINVAL;
        }
        if (dnsrequest->name != NULL) {
                free(dnsrequest->name);
        }
        dnsrequest->name = strdup(name);
        if (dnsrequest->name == NULL) {
                return -ENOMEM;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_set_name (struct medusa_dnsrequest *dnsrequest, const char *name)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(name)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_set_name_unlocked(dnsrequest, name);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsrequest_get_name_unlocked (struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return dnsrequest->name;
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsrequest_get_name (struct medusa_dnsrequest *dnsrequest)
{
        const char *rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_get_name_unlocked(dnsrequest);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_lookup_unlocked (struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_lookup (struct medusa_dnsrequest *dnsrequest)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_lookup_unlocked(dnsrequest);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_onevent_unlocked (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *param)
{
        int ret;
        struct medusa_monitor *monitor;
        ret = 0;
        monitor = dnsrequest->subject.monitor;
        if (dnsrequest->onevent != NULL) {
                if ((medusa_subject_is_active(&dnsrequest->subject)) ||
                    (events & MEDUSA_DNSREQUEST_EVENT_DESTROY)) {
                        medusa_monitor_unlock(monitor);
                        ret = dnsrequest->onevent(dnsrequest, events, dnsrequest->context, param);
                        medusa_monitor_lock(monitor);
                }
        }
        if (events & MEDUSA_DNSREQUEST_EVENT_DESTROY) {
                if (dnsrequest->nameserver != NULL) {
                        free(dnsrequest->nameserver);
                        dnsrequest->nameserver = NULL;
                }
                if (dnsrequest->name != NULL) {
                        free(dnsrequest->name);
                        dnsrequest->name = NULL;
                }
                if (!MEDUSA_IS_ERR_OR_NULL(dnsrequest->udpsocket)) {
                        medusa_udpsocket_destroy_unlocked(dnsrequest->udpsocket);
                        dnsrequest->udpsocket = NULL;
                }
                if (dnsrequest->subject.flags & MEDUSA_SUBJECT_FLAG_ALLOC) {
#if defined(MEDUSA_DNSREQUEST_USE_POOL) && (MEDUSA_DNSREQUEST_USE_POOL == 1)
                        medusa_pool_free(dnsrequest);
#else
                        free(dnsrequest);
#endif
                } else {
                        memset(dnsrequest, 0, sizeof(struct medusa_dnsrequest));
                }
        }
        return ret;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_onevent (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *param)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_onevent_unlocked(dnsrequest, events, param);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_dnsrequest_get_monitor_unlocked (struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return dnsrequest->subject.monitor;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_dnsrequest_get_monitor (struct medusa_dnsrequest *dnsrequest)
{
        struct medusa_monitor *rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_get_monitor_unlocked(dnsrequest);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsrequest_event_string (unsigned int events)
{
        if (events == MEDUSA_DNSREQUEST_EVENT_ERROR)           return "MEDUSA_DNSREQUEST_EVENT_ERROR";
        if (events == MEDUSA_DNSREQUEST_EVENT_DESTROY)         return "MEDUSA_DNSREQUEST_EVENT_DESTROY";
        return "MEDUSA_DNSREQUEST_EVENT_UNKNOWN";
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsrequest_state_string (unsigned int state)
{
        if (state == MEDUSA_DNSREQUEST_STATE_UNKNOWN)          return "MEDUSA_DNSREQUEST_STATE_UNKNOWN";
        if (state == MEDUSA_DNSREQUEST_STATE_DISCONNECTED)     return "MEDUSA_DNSREQUEST_STATE_DISCONNECTED";
        return "MEDUSA_DNSREQUEST_STATE_UNKNOWN";
}

__attribute__ ((constructor)) static void dnsrequest_constructor (void)
{
#if defined(MEDUSA_DNSREQUEST_USE_POOL) && (MEDUSA_DNSREQUEST_USE_POOL == 1)
        g_pool = medusa_pool_create("medusa-dnsrequest", sizeof(struct medusa_dnsrequest), 0, 0, MEDUSA_POOL_FLAG_DEFAULT | MEDUSA_POOL_FLAG_THREAD_SAFE, NULL, NULL, NULL);
#endif
}

__attribute__ ((destructor)) static void dnsrequest_destructor (void)
{
#if defined(MEDUSA_DNSREQUEST_USE_POOL) && (MEDUSA_DNSREQUEST_USE_POOL == 1)
        if (g_pool != NULL) {
                medusa_pool_destroy(g_pool);
        }
#endif
}
