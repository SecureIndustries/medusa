
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "error.h"
#include "pool.h"
#include "queue.h"
#include "subject-struct.h"
#include "dnsresolver.h"
#include "dnsresolver-private.h"
#include "dnsresolver-struct.h"
#include "monitor-private.h"

#define MEDUSA_DNSRESOLVER_USE_POOL             1

#if defined(MEDUSA_DNSRESOLVER_USE_POOL) && (MEDUSA_DNSRESOLVER_USE_POOL == 1)
static struct medusa_pool *g_pool;
#endif

static inline unsigned int dnsresolver_get_state (const struct medusa_dnsresolver *dnsresolver)
{
        return dnsresolver->state;
}

static inline int dnsresolver_set_state (struct medusa_dnsresolver *dnsresolver, unsigned int state, unsigned int error)
{
        int rc;
        unsigned int pstate;
        struct medusa_dnsresolver_event_state_changed medusa_dnsresolver_event_state_changed;

        pstate = dnsresolver->state;
        dnsresolver->error = error;
        dnsresolver->state = state;

        medusa_dnsresolver_event_state_changed.pstate = pstate;
        medusa_dnsresolver_event_state_changed.state  = dnsresolver->state;
        medusa_dnsresolver_event_state_changed.error  = dnsresolver->error;
        rc = medusa_dnsresolver_onevent_unlocked(dnsresolver, MEDUSA_DNSRESOLVER_EVENT_STATE_CHANGED, &medusa_dnsresolver_event_state_changed);
        if (rc < 0) {
                return rc;
        }

        return 0;
}

static int dnsresolver_init_with_options_unlocked (struct medusa_dnsresolver *dnsresolver, const struct medusa_dnsresolver_init_options *options)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
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
        memset(dnsresolver, 0, sizeof(struct medusa_dnsresolver));
        medusa_subject_set_type(&dnsresolver->subject, MEDUSA_SUBJECT_TYPE_DNSRESOLVER);
        dnsresolver->subject.monitor = NULL;
        dnsresolver_set_state(dnsresolver, MEDUSA_DNSRESOLVER_EVENT_STOPPED, 0);
        dnsresolver->onevent = options->onevent;
        dnsresolver->context = options->context;
        rc = medusa_monitor_add_unlocked(options->monitor, &dnsresolver->subject);
        if (rc < 0) {
                return rc;
        }
        if (options->nameserver != NULL) {
                rc = medusa_dnsresolver_set_nameserver_unlocked(dnsresolver, options->nameserver);
                if (rc != 0) {
                        return rc;
                }
        }
        return 0;
}

static void dnsresolver_uninit_unlocked (struct medusa_dnsresolver *dnsresolver)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return;
        }
        if (dnsresolver->subject.monitor != NULL) {
                medusa_monitor_del_unlocked(&dnsresolver->subject);
        } else {
                medusa_dnsresolver_onevent_unlocked(dnsresolver, MEDUSA_DNSRESOLVER_EVENT_DESTROY, NULL);
        }
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_init_options_default (struct medusa_dnsresolver_init_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_dnsresolver_init_options));
        return 0;
}

__attribute__ ((visibility ("default"))) struct medusa_dnsresolver * medusa_dnsresolver_create_unlocked (struct medusa_monitor *monitor, int (*onevent) (struct medusa_dnsresolver *dnsresolver, unsigned int events, void *context, void *param), void *context)
{
        int rc;
        struct medusa_dnsresolver_init_options options;
        rc = medusa_dnsresolver_init_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.monitor = monitor;
        options.onevent = onevent;
        options.context = context;
        return medusa_dnsresolver_create_with_options_unlocked(&options);
}

__attribute__ ((visibility ("default"))) struct medusa_dnsresolver * medusa_dnsresolver_create (struct medusa_monitor *monitor, int (*onevent) (struct medusa_dnsresolver *dnsresolver, unsigned int events, void *context, void *param), void *context)
{
        struct medusa_dnsresolver *rc;
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(monitor);
        rc = medusa_dnsresolver_create_unlocked(monitor, onevent, context);
        medusa_monitor_unlock(monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_dnsresolver * medusa_dnsresolver_create_with_options_unlocked (const struct medusa_dnsresolver_init_options *options)
{
        int rc;
        struct medusa_dnsresolver *dnsresolver;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
#if defined(MEDUSA_DNSRESOLVER_USE_POOL) && (MEDUSA_DNSRESOLVER_USE_POOL == 1)
        dnsresolver = medusa_pool_malloc(g_pool);
#else
        dnsresolver = malloc(sizeof(struct medusa_dnsresolver));
#endif
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(dnsresolver, 0, sizeof(struct medusa_dnsresolver));
        rc = dnsresolver_init_with_options_unlocked(dnsresolver, options);
        if (rc < 0) {
                medusa_dnsresolver_destroy_unlocked(dnsresolver);
                return MEDUSA_ERR_PTR(rc);
        }
        return dnsresolver;
}

__attribute__ ((visibility ("default"))) struct medusa_dnsresolver * medusa_dnsresolver_create_with_options (const struct medusa_dnsresolver_init_options *options)
{
        struct medusa_dnsresolver *rc;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(options->monitor);
        rc = medusa_dnsresolver_create_with_options_unlocked(options);
        medusa_monitor_unlock(options->monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void medusa_dnsresolver_destroy_unlocked (struct medusa_dnsresolver *dnsresolver)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return;
        }
        dnsresolver_uninit_unlocked(dnsresolver);
}

__attribute__ ((visibility ("default"))) void medusa_dnsresolver_destroy (struct medusa_dnsresolver *dnsresolver)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return;
        }
        medusa_monitor_lock(dnsresolver->subject.monitor);
        medusa_dnsresolver_destroy_unlocked(dnsresolver);
        medusa_monitor_unlock(dnsresolver->subject.monitor);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_dnsresolver_get_state_unlocked (const struct medusa_dnsresolver *dnsresolver)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return MEDUSA_DNSRESOLVER_STATE_UNKNOWN;
        }
        return dnsresolver_get_state(dnsresolver);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_dnsresolver_get_state (const struct medusa_dnsresolver *dnsresolver)
{
        unsigned int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return MEDUSA_DNSRESOLVER_STATE_UNKNOWN;
        }
        medusa_monitor_lock(dnsresolver->subject.monitor);
        rc = medusa_dnsresolver_get_state_unlocked(dnsresolver);
        medusa_monitor_unlock(dnsresolver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_set_nameserver_unlocked (struct medusa_dnsresolver *dnsresolver, const char *nameserver)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(nameserver)) {
                return -EINVAL;
        }
        if (dnsresolver->nameserver != NULL) {
                free(dnsresolver->nameserver);
        }
        dnsresolver->nameserver = strdup(nameserver);
        if (dnsresolver->nameserver == NULL) {
                return -ENOMEM;
        }
        return medusa_monitor_mod_unlocked(&dnsresolver->subject);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_set_nameserver (struct medusa_dnsresolver *dnsresolver, const char *nameserver)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(nameserver)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsresolver->subject.monitor);
        rc = medusa_dnsresolver_set_nameserver_unlocked(dnsresolver, nameserver);
        medusa_monitor_unlock(dnsresolver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsresolver_get_nameserver_unlocked (struct medusa_dnsresolver *dnsresolver)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return dnsresolver->nameserver;
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsresolver_get_nameserver (struct medusa_dnsresolver *dnsresolver)
{
        const char *rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(dnsresolver->subject.monitor);
        rc = medusa_dnsresolver_get_nameserver_unlocked(dnsresolver);
        medusa_monitor_unlock(dnsresolver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_set_context_unlocked (struct medusa_dnsresolver *dnsresolver, void *context)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return -EINVAL;
        }
        dnsresolver->context = context;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_set_context (struct medusa_dnsresolver *dnsresolver, void *context)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsresolver->subject.monitor);
        rc = medusa_dnsresolver_set_context_unlocked(dnsresolver, context);
        medusa_monitor_unlock(dnsresolver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void * medusa_dnsresolver_get_context_unlocked (struct medusa_dnsresolver *dnsresolver)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return dnsresolver->context;
}

__attribute__ ((visibility ("default"))) void * medusa_dnsresolver_get_context (struct medusa_dnsresolver *dnsresolver)
{
        void *rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(dnsresolver->subject.monitor);
        rc = medusa_dnsresolver_get_context_unlocked(dnsresolver);
        medusa_monitor_unlock(dnsresolver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_set_userdata_unlocked (struct medusa_dnsresolver *dnsresolver, void *userdata)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return -EINVAL;
        }
        dnsresolver->userdata = userdata;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_set_userdata (struct medusa_dnsresolver *dnsresolver, void *userdata)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsresolver->subject.monitor);
        rc = medusa_dnsresolver_set_userdata_unlocked(dnsresolver, userdata);
        medusa_monitor_unlock(dnsresolver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void * medusa_dnsresolver_get_userdata_unlocked (struct medusa_dnsresolver *dnsresolver)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return dnsresolver->userdata;
}

__attribute__ ((visibility ("default"))) void * medusa_dnsresolver_get_userdata (struct medusa_dnsresolver *dnsresolver)
{
        void *rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(dnsresolver->subject.monitor);
        rc = medusa_dnsresolver_get_userdata_unlocked(dnsresolver);
        medusa_monitor_unlock(dnsresolver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_set_userdata_ptr_unlocked (struct medusa_dnsresolver *dnsresolver, void *userdata)
{
        return medusa_dnsresolver_set_userdata_unlocked(dnsresolver, userdata);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_set_userdata_ptr (struct medusa_dnsresolver *dnsresolver, void *userdata)
{
        return medusa_dnsresolver_set_userdata(dnsresolver, userdata);
}

__attribute__ ((visibility ("default"))) void * medusa_dnsresolver_get_userdata_ptr_unlocked (struct medusa_dnsresolver *dnsresolver)
{
        return medusa_dnsresolver_get_userdata_unlocked(dnsresolver);
}

__attribute__ ((visibility ("default"))) void * medusa_dnsresolver_get_userdata_ptr (struct medusa_dnsresolver *dnsresolver)
{
        return medusa_dnsresolver_get_userdata(dnsresolver);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_set_userdata_int_unlocked (struct medusa_dnsresolver *dnsresolver, int userdata)
{
        return medusa_dnsresolver_set_userdata_unlocked(dnsresolver, (void *) (intptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_set_userdata_int (struct medusa_dnsresolver *dnsresolver, int userdata)
{
        return medusa_dnsresolver_set_userdata(dnsresolver, (void *) (intptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_get_userdata_int_unlocked (struct medusa_dnsresolver *dnsresolver)
{
        return (int) (intptr_t) medusa_dnsresolver_get_userdata_unlocked(dnsresolver);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_get_userdata_int (struct medusa_dnsresolver *dnsresolver)
{
        return (int) (intptr_t) medusa_dnsresolver_get_userdata(dnsresolver);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_set_userdata_uint_unlocked (struct medusa_dnsresolver *dnsresolver, unsigned int userdata)
{
        return medusa_dnsresolver_set_userdata_unlocked(dnsresolver, (void *) (uintptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_set_userdata_uint (struct medusa_dnsresolver *dnsresolver, unsigned int userdata)
{
        return medusa_dnsresolver_set_userdata(dnsresolver, (void *) (uintptr_t) userdata);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_dnsresolver_get_userdata_uint_unlocked (struct medusa_dnsresolver *dnsresolver)
{
        return (unsigned int) (intptr_t) medusa_dnsresolver_get_userdata_unlocked(dnsresolver);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_dnsresolver_get_userdata_uint (struct medusa_dnsresolver *dnsresolver)
{
        return (unsigned int) (uintptr_t) medusa_dnsresolver_get_userdata(dnsresolver);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_onevent_unlocked (struct medusa_dnsresolver *dnsresolver, unsigned int events, void *param)
{
        int ret;
        struct medusa_monitor *monitor;
        ret = 0;
        monitor = dnsresolver->subject.monitor;
        if (dnsresolver->onevent != NULL) {
                if ((medusa_subject_is_active(&dnsresolver->subject)) ||
                    (events & MEDUSA_DNSRESOLVER_EVENT_DESTROY)) {
                        medusa_monitor_unlock(monitor);
                        ret = dnsresolver->onevent(dnsresolver, events, dnsresolver->context, param);
                        medusa_monitor_lock(monitor);
                }
        }
        if (events & MEDUSA_DNSRESOLVER_EVENT_DESTROY) {
                if (dnsresolver->nameserver != NULL) {
                        free(dnsresolver->nameserver);
                        dnsresolver->nameserver = NULL;
                }
#if defined(MEDUSA_DNSRESOLVER_USE_POOL) && (MEDUSA_DNSRESOLVER_USE_POOL == 1)
                medusa_pool_free(dnsresolver);
#else
                free(dnsresolver);
#endif
        }
        return ret;
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_set_enabled_unlocked (struct medusa_dnsresolver *dnsresolver, int enabled)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return -EINVAL;
        }
        dnsresolver->enabled = !!enabled;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_set_enabled (struct medusa_dnsresolver *dnsresolver, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsresolver->subject.monitor);
        rc = medusa_dnsresolver_set_enabled_unlocked(dnsresolver, enabled);
        medusa_monitor_unlock(dnsresolver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_get_enabled_unlocked (struct medusa_dnsresolver *dnsresolver)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return -EINVAL;
        }
        return dnsresolver->enabled;
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_get_enabled (struct medusa_dnsresolver *dnsresolver)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsresolver->subject.monitor);
        rc = medusa_dnsresolver_get_enabled_unlocked(dnsresolver);
        medusa_monitor_unlock(dnsresolver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_start_unlocked (struct medusa_dnsresolver *dnsresolver)
{
        return medusa_dnsresolver_set_enabled_unlocked(dnsresolver, 1);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_start (struct medusa_dnsresolver *dnsresolver)
{
        return medusa_dnsresolver_set_enabled(dnsresolver, 1);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_stop_unlocked (struct medusa_dnsresolver *dnsresolver)
{
        return medusa_dnsresolver_set_enabled_unlocked(dnsresolver, 0);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_stop (struct medusa_dnsresolver *dnsresolver)
{
        return medusa_dnsresolver_set_enabled(dnsresolver, 0);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_onevent (struct medusa_dnsresolver *dnsresolver, unsigned int events, void *param)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsresolver->subject.monitor);
        rc = medusa_dnsresolver_onevent_unlocked(dnsresolver, events, param);
        medusa_monitor_unlock(dnsresolver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_dnsresolver_get_monitor_unlocked (struct medusa_dnsresolver *dnsresolver)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return dnsresolver->subject.monitor;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_dnsresolver_get_monitor (struct medusa_dnsresolver *dnsresolver)
{
        struct medusa_monitor *rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(dnsresolver->subject.monitor);
        rc = medusa_dnsresolver_get_monitor_unlocked(dnsresolver);
        medusa_monitor_unlock(dnsresolver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsresolver_event_string (unsigned int events)
{
        if (events == MEDUSA_DNSRESOLVER_EVENT_STARTED)         return "MEDUSA_DNSRESOLVER_EVENT_STARTED";
        if (events == MEDUSA_DNSRESOLVER_EVENT_STOPPED)         return "MEDUSA_DNSRESOLVER_EVENT_STOPPED";
        if (events == MEDUSA_DNSRESOLVER_EVENT_ERROR)           return "MEDUSA_DNSRESOLVER_EVENT_ERROR";
        if (events == MEDUSA_DNSRESOLVER_EVENT_STATE_CHANGED)   return "MEDUSA_DNSRESOLVER_EVENT_STATE_CHANGED";
        if (events == MEDUSA_DNSRESOLVER_EVENT_DESTROY)         return "MEDUSA_DNSRESOLVER_EVENT_DESTROY";
        return "MEDUSA_DNSRESOLVER_EVENT_UNKNOWN";
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsresolver_state_string (unsigned int state)
{
        if (state == MEDUSA_DNSRESOLVER_STATE_UNKNOWN)          return "MEDUSA_DNSRESOLVER_STATE_UNKNOWN";
        if (state == MEDUSA_DNSRESOLVER_STATE_STARTED)          return "MEDUSA_DNSRESOLVER_STATE_STARTED";
        if (state == MEDUSA_DNSRESOLVER_STATE_STOPPED)          return "MEDUSA_DNSRESOLVER_STATE_STOPPED";
        if (state == MEDUSA_DNSRESOLVER_STATE_ERROR)            return "MEDUSA_DNSRESOLVER_STATE_ERROR";
        return "MEDUSA_DNSRESOLVER_STATE_UNKNOWN";
}

static inline unsigned int dnsresolver_lookup_get_state (const struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        return dnsresolver_lookup->state;
}

static inline int dnsresolver_lookup_set_state (struct medusa_dnsresolver_lookup *dnsresolver_lookup, unsigned int state, unsigned int error)
{
        int rc;
        unsigned int pstate;
        struct medusa_dnsresolver_lookup_event_state_changed medusa_dnsresolver_lookup_event_state_changed;

        pstate = dnsresolver_lookup->state;
        dnsresolver_lookup->error = error;
        dnsresolver_lookup->state = state;

        medusa_dnsresolver_lookup_event_state_changed.pstate = pstate;
        medusa_dnsresolver_lookup_event_state_changed.state  = dnsresolver_lookup->state;
        medusa_dnsresolver_lookup_event_state_changed.error  = dnsresolver_lookup->error;
        rc = medusa_dnsresolver_lookup_onevent_unlocked(dnsresolver_lookup, MEDUSA_DNSRESOLVER_LOOKUP_EVENT_STATE_CHANGED, &medusa_dnsresolver_lookup_event_state_changed);
        if (rc < 0) {
                return rc;
        }

        return 0;
}

static int dnsresolver_lookup_init_with_options_unlocked (struct medusa_dnsresolver_lookup *dnsresolver_lookup, struct medusa_dnsresolver *dnsresolver, const struct medusa_dnsresolver_lookup_options *options)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                return -EINVAL;
        }
        memset(dnsresolver_lookup, 0, sizeof(struct medusa_dnsresolver_lookup));
        medusa_subject_set_type(&dnsresolver_lookup->subject, MEDUSA_SUBJECT_TYPE_DNSRESOLVER_LOOKUP);
        dnsresolver_lookup->subject.monitor = NULL;
        dnsresolver_lookup_set_state(dnsresolver_lookup, MEDUSA_DNSRESOLVER_LOOKUP_EVENT_STOPPED, 0);
        dnsresolver_lookup->onevent = options->onevent;
        dnsresolver_lookup->context = options->context;
        rc = medusa_monitor_add_unlocked(dnsresolver->subject.monitor, &dnsresolver_lookup->subject);
        if (rc < 0) {
                return rc;
        }
        if (options->nameserver != NULL) {
                rc = medusa_dnsresolver_lookup_set_nameserver_unlocked(dnsresolver_lookup, options->nameserver);
                if (rc != 0) {
                        return rc;
                }
        }
        return 0;
}

static void dnsresolver_lookup_uninit_unlocked (struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return;
        }
        if (dnsresolver_lookup->subject.monitor != NULL) {
                medusa_monitor_del_unlocked(&dnsresolver_lookup->subject);
        } else {
                medusa_dnsresolver_lookup_onevent_unlocked(dnsresolver_lookup, MEDUSA_DNSRESOLVER_LOOKUP_EVENT_DESTROY, NULL);
        }
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_options_default (struct medusa_dnsresolver_lookup_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_dnsresolver_lookup_options));
        return 0;
}

__attribute__ ((visibility ("default"))) struct medusa_dnsresolver_lookup * medusa_dnsresolver_lookup_unlocked (struct medusa_dnsresolver *dnsresolver, unsigned int family, const char *name, int (*onevent) (struct medusa_dnsresolver_lookup *dnsresolver_lookup, unsigned int events, void *context, void *param), void *context)
{
        int rc;
        struct medusa_dnsresolver_lookup_options options;
        rc = medusa_dnsresolver_lookup_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.family  = family;
        options.name    = name;
        options.onevent = onevent;
        options.context = context;
        return medusa_dnsresolver_lookup_with_options_unlocked(dnsresolver, &options);
}

__attribute__ ((visibility ("default"))) struct medusa_dnsresolver_lookup * medusa_dnsresolver_lookup (struct medusa_dnsresolver *dnsresolver, unsigned int family, const char *name, int (*onevent) (struct medusa_dnsresolver_lookup *dnsresolver_lookup, unsigned int events, void *context, void *param), void *context)
{
        struct medusa_dnsresolver_lookup *rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(dnsresolver->subject.monitor);
        rc = medusa_dnsresolver_lookup_unlocked(dnsresolver, family, name, onevent, context);
        medusa_monitor_unlock(dnsresolver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_dnsresolver_lookup * medusa_dnsresolver_lookup_with_options_unlocked (struct medusa_dnsresolver *dnsresolver, const struct medusa_dnsresolver_lookup_options *options)
{
        int rc;
        struct medusa_dnsresolver_lookup *dnsresolver_lookup;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
#if defined(MEDUSA_DNSRESOLVER_USE_POOL) && (MEDUSA_DNSRESOLVER_USE_POOL == 1)
        dnsresolver_lookup = medusa_pool_malloc(g_pool);
#else
        dnsresolver_lookup = malloc(sizeof(struct medusa_dnsresolver_lookup));
#endif
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(dnsresolver_lookup, 0, sizeof(struct medusa_dnsresolver_lookup));
        rc = dnsresolver_lookup_init_with_options_unlocked(dnsresolver_lookup, dnsresolver, options);
        if (rc < 0) {
                medusa_dnsresolver_lookup_destroy_unlocked(dnsresolver_lookup);
                return MEDUSA_ERR_PTR(rc);
        }
        return dnsresolver_lookup;
}

__attribute__ ((visibility ("default"))) struct medusa_dnsresolver_lookup * medusa_dnsresolver_lookup_with_options (struct medusa_dnsresolver *dnsresolver, const struct medusa_dnsresolver_lookup_options *options)
{
        struct medusa_dnsresolver_lookup *rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(dnsresolver->subject.monitor);
        rc = medusa_dnsresolver_lookup_with_options_unlocked(dnsresolver, options);
        medusa_monitor_unlock(dnsresolver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void medusa_dnsresolver_lookup_destroy_unlocked (struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return;
        }
        dnsresolver_lookup_uninit_unlocked(dnsresolver_lookup);
}

__attribute__ ((visibility ("default"))) void medusa_dnsresolver_lookup_destroy (struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return;
        }
        medusa_monitor_lock(dnsresolver_lookup->subject.monitor);
        medusa_dnsresolver_lookup_destroy_unlocked(dnsresolver_lookup);
        medusa_monitor_unlock(dnsresolver_lookup->subject.monitor);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_dnsresolver_lookup_get_state_unlocked (const struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return MEDUSA_DNSRESOLVER_LOOKUP_STATE_UNKNOWN;
        }
        return dnsresolver_lookup_get_state(dnsresolver_lookup);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_dnsresolver_lookup_get_state (const struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        unsigned int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return MEDUSA_DNSRESOLVER_LOOKUP_STATE_UNKNOWN;
        }
        medusa_monitor_lock(dnsresolver_lookup->subject.monitor);
        rc = medusa_dnsresolver_lookup_get_state_unlocked(dnsresolver_lookup);
        medusa_monitor_unlock(dnsresolver_lookup->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_set_nameserver_unlocked (struct medusa_dnsresolver_lookup *dnsresolver_lookup, const char *nameserver)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(nameserver)) {
                return -EINVAL;
        }
        if (dnsresolver_lookup->nameserver != NULL) {
                free(dnsresolver_lookup->nameserver);
        }
        dnsresolver_lookup->nameserver = strdup(nameserver);
        if (dnsresolver_lookup->nameserver == NULL) {
                return -ENOMEM;
        }
        return medusa_monitor_mod_unlocked(&dnsresolver_lookup->subject);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_set_nameserver (struct medusa_dnsresolver_lookup *dnsresolver_lookup, const char *nameserver)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(nameserver)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsresolver_lookup->subject.monitor);
        rc = medusa_dnsresolver_lookup_set_nameserver_unlocked(dnsresolver_lookup, nameserver);
        medusa_monitor_unlock(dnsresolver_lookup->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsresolver_lookup_get_nameserver_unlocked (struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return dnsresolver_lookup->nameserver;
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsresolver_lookup_get_nameserver (struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        const char *rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(dnsresolver_lookup->subject.monitor);
        rc = medusa_dnsresolver_lookup_get_nameserver_unlocked(dnsresolver_lookup);
        medusa_monitor_unlock(dnsresolver_lookup->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_set_context_unlocked (struct medusa_dnsresolver_lookup *dnsresolver_lookup, void *context)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return -EINVAL;
        }
        dnsresolver_lookup->context = context;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_set_context (struct medusa_dnsresolver_lookup *dnsresolver_lookup, void *context)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsresolver_lookup->subject.monitor);
        rc = medusa_dnsresolver_lookup_set_context_unlocked(dnsresolver_lookup, context);
        medusa_monitor_unlock(dnsresolver_lookup->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void * medusa_dnsresolver_lookup_get_context_unlocked (struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return dnsresolver_lookup->context;
}

__attribute__ ((visibility ("default"))) void * medusa_dnsresolver_lookup_get_context (struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        void *rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(dnsresolver_lookup->subject.monitor);
        rc = medusa_dnsresolver_lookup_get_context_unlocked(dnsresolver_lookup);
        medusa_monitor_unlock(dnsresolver_lookup->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_set_userdata_unlocked (struct medusa_dnsresolver_lookup *dnsresolver_lookup, void *userdata)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return -EINVAL;
        }
        dnsresolver_lookup->userdata = userdata;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_set_userdata (struct medusa_dnsresolver_lookup *dnsresolver_lookup, void *userdata)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsresolver_lookup->subject.monitor);
        rc = medusa_dnsresolver_lookup_set_userdata_unlocked(dnsresolver_lookup, userdata);
        medusa_monitor_unlock(dnsresolver_lookup->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void * medusa_dnsresolver_lookup_get_userdata_unlocked (struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return dnsresolver_lookup->userdata;
}

__attribute__ ((visibility ("default"))) void * medusa_dnsresolver_lookup_get_userdata (struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        void *rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(dnsresolver_lookup->subject.monitor);
        rc = medusa_dnsresolver_lookup_get_userdata_unlocked(dnsresolver_lookup);
        medusa_monitor_unlock(dnsresolver_lookup->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_set_userdata_ptr_unlocked (struct medusa_dnsresolver_lookup *dnsresolver_lookup, void *userdata)
{
        return medusa_dnsresolver_lookup_set_userdata_unlocked(dnsresolver_lookup, userdata);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_set_userdata_ptr (struct medusa_dnsresolver_lookup *dnsresolver_lookup, void *userdata)
{
        return medusa_dnsresolver_lookup_set_userdata(dnsresolver_lookup, userdata);
}

__attribute__ ((visibility ("default"))) void * medusa_dnsresolver_lookup_get_userdata_ptr_unlocked (struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        return medusa_dnsresolver_lookup_get_userdata_unlocked(dnsresolver_lookup);
}

__attribute__ ((visibility ("default"))) void * medusa_dnsresolver_lookup_get_userdata_ptr (struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        return medusa_dnsresolver_lookup_get_userdata(dnsresolver_lookup);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_set_userdata_int_unlocked (struct medusa_dnsresolver_lookup *dnsresolver_lookup, int userdata)
{
        return medusa_dnsresolver_lookup_set_userdata_unlocked(dnsresolver_lookup, (void *) (intptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_set_userdata_int (struct medusa_dnsresolver_lookup *dnsresolver_lookup, int userdata)
{
        return medusa_dnsresolver_lookup_set_userdata(dnsresolver_lookup, (void *) (intptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_get_userdata_int_unlocked (struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        return (int) (intptr_t) medusa_dnsresolver_lookup_get_userdata_unlocked(dnsresolver_lookup);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_get_userdata_int (struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        return (int) (intptr_t) medusa_dnsresolver_lookup_get_userdata(dnsresolver_lookup);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_set_userdata_uint_unlocked (struct medusa_dnsresolver_lookup *dnsresolver_lookup, unsigned int userdata)
{
        return medusa_dnsresolver_lookup_set_userdata_unlocked(dnsresolver_lookup, (void *) (uintptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_set_userdata_uint (struct medusa_dnsresolver_lookup *dnsresolver_lookup, unsigned int userdata)
{
        return medusa_dnsresolver_lookup_set_userdata(dnsresolver_lookup, (void *) (uintptr_t) userdata);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_dnsresolver_lookup_get_userdata_uint_unlocked (struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        return (unsigned int) (intptr_t) medusa_dnsresolver_lookup_get_userdata_unlocked(dnsresolver_lookup);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_dnsresolver_lookup_get_userdata_uint (struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        return (unsigned int) (uintptr_t) medusa_dnsresolver_lookup_get_userdata(dnsresolver_lookup);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_onevent_unlocked (struct medusa_dnsresolver_lookup *dnsresolver_lookup, unsigned int events, void *param)
{
        int ret;
        struct medusa_monitor *monitor;
        ret = 0;
        monitor = dnsresolver_lookup->subject.monitor;
        if (dnsresolver_lookup->onevent != NULL) {
                if ((medusa_subject_is_active(&dnsresolver_lookup->subject)) ||
                    (events & MEDUSA_DNSRESOLVER_LOOKUP_EVENT_DESTROY)) {
                        medusa_monitor_unlock(monitor);
                        ret = dnsresolver_lookup->onevent(dnsresolver_lookup, events, dnsresolver_lookup->context, param);
                        medusa_monitor_lock(monitor);
                }
        }
        if (events & MEDUSA_DNSRESOLVER_LOOKUP_EVENT_DESTROY) {
                if (dnsresolver_lookup->nameserver != NULL) {
                        free(dnsresolver_lookup->nameserver);
                        dnsresolver_lookup->nameserver = NULL;
                }
#if defined(MEDUSA_DNSRESOLVER_USE_POOL) && (MEDUSA_DNSRESOLVER_USE_POOL == 1)
                medusa_pool_free(dnsresolver_lookup);
#else
                free(dnsresolver_lookup);
#endif
        }
        return ret;
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_set_enabled_unlocked (struct medusa_dnsresolver_lookup *dnsresolver_lookup, int enabled)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return -EINVAL;
        }
        dnsresolver_lookup->enabled = !!enabled;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_set_enabled (struct medusa_dnsresolver_lookup *dnsresolver_lookup, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsresolver_lookup->subject.monitor);
        rc = medusa_dnsresolver_lookup_set_enabled_unlocked(dnsresolver_lookup, enabled);
        medusa_monitor_unlock(dnsresolver_lookup->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_get_enabled_unlocked (struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return -EINVAL;
        }
        return dnsresolver_lookup->enabled;
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_get_enabled (struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsresolver_lookup->subject.monitor);
        rc = medusa_dnsresolver_lookup_get_enabled_unlocked(dnsresolver_lookup);
        medusa_monitor_unlock(dnsresolver_lookup->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_start_unlocked (struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        return medusa_dnsresolver_lookup_set_enabled_unlocked(dnsresolver_lookup, 1);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_start (struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        return medusa_dnsresolver_lookup_set_enabled(dnsresolver_lookup, 1);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_stop_unlocked (struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        return medusa_dnsresolver_lookup_set_enabled_unlocked(dnsresolver_lookup, 0);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_stop (struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        return medusa_dnsresolver_lookup_set_enabled(dnsresolver_lookup, 0);
}

__attribute__ ((visibility ("default"))) int medusa_dnsresolver_lookup_onevent (struct medusa_dnsresolver_lookup *dnsresolver_lookup, unsigned int events, void *param)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsresolver_lookup->subject.monitor);
        rc = medusa_dnsresolver_lookup_onevent_unlocked(dnsresolver_lookup, events, param);
        medusa_monitor_unlock(dnsresolver_lookup->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_dnsresolver_lookup_get_monitor_unlocked (struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return dnsresolver_lookup->subject.monitor;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_dnsresolver_lookup_get_monitor (struct medusa_dnsresolver_lookup *dnsresolver_lookup)
{
        struct medusa_monitor *rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsresolver_lookup)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(dnsresolver_lookup->subject.monitor);
        rc = medusa_dnsresolver_lookup_get_monitor_unlocked(dnsresolver_lookup);
        medusa_monitor_unlock(dnsresolver_lookup->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsresolver_lookup_event_string (unsigned int events)
{
        if (events == MEDUSA_DNSRESOLVER_LOOKUP_EVENT_STARTED)         return "MEDUSA_DNSRESOLVER_LOOKUP_EVENT_STARTED";
        if (events == MEDUSA_DNSRESOLVER_LOOKUP_EVENT_STOPPED)         return "MEDUSA_DNSRESOLVER_LOOKUP_EVENT_STOPPED";
        if (events == MEDUSA_DNSRESOLVER_LOOKUP_EVENT_ERROR)           return "MEDUSA_DNSRESOLVER_LOOKUP_EVENT_ERROR";
        if (events == MEDUSA_DNSRESOLVER_LOOKUP_EVENT_STATE_CHANGED)   return "MEDUSA_DNSRESOLVER_LOOKUP_EVENT_STATE_CHANGED";
        if (events == MEDUSA_DNSRESOLVER_LOOKUP_EVENT_DESTROY)         return "MEDUSA_DNSRESOLVER_LOOKUP_EVENT_DESTROY";
        return "MEDUSA_DNSRESOLVER_LOOKUP_EVENT_UNKNOWN";
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsresolver_lookup_state_string (unsigned int state)
{
        if (state == MEDUSA_DNSRESOLVER_LOOKUP_STATE_UNKNOWN)          return "MEDUSA_DNSRESOLVER_LOOKUP_STATE_UNKNOWN";
        if (state == MEDUSA_DNSRESOLVER_LOOKUP_STATE_STARTED)          return "MEDUSA_DNSRESOLVER_LOOKUP_STATE_STARTED";
        if (state == MEDUSA_DNSRESOLVER_LOOKUP_STATE_STOPPED)          return "MEDUSA_DNSRESOLVER_LOOKUP_STATE_STOPPED";
        if (state == MEDUSA_DNSRESOLVER_LOOKUP_STATE_ERROR)            return "MEDUSA_DNSRESOLVER_LOOKUP_STATE_ERROR";
        return "MEDUSA_DNSRESOLVER_LOOKUP_STATE_UNKNOWN";
}

__attribute__ ((constructor)) static void dnsresolver_constructor (void)
{
#if defined(MEDUSA_DNSRESOLVER_USE_POOL) && (MEDUSA_DNSRESOLVER_USE_POOL == 1)
        g_pool = medusa_pool_create("medusa-dnsresolver", sizeof(struct medusa_dnsresolver), 0, 0, MEDUSA_POOL_FLAG_DEFAULT | MEDUSA_POOL_FLAG_THREAD_SAFE, NULL, NULL, NULL);
#endif
}

__attribute__ ((destructor)) static void dnsresolver_destructor (void)
{
#if defined(MEDUSA_DNSRESOLVER_USE_POOL) && (MEDUSA_DNSRESOLVER_USE_POOL == 1)
        if (g_pool != NULL) {
                medusa_pool_destroy(g_pool);
        }
#endif
}
