
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "clock.h"
#include "error.h"
#include "pool.h"
#include "queue.h"
#include "monitor.h"
#include "monitor-private.h"
#include "subject-struct.h"
#include "signal-struct.h"
#include "signal-private.h"

#include "signal.h"

#define MEDUSA_SIGNAL_USE_POOL   1
#if defined(MEDUSA_SIGNAL_USE_POOL) && (MEDUSA_SIGNAL_USE_POOL == 1)
static struct medusa_pool *g_pool;
#endif

enum {
        MEDUSA_SIGNAL_FLAG_ENABLED       = 0x00000001,
        MEDUSA_SIGNAL_FLAG_SINGLE_SHOT   = 0x00000002,
        MEDUSA_SIGNAL_FLAG_AUTO_DESTROY  = 0x00000004
#define MEDUSA_SIGNAL_FLAG_ENABLED       MEDUSA_SIGNAL_FLAG_ENABLED
#define MEDUSA_SIGNAL_FLAG_SINGLE_SHOT   MEDUSA_SIGNAL_FLAG_SINGLE_SHOT
#define MEDUSA_SIGNAL_FLAG_AUTO_DESTROY  MEDUSA_SIGNAL_FLAG_AUTO_DESTROY
};

static int signal_set_number (struct medusa_signal *signal, int number)
{
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return -EINVAL;
        }
        if (number < 0) {
                return -EINVAL;
        }
        signal->number = number;
        return 0;
}

static int signal_set_singleshot (struct medusa_signal *signal, int singleshot)
{
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return -EINVAL;
        }
        if (singleshot) {
                signal->flags |= MEDUSA_SIGNAL_FLAG_SINGLE_SHOT;
        } else {
                signal->flags &= ~MEDUSA_SIGNAL_FLAG_SINGLE_SHOT;
        }
        return 0;
}

static int signal_set_enabled (struct medusa_signal *signal, int enabled)
{
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return -EINVAL;
        }
        if (enabled) {
                signal->flags |= MEDUSA_SIGNAL_FLAG_ENABLED;
        } else {
                signal->flags &= ~MEDUSA_SIGNAL_FLAG_ENABLED;
        }
        return 0;
}

static int signal_init_with_options (struct medusa_signal *signal, const struct medusa_signal_init_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return -EINVAL;
        }
        if (options->number <= 0) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                return -EINVAL;
        }
        memset(signal, 0, sizeof(struct medusa_signal));
        signal->onevent = options->onevent;
        signal->context = options->context;
        signal_set_number(signal, options->number);
        signal_set_singleshot(signal, options->singleshot);
        signal_set_enabled(signal, options->enabled);
        signal->subject.flags = MEDUSA_SUBJECT_TYPE_SIGNAL;
        signal->subject.monitor = NULL;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_signal_init_options_default (struct medusa_signal_init_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_signal_init_options));
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_signal_init (struct medusa_signal *signal, struct medusa_monitor *monitor, int (*onevent) (struct medusa_signal *signal, unsigned int events, void *context, ...), void *context)
{
        int rc;
        struct medusa_signal_init_options options;
        rc = medusa_signal_init_options_default(&options);
        if (rc < 0) {
                return rc;
        }
        options.monitor = monitor;
        options.onevent = onevent;
        options.context = context;
        return medusa_signal_init_with_options(signal, &options);
}

__attribute__ ((visibility ("default"))) int medusa_signal_init_with_options (struct medusa_signal *signal, const struct medusa_signal_init_options *options)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        rc = signal_init_with_options(signal, options);
        if (rc < 0) {
                return rc;
        }
        return medusa_monitor_add(options->monitor, &signal->subject);
}

__attribute__ ((visibility ("default"))) void medusa_signal_uninit_unlocked (struct medusa_signal *signal)
{
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return;
        }
        if ((signal->subject.flags & MEDUSA_SUBJECT_TYPE_SIGNAL) == 0) {
                return;
        }
        if (signal->subject.monitor != NULL) {
                medusa_monitor_del_unlocked(&signal->subject);
        } else {
                medusa_signal_onevent_unlocked(signal, MEDUSA_SIGNAL_EVENT_DESTROY);
        }
}

__attribute__ ((visibility ("default"))) void medusa_signal_uninit (struct medusa_signal *signal)
{
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return;
        }
        medusa_monitor_lock(signal->subject.monitor);
        medusa_signal_uninit_unlocked(signal);
        medusa_monitor_unlock(signal->subject.monitor);
}

__attribute__ ((visibility ("default"))) int medusa_signal_create_singleshot (struct medusa_monitor *monitor, int number, int (*onevent) (struct medusa_signal *signal, unsigned int events, void *context, ...), void *context)
{
        int rc;
        struct medusa_signal *signal;
        if (monitor == NULL) {
                return -EINVAL;
        }
        if (number <= 0) {
                return -EINVAL;
        }
        if (onevent == NULL) {
                return -EINVAL;
        }
        signal = medusa_signal_create(monitor, number, onevent, context);
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return -EIO;
        }
        rc = medusa_signal_set_singleshot(signal, 1);
        if (rc < 0) {
                medusa_signal_destroy(signal);
                return rc;
        }
        rc = medusa_signal_set_enabled(signal, 1);
        if (rc < 0) {
                medusa_signal_destroy(signal);
                return rc;
        }
        medusa_monitor_lock(signal->subject.monitor);
        signal->flags |= MEDUSA_SIGNAL_FLAG_AUTO_DESTROY;
        medusa_monitor_unlock(signal->subject.monitor);
        return 0;
}

__attribute__ ((visibility ("default"))) struct medusa_signal * medusa_signal_create (struct medusa_monitor *monitor, int number, int (*onevent) (struct medusa_signal *signal, unsigned int events, void *context, ...), void *context)
{
        int rc;
        struct medusa_signal_init_options options;
        rc = medusa_signal_init_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.monitor = monitor;
        options.number = number;
        options.onevent = onevent;
        options.context = context;
        return medusa_signal_create_with_options(&options);
}

__attribute__ ((visibility ("default"))) struct medusa_signal * medusa_signal_create_with_options (const struct medusa_signal_init_options *options)
{
        int rc;
        struct medusa_signal *signal;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
#if defined(MEDUSA_SIGNAL_USE_POOL) && (MEDUSA_SIGNAL_USE_POOL == 1)
        signal = medusa_pool_malloc(g_pool);
#else
        signal = malloc(sizeof(struct medusa_signal));
#endif
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        rc = signal_init_with_options(signal, options);
        if (rc < 0) {
#if defined(MEDUSA_SIGNAL_USE_POOL) && (MEDUSA_SIGNAL_USE_POOL == 1)
                medusa_pool_free(signal);
#else
                free(signal);
#endif
                return MEDUSA_ERR_PTR(rc);
        }
        signal->subject.flags |= MEDUSA_SUBJECT_FLAG_ALLOC;
        rc = medusa_monitor_add(options->monitor, &signal->subject);
        if (rc < 0) {
                medusa_signal_destroy(signal);
                return MEDUSA_ERR_PTR(rc);
        }
        return signal;
}

__attribute__ ((visibility ("default"))) void medusa_signal_destroy_unlocked (struct medusa_signal *signal)
{
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return;
        }
        medusa_signal_uninit_unlocked(signal);
}

__attribute__ ((visibility ("default"))) void medusa_signal_destroy (struct medusa_signal *signal)
{
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return;
        }
        medusa_monitor_lock(signal->subject.monitor);
        medusa_signal_uninit_unlocked(signal);
        medusa_monitor_unlock(signal->subject.monitor);
}

__attribute__ ((visibility ("default"))) int medusa_signal_get_number_unlocked (const struct medusa_signal *signal)
{
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return -EINVAL;
        }
        return signal->number;
}

__attribute__ ((visibility ("default"))) int medusa_signal_get_number (const struct medusa_signal *signal)
{
        double rc;
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return -EINVAL;
        }
        medusa_monitor_lock(signal->subject.monitor);
        rc = medusa_signal_get_number_unlocked(signal);
        medusa_monitor_unlock(signal->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_signal_set_singleshot_unlocked (struct medusa_signal *signal, int singleshot)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return -EINVAL;
        }
        rc = signal_set_singleshot(signal, singleshot);
        if (rc < 0) {
                return rc;
        }
        return medusa_monitor_mod_unlocked(&signal->subject);
}

__attribute__ ((visibility ("default"))) int medusa_signal_set_singleshot (struct medusa_signal *signal, int singleshot)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return -EINVAL;
        }
        medusa_monitor_lock(signal->subject.monitor);
        rc = medusa_signal_set_singleshot_unlocked(signal, singleshot);
        medusa_monitor_unlock(signal->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_signal_get_singleshot_unlocked (const struct medusa_signal *signal)
{
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return -EINVAL;
        }
        return !!(signal->flags & MEDUSA_SIGNAL_FLAG_SINGLE_SHOT);
}

__attribute__ ((visibility ("default"))) int medusa_signal_get_singleshot (const struct medusa_signal *signal)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return -EINVAL;
        }
        medusa_monitor_lock(signal->subject.monitor);
        rc = medusa_signal_get_singleshot_unlocked(signal);
        medusa_monitor_unlock(signal->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_signal_set_enabled_unlocked (struct medusa_signal *signal, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return -EINVAL;
        }
        rc = signal_set_enabled(signal, enabled);
        if (rc < 0) {
                return rc;
        }
        return medusa_monitor_mod_unlocked(&signal->subject);
}

__attribute__ ((visibility ("default"))) int medusa_signal_set_enabled (struct medusa_signal *signal, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return -EINVAL;
        }
        medusa_monitor_lock(signal->subject.monitor);
        rc = medusa_signal_set_enabled_unlocked(signal, enabled);
        medusa_monitor_unlock(signal->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_signal_get_enabled_unlocked (const struct medusa_signal *signal)
{
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return -EINVAL;
        }
        return !!(signal->flags & MEDUSA_SIGNAL_FLAG_ENABLED);
}

__attribute__ ((visibility ("default"))) int medusa_signal_get_enabled (const struct medusa_signal *signal)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return -EINVAL;
        }
        medusa_monitor_lock(signal->subject.monitor);
        rc = medusa_signal_get_enabled_unlocked(signal);
        medusa_monitor_unlock(signal->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_signal_get_monitor_unlocked (const struct medusa_signal *signal)
{
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return signal->subject.monitor;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_signal_get_monitor (const struct medusa_signal *signal)
{
        struct medusa_monitor *rc;
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(signal->subject.monitor);
        rc = medusa_signal_get_monitor_unlocked(signal);
        medusa_monitor_unlock(signal->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_signal_onevent_unlocked (struct medusa_signal *signal, unsigned int events)
{
        int rc;
        unsigned int type;
        struct medusa_monitor *monitor;
        rc = 0;
        type = signal->subject.flags & MEDUSA_SUBJECT_TYPE_MASK;
        monitor = signal->subject.monitor;
        if (events & MEDUSA_SIGNAL_EVENT_FIRED) {
                if (medusa_signal_get_singleshot_unlocked(signal)) {
                        rc = medusa_signal_set_enabled_unlocked(signal, 0);
                        if (rc < 0) {
                                return rc;
                        }
                }
        }
        if (signal->onevent != NULL) {
                medusa_monitor_unlock(monitor);
                rc = signal->onevent(signal, events, signal->context);
                medusa_monitor_lock(monitor);
        }
        if (events & MEDUSA_SIGNAL_EVENT_FIRED) {
                if (signal->flags & MEDUSA_SIGNAL_FLAG_AUTO_DESTROY) {
                        medusa_signal_destroy_unlocked(signal);
                }
        }
        if (events & MEDUSA_SIGNAL_EVENT_DESTROY) {
                if (type == MEDUSA_SUBJECT_TYPE_SIGNAL) {
                        if (signal->subject.flags & MEDUSA_SUBJECT_FLAG_ALLOC) {
#if defined(MEDUSA_SIGNAL_USE_POOL) && (MEDUSA_SIGNAL_USE_POOL == 1)
                                medusa_pool_free(signal);
#else
                                free(signal);
#endif
                        } else {
                                memset(signal, 0, sizeof(struct medusa_signal));
                        }
                }
        }
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_signal_onevent (struct medusa_signal *signal, unsigned int events)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return -EINVAL;
        }
        medusa_monitor_lock(signal->subject.monitor);
        rc = medusa_signal_onevent_unlocked(signal, events);
        medusa_monitor_unlock(signal->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_signal_is_valid_unlocked (const struct medusa_signal *signal)
{
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                return 0;
        }
        if (signal->number < 0) {
                return 0;
        }
        if ((signal->flags & MEDUSA_SIGNAL_FLAG_ENABLED) == 0) {
                return 0;
        }
        return 1;
}

__attribute__ ((constructor)) static void signal_constructor (void)
{
#if defined(MEDUSA_SIGNAL_USE_POOL) && (MEDUSA_SIGNAL_USE_POOL == 1)
        g_pool = medusa_pool_create("medusa-signal", sizeof(struct medusa_signal), 0, 0, MEDUSA_POOL_FLAG_DEFAULT | MEDUSA_POOL_FLAG_THREAD_SAFE, NULL, NULL, NULL);
#endif
}

__attribute__ ((destructor)) static void signal_destructor (void)
{
#if defined(MEDUSA_SIGNAL_USE_POOL) && (MEDUSA_SIGNAL_USE_POOL == 1)
        if (g_pool != NULL) {
                medusa_pool_destroy(g_pool);
        }
#endif
}
