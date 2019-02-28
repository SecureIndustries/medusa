
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <pthread.h>

#include "error.h"
#include "pool.h"
#include "queue.h"
#include "monitor.h"
#include "monitor-private.h"

#include "subject-struct.h"
#include "exec-struct.h"
#include "exec-private.h"

#include "exec.h"

#define MEDUSA_EXEC_EVENT_MASK            0xff
#define MEDUSA_EXEC_EVENT_SHIFT           0x00

#define MEDUSA_EXEC_ENABLE_MASK           0xff
#define MEDUSA_EXEC_ENABLE_SHIFT          0x18

#define MEDUSA_EXEC_USE_POOL              1
#if defined(MEDUSA_EXEC_USE_POOL) && (MEDUSA_EXEC_USE_POOL == 1)
static struct medusa_pool *g_pool;
#endif

static inline void exec_set_events (struct medusa_exec *exec, unsigned int events)
{
        exec->flags = (exec->flags & ~(MEDUSA_EXEC_EVENT_MASK << MEDUSA_EXEC_EVENT_SHIFT)) |
                    ((events & MEDUSA_EXEC_EVENT_MASK) << MEDUSA_EXEC_EVENT_SHIFT);
}

static inline void exec_add_events (struct medusa_exec *exec, unsigned int events)
{
        exec->flags |= ((events & MEDUSA_EXEC_EVENT_MASK) << MEDUSA_EXEC_EVENT_SHIFT);
}

static inline void exec_del_events (struct medusa_exec *exec, unsigned int events)
{
        exec->flags &= ~((events & MEDUSA_EXEC_EVENT_MASK) << MEDUSA_EXEC_EVENT_SHIFT);
}

static inline unsigned int exec_get_events (const struct medusa_exec *exec)
{
        return (exec->flags >> MEDUSA_EXEC_EVENT_SHIFT) & MEDUSA_EXEC_EVENT_MASK;
}

static inline unsigned int exec_get_enabled (const struct medusa_exec *exec)
{
        return (exec->flags >> MEDUSA_EXEC_ENABLE_SHIFT) & MEDUSA_EXEC_ENABLE_MASK;
}

static inline void exec_set_enabled (struct medusa_exec *exec, unsigned int enabled)
{
        exec->flags = (exec->flags & ~(MEDUSA_EXEC_ENABLE_MASK << MEDUSA_EXEC_ENABLE_SHIFT)) |
                    ((enabled & MEDUSA_EXEC_ENABLE_MASK) << MEDUSA_EXEC_ENABLE_SHIFT);
}

__attribute__ ((visibility ("default"))) int medusa_exec_init_options_default (struct medusa_exec_init_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_exec_init_options));
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_exec_init_unlocked (struct medusa_exec *exec, struct medusa_monitor *monitor, const char *argv[], int (*onevent) (struct medusa_exec *exec, unsigned int events, void *context, ...), void *context)
{
        int rc;
        struct medusa_exec_init_options options;
        rc = medusa_exec_init_options_default(&options);
        if (rc < 0) {
                return rc;
        }
        options.monitor = monitor;
        options.argv = argv;
        options.onevent = onevent;
        options.context = context;
        return medusa_exec_init_with_options_unlocked(exec, &options);
}

__attribute__ ((visibility ("default"))) int medusa_exec_init (struct medusa_exec *exec, struct medusa_monitor *monitor, const char *argv[], int (*onevent) (struct medusa_exec *exec, unsigned int events, void *context, ...), void *context)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(exec)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return -EINVAL;
        }
        medusa_monitor_lock(monitor);
        rc = medusa_exec_init_unlocked(exec, monitor, argv, onevent, context);
        medusa_monitor_unlock(monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_exec_init_with_options_unlocked (struct medusa_exec *exec, const struct medusa_exec_init_options *options)
{
        int argc;
        if (MEDUSA_IS_ERR_OR_NULL(exec)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return -EINVAL;
        }
        if (options->argv == NULL) {
                return -EINVAL;
        }
        for (argc = 0; options->argv[argc] != NULL; argc++) {
                ;
        }
        if (argc < 1) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                return -EINVAL;
        }
        memset(exec, 0, sizeof(struct medusa_exec));
        exec->pid = -1;
        exec->argv = malloc(sizeof(char *) * (argc + 1));
        if (exec->argv == NULL) {
                return -ENOMEM;
        }
        memset(exec->argv, 0, sizeof(char *) * (argc + 1));
        for (argc = 0; options->argv[argc] != NULL; argc++) {
                exec->argv[argc] = strdup(options->argv[argc]);
                if (exec->argv[argc] == NULL) {
                        for (argc = 0; options->argv[argc] != NULL; argc++) {
                                free(exec->argv[argc]);
                        }
                        free(exec->argv);
                        return -ENOMEM;
                }
        }
        exec->argv[argc++] = NULL;
        exec->onevent = options->onevent;
        exec->context = options->context;
        exec_set_events(exec, options->events);
        exec_set_enabled(exec, options->enabled);
        medusa_subject_set_type(&exec->subject, MEDUSA_SUBJECT_TYPE_EXEC);
        exec->subject.monitor = NULL;
        return medusa_monitor_add_unlocked(options->monitor, &exec->subject);
}

__attribute__ ((visibility ("default"))) int medusa_exec_init_with_options (struct medusa_exec *exec, const struct medusa_exec_init_options *options)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(exec)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return -EINVAL;
        }
        medusa_monitor_lock(options->monitor);
        rc = medusa_exec_init_with_options_unlocked(exec, options);
        medusa_monitor_unlock(options->monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void medusa_exec_uninit_unlocked (struct medusa_exec *exec)
{
        if (MEDUSA_IS_ERR_OR_NULL(exec)) {
                return;
        }
        if (exec->subject.monitor != NULL) {
                medusa_monitor_del_unlocked(&exec->subject);
        } else {
                medusa_exec_onevent_unlocked(exec, MEDUSA_EXEC_EVENT_DESTROY);
        }
}

__attribute__ ((visibility ("default"))) void medusa_exec_uninit (struct medusa_exec *exec)
{
        if (MEDUSA_IS_ERR_OR_NULL(exec)) {
                return;
        }
        medusa_monitor_lock(exec->subject.monitor);
        medusa_exec_uninit_unlocked(exec);
        medusa_monitor_unlock(exec->subject.monitor);
}

__attribute__ ((visibility ("default"))) struct medusa_exec * medusa_exec_create_unlocked (struct medusa_monitor *monitor, const char *argv[], int (*onevent) (struct medusa_exec *exec, unsigned int events, void *context, ...), void *context)
{
        int rc;
        struct medusa_exec_init_options options;
        rc = medusa_exec_init_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.monitor = monitor;
        options.argv = argv;
        options.onevent = onevent;
        options.context = context;
        return medusa_exec_create_with_options_unlocked(&options);
}

__attribute__ ((visibility ("default"))) struct medusa_exec * medusa_exec_create (struct medusa_monitor *monitor, const char *argv[], int (*onevent) (struct medusa_exec *exec, unsigned int events, void *context, ...), void *context)
{
        struct medusa_exec *rc;
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(monitor);
        rc = medusa_exec_create_unlocked(monitor, argv, onevent, context);
        medusa_monitor_unlock(monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_exec * medusa_exec_create_with_options_unlocked (const struct medusa_exec_init_options *options)
{
        int rc;
        struct medusa_exec *exec;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
#if defined(MEDUSA_EXEC_USE_POOL) && (MEDUSA_EXEC_USE_POOL == 1)
        exec = medusa_pool_malloc(g_pool);
#else
        exec = malloc(sizeof(struct medusa_exec));
#endif
        if (MEDUSA_IS_ERR_OR_NULL(exec)) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(exec, 0, sizeof(struct medusa_exec));
        rc = medusa_exec_init_with_options_unlocked(exec, options);
        if (rc < 0) {
                medusa_exec_destroy_unlocked(exec);
                return MEDUSA_ERR_PTR(rc);
        }
        exec->subject.flags |= MEDUSA_SUBJECT_FLAG_ALLOC;
        return exec;
}

__attribute__ ((visibility ("default"))) struct medusa_exec * medusa_exec_create_with_options (const struct medusa_exec_init_options *options)
{
        struct medusa_exec *rc;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(options->monitor);
        rc = medusa_exec_create_with_options_unlocked(options);
        medusa_monitor_unlock(options->monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void medusa_exec_destroy_unlocked (struct medusa_exec *exec)
{
        if (MEDUSA_IS_ERR_OR_NULL(exec)) {
                return;
        }
        medusa_exec_uninit_unlocked(exec);
}

__attribute__ ((visibility ("default"))) void medusa_exec_destroy (struct medusa_exec *exec)
{
        if (MEDUSA_IS_ERR_OR_NULL(exec)) {
                return;
        }
        medusa_monitor_lock(exec->subject.monitor);
        medusa_exec_uninit_unlocked(exec);
        medusa_monitor_unlock(exec->subject.monitor);
}

__attribute__ ((visibility ("default"))) int medusa_exec_get_pid_unlocked (const struct medusa_exec *exec)
{
        if (MEDUSA_IS_ERR_OR_NULL(exec)) {
                return -EINVAL;
        }
        return exec->pid;
}

__attribute__ ((visibility ("default"))) int medusa_exec_get_pid (const struct medusa_exec *exec)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(exec)) {
                return -EINVAL;
        }
        medusa_monitor_lock(exec->subject.monitor);
        rc = medusa_exec_get_pid_unlocked(exec);
        medusa_monitor_unlock(exec->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_exec_set_enabled_unlocked (struct medusa_exec *exec, int enabled)
{
        if (MEDUSA_IS_ERR_OR_NULL(exec)) {
                return -EINVAL;
        }
        exec_set_enabled(exec, !!enabled);
        return medusa_monitor_mod_unlocked(&exec->subject);
}

__attribute__ ((visibility ("default"))) int medusa_exec_set_enabled (struct medusa_exec *exec, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(exec)) {
                return -EINVAL;
        }
        medusa_monitor_lock(exec->subject.monitor);
        rc = medusa_exec_set_enabled_unlocked(exec, enabled);
        medusa_monitor_unlock(exec->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_exec_get_enabled_unlocked (const struct medusa_exec *exec)
{
        if (MEDUSA_IS_ERR_OR_NULL(exec)) {
                return -EINVAL;
        }
        return exec_get_enabled(exec);
}

__attribute__ ((visibility ("default"))) int medusa_exec_get_enabled (const struct medusa_exec *exec)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(exec)) {
                return -EINVAL;
        }
        medusa_monitor_lock(exec->subject.monitor);
        rc = medusa_exec_get_enabled_unlocked(exec);
        medusa_monitor_unlock(exec->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_exec_enable (struct medusa_exec *exec)
{
        return medusa_exec_set_enabled(exec, 1);
}

__attribute__ ((visibility ("default"))) int medusa_exec_disable (struct medusa_exec *exec)
{
        return medusa_exec_set_enabled(exec, 0);
}

__attribute__ ((visibility ("default"))) int medusa_exec_start (struct medusa_exec *exec)
{
        return medusa_exec_set_enabled(exec, 1);
}

__attribute__ ((visibility ("default"))) int medusa_exec_stop (struct medusa_exec *exec)
{
        return medusa_exec_set_enabled(exec, 0);
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_exec_get_monitor_unlocked (const struct medusa_exec *exec)
{
        if (MEDUSA_IS_ERR_OR_NULL(exec)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return exec->subject.monitor;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_exec_get_monitor (const struct medusa_exec *exec)
{
        struct medusa_monitor *rc;
        if (MEDUSA_IS_ERR_OR_NULL(exec)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(exec->subject.monitor);
        rc = medusa_exec_get_monitor_unlocked(exec);
        medusa_monitor_unlock(exec->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_exec_onevent_unlocked (struct medusa_exec *exec, unsigned int events)
{
        int rc;
        struct medusa_monitor *monitor;
        rc = 0;
        monitor = exec->subject.monitor;
        if (exec->onevent != NULL) {
                medusa_monitor_unlock(monitor);
                rc = exec->onevent(exec, events, exec->context);
                medusa_monitor_lock(monitor);
        }
        if (events & MEDUSA_EXEC_EVENT_DESTROY) {
                if (exec->argv != NULL) {
                        char **ptr;
                        for (ptr = exec->argv; ptr && *ptr; ptr++) {
                                free(*ptr);
                        }
                        free(exec->argv);
                }
                if (exec->subject.flags & MEDUSA_SUBJECT_FLAG_ALLOC) {
#if defined(MEDUSA_EXEC_USE_POOL) && (MEDUSA_EXEC_USE_POOL == 1)
                        medusa_pool_free(exec);
#else
                        free(exec);
#endif
                } else {
                        memset(exec, 0, sizeof(struct medusa_exec));
                }
        }
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_exec_onevent (struct medusa_exec *exec, unsigned int events)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(exec)) {
                return -EINVAL;
        }
        medusa_monitor_lock(exec->subject.monitor);
        rc = medusa_exec_onevent_unlocked(exec, events);
        medusa_monitor_unlock(exec->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_exec_is_valid_unlocked (const struct medusa_exec *exec)
{
        if (exec->pid < 0) {
                return 0;
        }
        if (exec->onevent == NULL) {
                return 0;
        }
        if (exec_get_enabled(exec) == 0) {
                return 0;
        }
        return 1;
}

__attribute__ ((constructor)) static void exec_constructor (void)
{
#if defined(MEDUSA_EXEC_USE_POOL) && (MEDUSA_EXEC_USE_POOL == 1)
        g_pool = medusa_pool_create("medusa-exec", sizeof(struct medusa_exec), 0, 0, MEDUSA_POOL_FLAG_DEFAULT | MEDUSA_POOL_FLAG_THREAD_SAFE, NULL, NULL, NULL);
#endif
}

__attribute__ ((destructor)) static void exec_destructor (void)
{
#if defined(MEDUSA_EXEC_USE_POOL) && (MEDUSA_EXEC_USE_POOL == 1)
        if (g_pool != NULL) {
                medusa_pool_destroy(g_pool);
        }
#endif
}
