
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
#include "io-struct.h"
#include "io-private.h"

#include "io.h"

#define MEDUSA_IO_EVENT_MASK              0xff
#define MEDUSA_IO_EVENT_SHIFT             0x00

#define MEDUSA_IO_ENABLE_MASK             0xff
#define MEDUSA_IO_ENABLE_SHIFT            0x18

#define MEDUSA_IO_USE_POOL      1
#if defined(MEDUSA_IO_USE_POOL) && (MEDUSA_IO_USE_POOL == 1)
static struct medusa_pool *g_pool;
#endif

static inline void io_set_events (struct medusa_io *io, unsigned int events)
{
        io->flags = (io->flags & ~(MEDUSA_IO_EVENT_MASK << MEDUSA_IO_EVENT_SHIFT)) |
                    ((events & MEDUSA_IO_EVENT_MASK) << MEDUSA_IO_EVENT_SHIFT);
}

static inline void io_add_events (struct medusa_io *io, unsigned int events)
{
        io->flags |= ((events & MEDUSA_IO_EVENT_MASK) << MEDUSA_IO_EVENT_SHIFT);
}

static inline void io_del_events (struct medusa_io *io, unsigned int events)
{
        io->flags &= ~((events & MEDUSA_IO_EVENT_MASK) << MEDUSA_IO_EVENT_SHIFT);
}

static inline unsigned int io_get_events (const struct medusa_io *io)
{
        return (io->flags >> MEDUSA_IO_EVENT_SHIFT) & MEDUSA_IO_EVENT_MASK;
}

static inline unsigned int io_get_enabled (const struct medusa_io *io)
{
        return (io->flags >> MEDUSA_IO_ENABLE_SHIFT) & MEDUSA_IO_ENABLE_MASK;
}

static inline void io_set_enabled (struct medusa_io *io, unsigned int enabled)
{
        io->flags = (io->flags & ~(MEDUSA_IO_ENABLE_MASK << MEDUSA_IO_ENABLE_SHIFT)) |
                    ((enabled & MEDUSA_IO_ENABLE_MASK) << MEDUSA_IO_ENABLE_SHIFT);
}

static int io_init_with_options (struct medusa_io *io, const struct medusa_io_init_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return -EINVAL;
        }
        if (options->fd < 0) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                return -EINVAL;
        }
        memset(io, 0, sizeof(struct medusa_io));
        io->fd = options->fd;
        io->onevent = options->onevent;
        io->context = options->context;
        io_set_events(io, options->events);
        io_set_enabled(io, options->enabled);
        io->subject.flags = MEDUSA_SUBJECT_TYPE_IO;
        io->subject.monitor = NULL;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_io_init_options_default (struct medusa_io_init_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_io_init_options));
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_io_init (struct medusa_io *io, struct medusa_monitor *monitor, int fd, int (*onevent) (struct medusa_io *io, unsigned int events, void *context, ...), void *context)
{
        int rc;
        struct medusa_io_init_options options;
        rc = medusa_io_init_options_default(&options);
        if (rc < 0) {
                return rc;
        }
        options.monitor = monitor;
        options.fd = fd;
        options.onevent = onevent;
        options.context = context;
        return medusa_io_init_with_options(io, &options);
}

__attribute__ ((visibility ("default"))) int medusa_io_init_with_options (struct medusa_io *io, const struct medusa_io_init_options *options)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        rc = io_init_with_options(io, options);
        if (rc < 0) {
                return rc;
        }
        return medusa_monitor_add(options->monitor, &io->subject);
}

__attribute__ ((visibility ("default"))) void medusa_io_uninit_unlocked (struct medusa_io *io)
{
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return;
        }
        if ((io->subject.flags & MEDUSA_SUBJECT_TYPE_IO) == 0) {
                return;
        }
        if (io->subject.monitor != NULL) {
                medusa_monitor_del_unlocked(&io->subject);
        } else {
                medusa_io_onevent_unlocked(io, MEDUSA_IO_EVENT_DESTROY);
        }
}

__attribute__ ((visibility ("default"))) void medusa_io_uninit (struct medusa_io *io)
{
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return;
        }
        medusa_monitor_lock(io->subject.monitor);
        medusa_io_uninit_unlocked(io);
        medusa_monitor_unlock(io->subject.monitor);
}

__attribute__ ((visibility ("default"))) struct medusa_io * medusa_io_create (struct medusa_monitor *monitor, int fd, int (*onevent) (struct medusa_io *io, unsigned int events, void *context, ...), void *context)
{
        int rc;
        struct medusa_io_init_options options;
        rc = medusa_io_init_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.monitor = monitor;
        options.fd = fd;
        options.onevent = onevent;
        options.context = context;
        return medusa_io_create_with_options(&options);
}

__attribute__ ((visibility ("default"))) struct medusa_io * medusa_io_create_with_options (const struct medusa_io_init_options *options)
{
        int rc;
        struct medusa_io *io;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
#if defined(MEDUSA_IO_USE_POOL) && (MEDUSA_IO_USE_POOL == 1)
        io = medusa_pool_malloc(g_pool);
#else
        io = malloc(sizeof(struct medusa_io));
#endif
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        rc = io_init_with_options(io, options);
        if (rc < 0) {
#if defined(MEDUSA_IO_USE_POOL) && (MEDUSA_IO_USE_POOL == 1)
                medusa_pool_free(io);
#else
                free(io);
#endif
                return MEDUSA_ERR_PTR(rc);
        }
        io->subject.flags |= MEDUSA_SUBJECT_FLAG_ALLOC;
        rc = medusa_monitor_add(options->monitor, &io->subject);
        if (rc < 0) {
                medusa_io_destroy(io);
                return MEDUSA_ERR_PTR(rc);
        }
        return io;
}

__attribute__ ((visibility ("default"))) void medusa_io_destroy_unlocked (struct medusa_io *io)
{
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return;
        }
        medusa_io_uninit_unlocked(io);
}

__attribute__ ((visibility ("default"))) void medusa_io_destroy (struct medusa_io *io)
{
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return;
        }
        medusa_monitor_lock(io->subject.monitor);
        medusa_io_uninit_unlocked(io);
        medusa_monitor_unlock(io->subject.monitor);
}

__attribute__ ((visibility ("default"))) int medusa_io_get_fd_unlocked (const struct medusa_io *io)
{
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return -EINVAL;
        }
        return io->fd;
}

__attribute__ ((visibility ("default"))) int medusa_io_get_fd (const struct medusa_io *io)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return -EINVAL;
        }
        medusa_monitor_lock(io->subject.monitor);
        rc = medusa_io_get_fd_unlocked(io);
        medusa_monitor_unlock(io->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_io_set_events_unlocked (struct medusa_io *io, unsigned int events)
{
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return -EINVAL;
        }
        io_set_events(io, events & (MEDUSA_IO_EVENT_IN | MEDUSA_IO_EVENT_OUT | MEDUSA_IO_EVENT_PRI));
        return medusa_monitor_mod_unlocked(&io->subject);
}

__attribute__ ((visibility ("default"))) int medusa_io_set_events (struct medusa_io *io, unsigned int events)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return -EINVAL;
        }
        medusa_monitor_lock(io->subject.monitor);
        rc = medusa_io_set_events_unlocked(io, events);
        medusa_monitor_unlock(io->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_io_add_events_unlocked (struct medusa_io *io, unsigned int events)
{
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return -EINVAL;
        }
        io_add_events(io, events & (MEDUSA_IO_EVENT_IN | MEDUSA_IO_EVENT_OUT | MEDUSA_IO_EVENT_PRI));
        return medusa_monitor_mod_unlocked(&io->subject);
}

__attribute__ ((visibility ("default"))) int medusa_io_add_events (struct medusa_io *io, unsigned int events)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return -EINVAL;
        }
        medusa_monitor_lock(io->subject.monitor);
        rc = medusa_io_add_events_unlocked(io, events);
        medusa_monitor_unlock(io->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_io_del_events_unlocked (struct medusa_io *io, unsigned int events)
{
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return -EINVAL;
        }
        io_del_events(io, events & (MEDUSA_IO_EVENT_IN | MEDUSA_IO_EVENT_OUT | MEDUSA_IO_EVENT_PRI));
        return medusa_monitor_mod_unlocked(&io->subject);
}

__attribute__ ((visibility ("default"))) int medusa_io_del_events (struct medusa_io *io, unsigned int events)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return -EINVAL;
        }
        medusa_monitor_lock(io->subject.monitor);
        rc = medusa_io_del_events_unlocked(io, events);
        medusa_monitor_unlock(io->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) unsigned int medusa_io_get_events_unlocked (const struct medusa_io *io)
{
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return 0;
        }
        return io_get_events(io);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_io_get_events (const struct medusa_io *io)
{
        unsigned int rc;
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return -EINVAL;
        }
        medusa_monitor_lock(io->subject.monitor);
        rc = medusa_io_get_events_unlocked(io);
        medusa_monitor_unlock(io->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_io_set_enabled_unlocked (struct medusa_io *io, int enabled)
{
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return -EINVAL;
        }
        io_set_enabled(io, !!enabled);
        return medusa_monitor_mod_unlocked(&io->subject);
}

__attribute__ ((visibility ("default"))) int medusa_io_set_enabled (struct medusa_io *io, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return -EINVAL;
        }
        medusa_monitor_lock(io->subject.monitor);
        rc = medusa_io_set_enabled_unlocked(io, enabled);
        medusa_monitor_unlock(io->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_io_get_enabled_unlocked (const struct medusa_io *io)
{
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return -EINVAL;
        }
        return io_get_enabled(io);
}

__attribute__ ((visibility ("default"))) int medusa_io_get_enabled (const struct medusa_io *io)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return -EINVAL;
        }
        medusa_monitor_lock(io->subject.monitor);
        rc = medusa_io_get_enabled_unlocked(io);
        medusa_monitor_unlock(io->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_io_get_monitor_unlocked (const struct medusa_io *io)
{
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return io->subject.monitor;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_io_get_monitor (const struct medusa_io *io)
{
        struct medusa_monitor *rc;
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(io->subject.monitor);
        rc = medusa_io_get_monitor_unlocked(io);
        medusa_monitor_unlock(io->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_io_onevent_unlocked (struct medusa_io *io, unsigned int events)
{
        int rc;
        unsigned int type;
        struct medusa_monitor *monitor;
        rc = 0;
        type = io->subject.flags & MEDUSA_SUBJECT_TYPE_MASK;
        monitor = io->subject.monitor;
        if (io->onevent != NULL) {
                medusa_monitor_unlock(monitor);
                rc = io->onevent(io, events, io->context);
                medusa_monitor_lock(monitor);
        }
        if (events & MEDUSA_IO_EVENT_DESTROY) {
                if (type == MEDUSA_SUBJECT_TYPE_IO) {
                        if (io->subject.flags & MEDUSA_SUBJECT_FLAG_ALLOC) {
#if defined(MEDUSA_IO_USE_POOL) && (MEDUSA_IO_USE_POOL == 1)
                                medusa_pool_free(io);
#else
                                free(io);
#endif
                        } else {
                                memset(io, 0, sizeof(struct medusa_io));
                        }
                }
        }
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_io_onevent (struct medusa_io *io, unsigned int events)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return -EINVAL;
        }
        medusa_monitor_lock(io->subject.monitor);
        rc = medusa_io_onevent_unlocked(io, events);
        medusa_monitor_unlock(io->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_io_is_valid_unlocked (const struct medusa_io *io)
{
        if (io->fd < 0) {
                return 0;
        }
        if (io->onevent == NULL) {
                return 0;
        }
        if ((io_get_events(io) & (MEDUSA_IO_EVENT_IN | MEDUSA_IO_EVENT_OUT | MEDUSA_IO_EVENT_PRI)) == 0) {
                return 0;
        }
        if (io_get_enabled(io) == 0) {
                return 0;
        }
        return 1;
}

__attribute__ ((constructor)) static void io_constructor (void)
{
#if defined(MEDUSA_IO_USE_POOL) && (MEDUSA_IO_USE_POOL == 1)
        g_pool = medusa_pool_create("medusa-io", sizeof(struct medusa_io), 0, 0, MEDUSA_POOL_FLAG_DEFAULT | MEDUSA_POOL_FLAG_THREAD_SAFE, NULL, NULL, NULL);
#endif
}

__attribute__ ((destructor)) static void io_destructor (void)
{
#if defined(MEDUSA_IO_USE_POOL) && (MEDUSA_IO_USE_POOL == 1)
        if (g_pool != NULL) {
                medusa_pool_destroy(g_pool);
        }
#endif
}
