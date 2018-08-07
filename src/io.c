
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "error.h"
#include "pool.h"
#include "queue.h"
#include "monitor.h"
#include "monitor-private.h"

#include "subject-struct.h"
#include "io-struct.h"
#include "io-private.h"

#include "io.h"

#define MEDUSA_IO_USE_POOL      1
#if defined(MEDUSA_IO_USE_POOL) && (MEDUSA_IO_USE_POOL == 1)
static struct medusa_pool *g_pool;
#endif

__attribute__ ((visibility ("default"))) int medusa_io_init (struct medusa_monitor *monitor, struct medusa_io *io, int fd, int (*onevent) (struct medusa_io *io, unsigned int events, void *context), void *context)
{
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return -EINVAL;
        }
        if (fd < 0) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(onevent)) {
                return -EINVAL;
        }
        memset(io, 0, sizeof(struct medusa_io));
        io->fd = fd;
        io->onevent = onevent;
        io->context = context;
        io->events = 0;
        io->enabled = 0;
        io->subject.flags = MEDUSA_SUBJECT_FLAG_IO;
        io->subject.monitor = NULL;
        return medusa_monitor_add(monitor, &io->subject);
}

__attribute__ ((visibility ("default"))) void medusa_io_uninit (struct medusa_io *io)
{
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return;
        }
        if ((io->subject.flags & MEDUSA_SUBJECT_FLAG_IO) == 0) {
                return;
        }
        if (io->subject.monitor != NULL) {
                medusa_monitor_del(&io->subject);
        } else {
                medusa_io_onevent(io, MEDUSA_IO_EVENT_DESTROY);
        }
}

__attribute__ ((visibility ("default"))) struct medusa_io * medusa_io_create (struct medusa_monitor *monitor, int fd, int (*onevent) (struct medusa_io *io, unsigned int events, void *context), void *context)
{
        int rc;
        struct medusa_io *io;
        io = NULL;
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (fd < 0) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(onevent)) {
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
        rc = medusa_io_init(monitor, io, fd, onevent, context);
        if (rc < 0) {
                medusa_io_destroy(io);
                return MEDUSA_ERR_PTR(rc);
        }
        io->subject.flags |= MEDUSA_SUBJECT_FLAG_ALLOC;
        return io;
}

__attribute__ ((visibility ("default"))) void medusa_io_destroy (struct medusa_io *io)
{
        medusa_io_uninit(io);
}

__attribute__ ((visibility ("default"))) int medusa_io_get_fd (const struct medusa_io *io)
{
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return -EINVAL;
        }
        return io->fd;
}

__attribute__ ((visibility ("default"))) int medusa_io_set_events (struct medusa_io *io, unsigned int events)
{
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return -EINVAL;
        }
        io->events = (events & (MEDUSA_IO_EVENT_IN | MEDUSA_IO_EVENT_OUT | MEDUSA_IO_EVENT_PRI));
        return medusa_monitor_mod(&io->subject);
}

__attribute__ ((visibility ("default"))) int medusa_io_add_events (struct medusa_io *io, unsigned int events)
{
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return -EINVAL;
        }
        io->events |= (events & (MEDUSA_IO_EVENT_IN | MEDUSA_IO_EVENT_OUT | MEDUSA_IO_EVENT_PRI));
        return medusa_monitor_mod(&io->subject);
}

__attribute__ ((visibility ("default"))) int medusa_io_del_events (struct medusa_io *io, unsigned int events)
{
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return -EINVAL;
        }
        io->events &= ~(events & (MEDUSA_IO_EVENT_IN | MEDUSA_IO_EVENT_OUT | MEDUSA_IO_EVENT_PRI));
        return medusa_monitor_mod(&io->subject);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_io_get_events (const struct medusa_io *io)
{
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return 0;
        }
        return io->events;
}

__attribute__ ((visibility ("default"))) int medusa_io_set_enabled (struct medusa_io *io, int enabled)
{
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return -EINVAL;
        }
        io->enabled = !!enabled;
        return medusa_monitor_mod(&io->subject);
}

__attribute__ ((visibility ("default"))) int medusa_io_get_enabled (const struct medusa_io *io)
{
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return -EINVAL;
        }
        return io->enabled;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_io_get_monitor (struct medusa_io *io)
{
        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return io->subject.monitor;
}

int medusa_io_onevent (struct medusa_io *io, unsigned int events)
{
        int rc;
        rc = 0;
        if (io->onevent != NULL) {
                rc = io->onevent(io, events, io->context);
        }
        if ((rc != 1) &&
            (events & MEDUSA_IO_EVENT_DESTROY)) {
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
        return rc;
}

int medusa_io_is_valid (const struct medusa_io *io)
{
        if (io->fd < 0) {
                return 0;
        }
        if (io->onevent == NULL) {
                return 0;
        }
        if ((io->events & (MEDUSA_IO_EVENT_IN | MEDUSA_IO_EVENT_OUT | MEDUSA_IO_EVENT_PRI)) == 0) {
                return 0;
        }
        if (io->enabled == 0) {
                return 0;
        }
        return 1;
}

__attribute__ ((constructor)) static void io_constructor (void)
{
#if defined(MEDUSA_IO_USE_POOL) && (MEDUSA_IO_USE_POOL == 1)
        g_pool = medusa_pool_create("medusa-io", sizeof(struct medusa_io), 0, 0, MEDUSA_POOL_FLAG_DEFAULT, NULL, NULL, NULL);
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
