
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "pool.h"
#include "queue.h"
#include "subject.h"
#include "monitor.h"

#include "subject-struct.h"
#include "io-struct.h"

#include "io.h"

static struct pool *g_pool;

static int io_subject_event (struct medusa_subject *subject, unsigned int events)
{
        struct medusa_io *io = (struct medusa_io *) subject;
        return io->onevent(io, events, io->context);
}

static int io_init (struct medusa_monitor *monitor, struct medusa_io *io, void (*destroy) (struct medusa_io *io), int fd, int (*onevent) (struct medusa_io *io, unsigned int events, void *context), void *context)
{
        if (monitor == NULL) {
                return -1;
        }
        if (io == NULL) {
                return -1;
        }
        if (destroy == NULL) {
                return -1;
        }
        if (fd < 0) {
                return -1;
        }
        if (onevent == NULL) {
                return -1;
        }
        memset(io, 0, sizeof(struct medusa_io));
        io->fd = fd;
        io->onevent = onevent;
        io->context = context;
        io->events = 0;
        io->enabled = 0;
        io->subject.event = io_subject_event;
        io->subject.destroy = (void (*) (struct medusa_subject *)) destroy;
        io->subject.flags = MEDUSA_SUBJECT_FLAG_IO;
        io->subject.monitor = NULL;
        return medusa_subject_add(monitor, &io->subject);
}

static void io_uninit (struct medusa_io *io)
{
        if (io == NULL) {
                return;
        }
        memset(io, 0, sizeof(struct medusa_io));
}

static void io_destroy (struct medusa_io *io)
{
        if (io == NULL) {
                return;
        }
        io_uninit(io);
#if 1
        pool_free(io);
#else
        free(io);
#endif
}

__attribute__ ((visibility ("default"))) int medusa_io_init (struct medusa_monitor *monitor, struct medusa_io *io, int fd, int (*onevent) (struct medusa_io *io, unsigned int events, void *context), void *context)
{
        if (monitor == NULL) {
                return -1;
        }
        if (io == NULL) {
                return -1;
        }
        if (fd < 0) {
                return -1;
        }
        if (onevent == NULL) {
                return -1;
        }
        return io_init(monitor, io, io_uninit, fd, onevent, context);
}

__attribute__ ((visibility ("default"))) void medusa_io_uninit (struct medusa_io *io)
{
        if (io == NULL) {
                return;
        }
        if ((io->subject.flags & MEDUSA_SUBJECT_FLAG_IO) == 0) {
             return;
        }
        medusa_subject_del(&io->subject);
}

__attribute__ ((visibility ("default"))) struct medusa_io * medusa_io_create (struct medusa_monitor *monitor, int fd, int (*onevent) (struct medusa_io *io, unsigned int events, void *context), void *context)
{
        int rc;
        struct medusa_io *io;
        io = NULL;
        if (monitor == NULL) {
                goto bail;
        }
        if (fd < 0) {
                goto bail;
        }
        if (onevent == NULL) {
                goto bail;
        }
#if 1
        io = pool_malloc(g_pool);
#else
        io = malloc(sizeof(struct medusa_io));
#endif
        if (io == NULL) {
                goto bail;
        }
        rc = io_init(monitor, io, io_destroy, fd, onevent, context);
        if (rc != 0) {
                goto bail;
        }
        return io;
bail:   if (io != NULL) {
                medusa_io_destroy(io);
        }
        return NULL;
}

__attribute__ ((visibility ("default"))) void medusa_io_destroy (struct medusa_io *io)
{
        if (io == NULL) {
                return;
        }
        medusa_subject_del(&io->subject);
}

__attribute__ ((visibility ("default"))) int medusa_io_get_fd (const struct medusa_io *io)
{
        if (io == NULL) {
                return -1;
        }
        return io->fd;
}

__attribute__ ((visibility ("default"))) int medusa_io_set_events (struct medusa_io *io, unsigned int events)
{
        if (io == NULL) {
                return -1;
        }
        io->events = events;
        return medusa_subject_mod(&io->subject);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_io_get_events (const struct medusa_io *io)
{
        if (io == NULL) {
                return 0;
        }
        return io->events;
}

__attribute__ ((visibility ("default"))) int medusa_io_set_enabled (struct medusa_io *io, int enabled)
{
        if (io == NULL) {
                return -1;
        }
        io->enabled = !!enabled;
        return medusa_subject_mod(&io->subject);
}

__attribute__ ((visibility ("default"))) int medusa_io_get_enabled (const struct medusa_io *io)
{
        if (io == NULL) {
                return 0;
        }
        return io->enabled;
}

__attribute__ ((visibility ("default"))) int medusa_io_is_valid (const struct medusa_io *io)
{
        if ((io->events & (MEDUSA_IO_EVENT_IN | MEDUSA_IO_EVENT_OUT | MEDUSA_IO_EVENT_PRI)) == 0) {
                return 0;
        }
        if (io->enabled == 0) {
                return 0;
        }
        return 1;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_io_get_monitor (struct medusa_io *io)
{
        if (io == NULL) {
                return NULL;
        }
        return io->subject.monitor;
}

__attribute__ ((constructor)) static void io_constructor (void)
{
        g_pool = pool_create("medusa-io", sizeof(struct medusa_io), 0, 0, POOL_FLAG_DEFAULT, NULL, NULL, NULL);
}

__attribute__ ((destructor)) static void io_destructor (void)
{
        if (g_pool != NULL) {
                pool_destroy(g_pool);
        }
}
