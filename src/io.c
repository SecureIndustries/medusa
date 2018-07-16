
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "queue.h"
#include "event.h"
#include "subject.h"
#include "monitor.h"

#include "subject-struct.h"
#include "io-struct.h"

#include "io.h"

static int io_subject_event (struct medusa_subject *subject, unsigned int events)
{
        struct medusa_io *io = (struct medusa_io *) subject;
        if (io->callback != NULL) {
                return io->callback(io, events, io->context);
        }
        return 0;
}

static int io_init (struct medusa_monitor *monitor, struct medusa_io *io, void (*destroy) (struct medusa_io *io))
{
        memset(io, 0, sizeof(struct medusa_io));
        io->fd = -1;
        io->events = 0;
        io->enabled = 0;
        io->subject.type = MEDUSA_SUBJECT_TYPE_IO;
        io->subject.event = io_subject_event;
        io->subject.destroy = (void (*) (struct medusa_subject *)) destroy;
        io->subject.flags = MEDUSA_SUBJECT_FLAG_NONE;
        io->subject.monitor = NULL;
        return medusa_subject_add(monitor, &io->subject);
}

static void io_uninit (struct medusa_io *io)
{
        if (io->fd >= 0 &&
            io->close_on_destroy) {
                close(io->fd);
        }
        memset(io, 0, sizeof(struct medusa_io));
}

static void io_destroy (struct medusa_io *io)
{
        io_uninit(io);
        free(io);
}

int medusa_io_init (struct medusa_monitor *monitor, struct medusa_io *io)
{
        return io_init(monitor, io, io_uninit);
}

void medusa_io_uninit (struct medusa_io *io)
{
        medusa_subject_del(&io->subject);
}

struct medusa_io * medusa_io_create (struct medusa_monitor *monitor)
{
        int rc;
        struct medusa_io *io;
        io = NULL;
        if (monitor == NULL) {
                goto bail;
        }
        io = malloc(sizeof(struct medusa_io));
        if (io == NULL) {
                goto bail;
        }
        rc = io_init(monitor, io, io_destroy);
        if (rc != 0) {
                goto bail;
        }
        return io;
bail:   if (io != NULL) {
                medusa_io_destroy(io);
        }
        return NULL;
}

int medusa_io_set_fd (struct medusa_io *io, int fd)
{
        io->fd = fd;
        return medusa_subject_mod(&io->subject);
}

void medusa_io_destroy (struct medusa_io *io)
{
        medusa_subject_del(&io->subject);
}

int medusa_io_get_fd (const struct medusa_io *io)
{
        return io->fd;
}

int medusa_io_set_close_on_destroy (struct medusa_io *io, int close_on_destroy)
{
        io->close_on_destroy = !!close_on_destroy;
        return medusa_subject_mod(&io->subject);
}

int medusa_io_get_close_on_destroy (const struct medusa_io *io)
{
        return io->close_on_destroy;
}

int medusa_io_set_events (struct medusa_io *io, unsigned int events)
{
        io->events = events;
        return medusa_subject_mod(&io->subject);
}

unsigned int medusa_io_get_events (const struct medusa_io *io)
{
        return io->events;
}

int medusa_io_set_callback (struct medusa_io *io, int (*callback) (struct medusa_io *io, unsigned int events, void *context), void *context)
{
        io->callback = callback;
        io->context = context;
        return medusa_subject_mod(&io->subject);
}

int medusa_io_set_enabled (struct medusa_io *io, int enabled)
{
        io->enabled = !!enabled;
        return medusa_subject_mod(&io->subject);
}

int medusa_io_get_enabled (const struct medusa_io *io)
{
        return io->enabled;
}

int medusa_io_is_valid (const struct medusa_io *io)
{
        if (io->fd < 0) {
                return 0;
        }
        if ((io->events & (MEDUSA_EVENT_IN | MEDUSA_EVENT_OUT | MEDUSA_EVENT_PRI)) == 0) {
                return 0;
        }
        if (io->callback == NULL) {
                return 0;
        }
        if (io->enabled == 0) {
                return 0;
        }
        return 1;
}

struct medusa_subject * medusa_io_get_subject (struct medusa_io *io)
{
        return &io->subject;
}

struct medusa_monitor * medusa_io_get_monitor (struct medusa_io *io)
{
        return io->subject.monitor;
}
