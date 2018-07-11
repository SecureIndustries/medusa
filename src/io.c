
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "queue.h"
#include "event.h"
#include "subject.h"

#include "subject-struct.h"
#include "io-struct.h"

#include "io.h"

static int io_subject_event (struct medusa_subject *subject, unsigned int events)
{
        struct medusa_io *io = (struct medusa_io *) subject;
        if (io->activated != NULL) {
                io->activated(io, events);
        }
        return 0;
}

static int io_init (struct medusa_io *io, void (*destroy) (struct medusa_io *io))
{
        memset(io, 0, sizeof(struct medusa_io));
        io->fd = -1;
        io->events = 0;
        io->enabled = 0;
        return medusa_subject_set(&io->subject, MEDUSA_SUBJECT_TYPE_IO, io_subject_event, (void (*) (struct medusa_subject *)) destroy, NULL);
}

static void io_uninit (struct medusa_io *io)
{
        medusa_subject_del(&io->subject);
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

int medusa_io_init (struct medusa_io *io)
{
        return io_init(io, io_uninit);
}

struct medusa_io * medusa_io_create (void)
{
        int rc;
        struct medusa_io *io;
        io = malloc(sizeof(struct medusa_io));
        if (io == NULL) {
                goto bail;
        }
        rc = io_init(io, io_destroy);
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
        medusa_subject_destroy(&io->subject);
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

int medusa_io_set_activated_callback (struct medusa_io *io, void (*activated) (struct medusa_io *io, unsigned int events), void *context)
{
        io->activated = activated;
        io->context = context;
        return medusa_subject_mod(&io->subject);
}

void * medusa_io_get_activated_context (const struct medusa_io *io)
{
        return io->context;
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
        if (io->activated == NULL) {
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
