
#include <stdlib.h>
#include <string.h>

#include "queue.h"
#include "event.h"
#include "subject.h"

#include "subject-struct.h"
#include "io-struct.h"

#include "io.h"

static int io_subject_callback (struct medusa_subject *subject, unsigned int events)
{
        struct medusa_io *io = (struct medusa_io *) subject;
        if (io->activated != NULL) {
                io->activated(io, events, io->context);
        }
        return 0;
}

static int medusa_io_init (struct medusa_io *io)
{
        memset(io, 0, sizeof(struct medusa_io));
        io->fd = -1;
        io->events = 0;
        io->enabled = 0;
        return medusa_subject_set(&io->subject, medusa_subject_type_io, io_subject_callback, NULL);
}

static void medusa_io_uninit (struct medusa_io *io)
{
        medusa_subject_del(&io->subject);
        memset(io, 0, sizeof(struct medusa_io));
}

struct medusa_io * medusa_io_create (void)
{
        int rc;
        struct medusa_io *io;
        io = malloc(sizeof(struct medusa_io));
        if (io == NULL) {
                goto bail;
        }
        rc = medusa_io_init(io);
        if (rc != 0) {
                goto bail;
        }
        return io;
bail:   if (io != NULL) {
                medusa_io_destroy(io);
        }
        return NULL;
}

void medusa_io_destroy (struct medusa_io *io)
{
        medusa_io_uninit(io);
        free(io);
}

int medusa_io_set_fd (struct medusa_io *io, int fd)
{
        io->fd = fd;
        return medusa_subject_mod(&io->subject);
}

int medusa_io_get_fd (const struct medusa_io *io)
{
        return io->fd;
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

int medusa_io_set_activated_callback (struct medusa_io *io, void (*activated) (struct medusa_io *io, unsigned int events, void *context), void *context)
{
        io->activated = activated;
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
        if ((io->events & (medusa_event_in | medusa_event_out | medusa_event_pri)) == 0) {
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

struct medusa_monitor * medusa_io_get_monitor (struct medusa_io *io)
{
        return io->subject.monitor;
}
