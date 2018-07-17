
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
#include "timer-struct.h"
#include "io-struct.h"

#include "timer.h"
#include "io.h"

static int io_subject_event (struct medusa_subject *subject, unsigned int events)
{
        struct medusa_io *io = (struct medusa_io *) subject;
        if (io->callback != NULL) {
                return io->callback(io, events, io->context);
        }
        return 0;
}

static int io_timeout_callback (struct medusa_timer *timer, unsigned int events, void *context)
{
        struct medusa_io *io = (struct medusa_io *) context;
        (void) timer;
        (void) events;
        if (events & MEDUSA_EVENT_TIMEOUT) {
                return io_subject_event(&io->subject, events);
        }
        return 0;
}

static int io_init (struct medusa_monitor *monitor, struct medusa_io *io, void (*destroy) (struct medusa_io *io))
{
        int rc;
        memset(io, 0, sizeof(struct medusa_io));
        io->fd = -1;
        io->events = 0;
        io->enabled = 0;
        io->subject.type = MEDUSA_SUBJECT_TYPE_IO;
        io->subject.event = io_subject_event;
        io->subject.destroy = (void (*) (struct medusa_subject *)) destroy;
        io->subject.flags = MEDUSA_SUBJECT_FLAG_NONE;
        io->subject.monitor = NULL;
        rc = medusa_subject_add(monitor, &io->subject);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_timer_init(monitor, &io->timeout);
        if (rc != 0) {
                medusa_subject_del(&io->subject);
                goto bail;
        }
        rc = medusa_timer_set_callback(&io->timeout, io_timeout_callback, io);
        if (rc != 0) {
                medusa_subject_del(&io->subject);
                goto bail;
        }
        return 0;
bail:   return -1;
}

static void io_uninit (struct medusa_io *io)
{
        if (io->fd >= 0 &&
            io->close_on_destroy) {
                close(io->fd);
        }
        medusa_timer_uninit(&io->timeout);
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

int medusa_io_set_timeout (struct medusa_io *io, double timeout)
{
        int rc;
        rc = medusa_timer_set_initial(&io->timeout, timeout);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_timer_set_interval(&io->timeout, timeout);
        if (rc != 0) {
                goto bail;
        }
        return 0;
bail:   return -1;
}

double medusa_io_get_timeout (const struct medusa_io *io)
{
        return medusa_timer_get_interval(&io->timeout);
}

int medusa_io_set_callback (struct medusa_io *io, int (*callback) (struct medusa_io *io, unsigned int events, void *context), void *context)
{
        io->callback = callback;
        io->context = context;
        return medusa_subject_mod(&io->subject);
}

int medusa_io_set_enabled (struct medusa_io *io, int enabled)
{
        int rc;
        io->enabled = !!enabled;
        rc = medusa_subject_mod(&io->subject);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_timer_set_enabled(&io->timeout, enabled);
        if (rc != 0) {
                goto bail;
        }
        return 0;
bail:   return -1;
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

struct medusa_monitor * medusa_io_get_monitor (struct medusa_io *io)
{
        return io->subject.monitor;
}
