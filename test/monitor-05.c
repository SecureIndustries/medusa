
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include "medusa/event.h"
#include "medusa/io.h"
#include "medusa/timer.h"
#include "medusa/monitor.h"

static const unsigned int g_polls[] = {
        MEDUSA_MONITOR_POLL_DEFAULT,
#if defined(__LINUX__)
        MEDUSA_MONITOR_POLL_EPOLL,
#endif
#if defined(__APPLE__)
        MEDUSA_MONITOR_POLL_KQUEUE,
#endif
        MEDUSA_MONITOR_POLL_POLL,
        MEDUSA_MONITOR_POLL_SELECT
};

static void io_activated_callback (struct medusa_io *io, unsigned int events)
{
        (void) io;
        (void) events;
}

static void timer_timeout_callback (struct medusa_timer *timer, void *context)
{
        (void) timer;
        (void) context;
}

static int test_poll (unsigned int poll)
{
        int rc;

        struct medusa_monitor *monitor;
        struct medusa_monitor_init_options options;

        struct medusa_io *io;
        struct medusa_timer *timer;

        monitor = NULL;

        medusa_monitor_init_options_default(&options);
        options.poll.type = poll;

        monitor = medusa_monitor_create(&options);
        if (monitor == NULL) {
                goto bail;
        }

        io = medusa_io_create();
        if (io == NULL) {
                goto bail;
        }
        rc = medusa_io_set_fd(io, STDIN_FILENO);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_io_set_events(io, MEDUSA_EVENT_IN);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_io_set_activated_callback(io, io_activated_callback, NULL);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_io_set_enabled(io, 1);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_monitor_add(monitor, (struct medusa_subject *) io);
        if (rc != 0) {
                goto bail;
        }

        timer = medusa_timer_create();
        if (timer == NULL) {
                goto bail;
        }
        rc = medusa_timer_set_initial(timer, 1.0);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_timer_set_interval(timer, 1.0);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_timer_set_single_shot(timer, 1);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_timer_set_type(timer, MEDUSA_TIMER_TYPE_PRECISE);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_timer_set_timeout_callback(timer, timer_timeout_callback, NULL);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_timer_set_active(timer, 1);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_monitor_add(monitor, (struct medusa_subject *) timer);
        if (rc != 0) {
                goto bail;
        }

        medusa_monitor_destroy(monitor);
        return 0;
bail:   if (monitor != NULL) {
                medusa_monitor_destroy(monitor);
        }
        return 01;
}

int main (int argc, char *argv[])
{
        int rc;
        unsigned int i;
        (void) argc;
        (void) argv;
        for (i = 0; i < sizeof(g_polls) / sizeof(g_polls[0]); i++) {
                rc = test_poll(g_polls[i]);
                if (rc != 0) {
                        return -1;
                }
        }
        return 0;
}
