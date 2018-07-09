
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include "medusa/event.h"
#include "medusa/time.h"
#include "medusa/subject.h"
#include "medusa/monitor.h"

static const unsigned int g_polls[] = {
        medusa_monitor_poll_default,
#if defined(__LINUX__)
        medusa_monitor_poll_epoll,
#endif
#if defined(__APPLE__)
        medusa_monitor_poll_kqueue,
#endif
        medusa_monitor_poll_poll,
        medusa_monitor_poll_select
};

static int subject_callback (struct medusa_subject *subject, unsigned int events)
{
        if (subject == NULL) {
                goto bail;
        }
        if (events == 0) {
                goto bail;
        }
        return 0;
bail:   return -1;
}

static int test_poll (unsigned int poll)
{
        int rc;

        struct medusa_monitor *monitor;
        struct medusa_monitor_init_options options;

        struct medusa_subject *subject_io;
        struct medusa_subject *subject_timer;
        struct medusa_subject *subject_signal;

        monitor = NULL;

        memset(&options, 0, sizeof(struct medusa_monitor_init_options));
        options.poll.type = poll;

        monitor = medusa_monitor_create(&options);
        if (monitor == NULL) {
                goto bail;
        }

        subject_io = medusa_subject_create_io(STDIN_FILENO, subject_callback, NULL);
        if (subject_io == NULL) {
                goto bail;
        }
        rc = medusa_monitor_add(monitor, subject_io, medusa_event_out);
        if (rc != 0) {
                goto bail;
        }

        subject_timer = medusa_subject_create_timer(
                                (struct medusa_timerspec) {
                                        .timespec = {
                                                .seconds = 1,
                                                .nanoseconds = 0
                                        },
                                        .interval = {
                                                .seconds = 0,
                                                .nanoseconds = 0
                                        }
                                },
                                subject_callback,
                                NULL
                        );
        if (subject_timer == NULL) {
                goto bail;
        }
        rc = medusa_monitor_add(monitor, subject_timer);
        if (rc != 0) {
                goto bail;
        }

        subject_signal = medusa_subject_create_signal(SIGINT, subject_callback, NULL);
        if (subject_signal == NULL) {
                goto bail;
        }
        rc = medusa_monitor_add(monitor, subject_signal);
        if (rc != 0) {
                goto bail;
        }

        medusa_subject_destroy(subject_signal);
        medusa_subject_destroy(subject_timer);
        medusa_subject_destroy(subject_io);
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
