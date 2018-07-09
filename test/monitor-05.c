
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include "medusa/event.h"
#include "medusa/time.h"
#include "medusa/subject.h"
#include "medusa/monitor.h"

static const unsigned int g_backends[] = {
        medusa_monitor_backend_default,
#if defined(__LINUX__)
        medusa_monitor_backend_epoll,
#endif
#if defined(__APPLE__)
        medusa_monitor_backend_kqueue,
#endif
        medusa_monitor_backend_poll,
        medusa_monitor_backend_select
};

static int subject_callback (void *context, struct medusa_subject *subject, unsigned int events)
{
        if (context != NULL) {
                goto bail;
        }
        if (subject == NULL) {
                goto bail;
        }
        if (events == 0) {
                goto bail;
        }
        return 0;
bail:   return -1;
}

static int test_backend (unsigned int backend)
{
        int rc;

        struct medusa_monitor *monitor;
        struct medusa_monitor_init_options options;

        struct medusa_subject *subject;

        monitor = NULL;

        memset(&options, 0, sizeof(struct medusa_monitor_init_options));
        options.backend.type = backend;

        monitor = medusa_monitor_create(&options);
        if (monitor == NULL) {
                goto bail;
        }

        subject = medusa_subject_create_io(STDIN_FILENO, subject_callback, NULL);
        if (subject == NULL) {
                goto bail;
        }
        rc = medusa_monitor_add(monitor, subject, medusa_event_out);
        if (rc != 0) {
                goto bail;
        }
        medusa_subject_destroy(subject);

        subject = medusa_subject_create_timer(
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
        if (subject == NULL) {
                goto bail;
        }
        rc = medusa_monitor_add(monitor, subject);
        if (rc != 0) {
                goto bail;
        }
        medusa_subject_destroy(subject);

        subject = medusa_subject_create_signal(SIGINT, subject_callback, NULL);
        if (subject == NULL) {
                goto bail;
        }
        rc = medusa_monitor_add(monitor, subject);
        if (rc != 0) {
                goto bail;
        }
        medusa_subject_destroy(subject);

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
        for (i = 0; i < sizeof(g_backends) / sizeof(g_backends[0]); i++) {
                rc = test_backend(g_backends[i]);
                if (rc != 0) {
                        return -1;
                }
        }
        return 0;
}
