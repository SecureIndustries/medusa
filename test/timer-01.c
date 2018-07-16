
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

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

static int timer_callback (struct medusa_timer *timer, unsigned int events, void *context)
{
        (void) timer;
        (void) events;
        (void) context;
        return 0;
}

static int test_poll (unsigned int poll)
{
        int rc;

        struct medusa_monitor *monitor;
        struct medusa_monitor_init_options options;

        struct medusa_timer *timer;

        monitor = NULL;

        medusa_monitor_init_options_default(&options);
        options.poll.type = poll;

        monitor = medusa_monitor_create(&options);
        if (monitor == NULL) {
                goto bail;
        }

        timer = medusa_timer_create(monitor);
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
        rc = medusa_timer_set_callback(timer, timer_callback, NULL);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_timer_set_active(timer, 1);
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
