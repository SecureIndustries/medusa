
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <time.h>
#include <signal.h>

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

static int test_poll (unsigned int poll, unsigned int count)
{
        int rc;
        unsigned int i;

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

        for (i = 0; i < count; i++) {
                timer = medusa_timer_create(monitor);
                if (timer == NULL) {
                        goto bail;
                }
                rc = medusa_timer_set_interval(timer, rand());
                if (rc != 0) {
                        goto bail;
                }
                rc = medusa_timer_set_single_shot(timer, rand() % 2);
                if (rc != 0) {
                        goto bail;
                }
                rc = medusa_timer_set_callback(timer, timer_callback, NULL);
                if (rc != 0) {
                        goto bail;
                }
                rc = medusa_timer_set_enabled(timer, 1);
                if (rc != 0) {
                        goto bail;
                }
        }

        rc = medusa_monitor_run_timeout(monitor, 0.0);
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

static void alarm_handler (int sig)
{
        (void) sig;
        abort();
}

int main (int argc, char *argv[])
{
        int rc;
        unsigned int i;

        unsigned int count;

        (void) argc;
        (void) argv;

        srand(time(NULL));
        signal(SIGALRM, alarm_handler);

        count = 100;

        for (i = 0; i < sizeof(g_polls) / sizeof(g_polls[0]); i++) {
                alarm(5);
                fprintf(stderr, "testing poll: %d\n", g_polls[i]);

                rc = test_poll(g_polls[i], count);
                if (rc != 0) {
                        return -1;
                }
        }

        return 0;
}
