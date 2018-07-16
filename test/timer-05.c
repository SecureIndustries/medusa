
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#include "medusa/timer.h"
#include "medusa/event.h"
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
//        MEDUSA_MONITOR_POLL_SELECT
};

static int timer_callback (struct medusa_timer *timer, unsigned int events, void *context)
{
        if (events & MEDUSA_EVENT_TIMEOUT) {
                int *count = context;
                fprintf(stderr, "timeout: %d\n", *count);
                if ((*count)++ > 10) {
                        fprintf(stderr, "break\n");
                        medusa_monitor_break(medusa_timer_get_monitor(timer));
                } else {
                        fprintf(stderr, "set interval\n");
                        medusa_timer_set_interval(timer, 0.01);
                        fprintf(stderr, "set active\n");
                        medusa_timer_start(timer);
                }
        }
        return 0;
}

static int test_poll (unsigned int poll)
{
        int rc;

        struct medusa_monitor *monitor;
        struct medusa_monitor_init_options options;

        int count;
        struct medusa_timer *timer;

        count = 0;
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
        rc = medusa_timer_set_interval(timer, 0.01);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_timer_set_callback(timer, timer_callback, &count);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_timer_start(timer);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_timer_set_single_shot(timer, 1);
        if (rc != 0) {
                goto bail;
        }

        rc = medusa_monitor_run(monitor);
        if (rc != 0) {
                fprintf(stderr, "can not run monitor\n");
                return -1;
        }

        fprintf(stderr, "finish\n");

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

        (void) argc;
        (void) argv;

        srand(time(NULL));
        signal(SIGALRM, alarm_handler);

        for (i = 0; i < sizeof(g_polls) / sizeof(g_polls[0]); i++) {
                alarm(5);
                fprintf(stderr, "testing poll: %d\n", g_polls[i]);

                rc = test_poll(g_polls[i]);
                if (rc != 0) {
                        return -1;
                }
        }
        return 0;
}
