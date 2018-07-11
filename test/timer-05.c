
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#include "medusa/timer.h"
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
//        medusa_monitor_poll_select
};

static void timer_timeout_callback (struct medusa_timer *timer, void *context)
{
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
        medusa_monitor_init_options_default(&options);
        options.poll.type = poll;

        monitor = medusa_monitor_create(&options);
        if (monitor == NULL) {
                goto bail;
        }

        timer = medusa_timer_create();
        if (timer == NULL) {
                goto bail;
        }
        rc = medusa_timer_set_interval(timer, 0.01);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_timer_set_timeout_callback(timer, timer_timeout_callback, &count);
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
        rc = medusa_monitor_add(monitor, (struct medusa_subject *) timer);
        if (rc != 0) {
                goto bail;
        }

        rc = medusa_monitor_run(monitor, medusa_monitor_run_default);
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