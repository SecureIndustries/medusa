
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#include <sys/types.h>
#include <pthread.h>

#include "medusa/error.h"
#include "medusa/timer.h"
#include "medusa/signal.h"
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

static int signal_onevent (struct medusa_signal *signal, unsigned int events, void *context, ...)
{
        (void) signal;
        (void) events;
        (void) context;
        return medusa_monitor_break(medusa_signal_get_monitor(signal));
}

static int timer_onevent (struct medusa_timer *timer, unsigned int events, void *context, ...)
{
        pid_t pid;
        (void) timer;
        (void) events;
        (void) context;
        pid = getpid();
        kill(pid, SIGUSR1);
        return 0;
}

static int test_poll (unsigned int poll)
{
        int rc;

        struct medusa_monitor *monitor;
        struct medusa_monitor_init_options options;

        struct medusa_signal *signal;

        monitor = NULL;

        medusa_monitor_init_options_default(&options);
        options.poll.type = poll;

        monitor = medusa_monitor_create(&options);
        if (monitor == NULL) {
                goto bail;
        }

        signal = medusa_signal_create(monitor, SIGUSR1, signal_onevent, NULL);
        if (MEDUSA_IS_ERR_OR_NULL(signal)) {
                goto bail;
        }
        rc = medusa_signal_set_enabled(signal, 1);
        if (rc < 0) {
                goto bail;
        }

        rc = medusa_timer_create_singleshot(monitor, 0.1, timer_onevent, NULL);
        if (rc < 0) {
                goto bail;
        }

        rc = medusa_monitor_run(monitor);
        if (rc < 0) {
                goto bail;
        }

        medusa_monitor_destroy(monitor);
        return 0;
bail:   if (monitor != NULL) {
                medusa_monitor_destroy(monitor);
        }
        return -1;
}

static void sigalarm_handler (int sig)
{
        (void) sig;
        abort();
}

static void sigint_handler (int sig)
{
        (void) sig;
        abort();
}

static void * do_nothing_thread (void *context)
{
        (void) context;

        while (1) {
                sleep(1);
        }

        return NULL;
}

int main (int argc, char *argv[])
{
        int rc;
        unsigned int i;
        pthread_t thread;

        (void) argc;
        (void) argv;

        pthread_create(&thread, NULL, do_nothing_thread, NULL);

        srand(time(NULL));
        signal(SIGALRM, sigalarm_handler);
        signal(SIGINT, sigint_handler);

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
