
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#include <pthread.h>

#include "medusa/monitor.h"

static void alarm_handler (int sig)
{
        (void) sig;
        abort();
}

static void * thread_worker (void *arg)
{
        int rc;
        struct medusa_monitor *monitor = (struct medusa_monitor *) arg;
        usleep(500000);
        fprintf(stderr, "breaking\n");
        rc = medusa_monitor_break(monitor);
        pthread_exit((void *) (*(int **) &rc));
        return NULL;
}

int main (int argc, char *argv[])
{
        int rc;

        pthread_t thread;
        struct medusa_monitor *monitor;

        (void) argc;
        (void) argv;

        srand(time(NULL));
        signal(SIGALRM, alarm_handler);

        alarm(5);

        monitor = medusa_monitor_create(NULL);
        if (monitor == NULL) {
                return -1;
        }

        pthread_create(&thread, NULL, thread_worker, monitor);

        fprintf(stderr, "run...\n");
        rc = medusa_monitor_run(monitor, 0);
        if (rc != 0) {
                return -1;
        }
        fprintf(stderr, "done...\n");

        pthread_join(thread, (void **) &rc);
        if (rc != 0) {
                return -1;
        }
        medusa_monitor_destroy(monitor);
        fprintf(stderr, "finish...\n");
        return 0;
}
