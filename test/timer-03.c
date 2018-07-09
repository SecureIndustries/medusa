
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#include "medusa/event.h"
#include "medusa/time.h"
#include "medusa/subject.h"
#include "medusa/monitor.h"

static int callback (struct medusa_subject *subject, unsigned int events)
{
        if (events == 0) {
                goto bail;
        }
        if (events & medusa_event_timeout) {
                return medusa_monitor_break(medusa_subject_get_monitor(subject));
        } else {
                goto bail;
        }
bail:   return -1;
}

static void alarm_handler (int sig)
{
        (void) sig;
        abort();
}

int main (int argc, char *argv[])
{
        int rc;

        struct medusa_monitor *monitor;
        struct medusa_subject *subject;

        (void) argc;
        (void) argv;

        srand(time(NULL));
        signal(SIGALRM, alarm_handler);

        alarm(5);

        monitor = medusa_monitor_create(NULL);
        if (monitor == NULL) {
                return -1;
        }
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
                        }, callback, NULL);
        if (subject == NULL) {
                return -1;
        }
        rc = medusa_monitor_add(monitor, subject);
        if (rc != 0) {
                return -1;
        }
        rc = medusa_monitor_run(monitor, 0);
        if (rc != 0) {
                return -1;
        }
        medusa_subject_destroy(subject);
        medusa_monitor_destroy(monitor);
        return 0;
}
