
#include <unistd.h>

#include "medusa/time.h"
#include "medusa/subject.h"

int main (int argc, char *argv[])
{
        struct medusa_subject *subject;
        (void) argc;
        (void) argv;
        subject = medusa_subject_create_timer(
                        (struct medusa_timerspec) {
                                .timespec = {
                                        .seconds = 0,
                                        .nanoseconds = 0
                                },
                                .interval = {
                                        .seconds = 0,
                                        .nanoseconds = 0
                                }
                        }, NULL, NULL);
        if (subject != NULL) {
                return -1;
        }
        return 0;
}
