
#include <unistd.h>
#include <string.h>

#include "medusa/monitor.h"

static const unsigned int polls[] = {
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

int main (int argc, char *argv[])
{
        unsigned int i;
        struct medusa_monitor *monitor;
        struct medusa_monitor_init_options options;
        (void) argc;
        (void) argv;
        for (i = 0; i < sizeof(polls) / sizeof(polls[0]); i++) {
                memset(&options, 0, sizeof(struct medusa_monitor_init_options));
                options.poll.type = polls[i];
                monitor = medusa_monitor_create(&options);
                if (monitor == NULL) {
                        return -1;
                }
                medusa_monitor_destroy(monitor);
        }
        return 0;
}
