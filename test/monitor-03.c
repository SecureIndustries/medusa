
#include <unistd.h>
#include <string.h>

#include "medusa/monitor.h"

static const unsigned int backends[] = {
        medusa_monitor_backend_default,
        medusa_monitor_backend_epoll,
        medusa_monitor_backend_kqueue,
        medusa_monitor_backend_poll,
        medusa_monitor_backend_select
};

int main (int argc, char *argv[])
{
        unsigned int i;
        struct medusa_monitor *monitor;
        struct medusa_monitor_init_options options;
        (void) argc;
        (void) argv;
        for (i = 0; i < sizeof(backends) / sizeof(backends[0]); i++) {
                memset(&options, 0, sizeof(struct medusa_monitor_init_options));
                options.backend.type = backends[i];
                monitor = medusa_monitor_create(&options);
                if (monitor == NULL) {
                        return -1;
                }
                medusa_monitor_destroy(monitor);
        }
        return 0;
}
