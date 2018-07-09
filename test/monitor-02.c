
#include <unistd.h>

#include "medusa/monitor.h"

int main (int argc, char *argv[])
{
        int rc;
        struct medusa_monitor *monitor;
        struct medusa_monitor_init_options options;
        (void) argc;
        (void) argv;
        rc = medusa_monitor_init_options_default(&options);
        if (rc != 0) {
                return -1;
        }
        monitor = medusa_monitor_create(&options);
        if (monitor == NULL) {
                return -1;
        }
        medusa_monitor_destroy(monitor);
        return 0;
}
