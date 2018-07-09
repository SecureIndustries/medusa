
#include <unistd.h>

#include "medusa/monitor.h"

int main (int argc, char *argv[])
{
        struct medusa_monitor *monitor;
        (void) argc;
        (void) argv;
        monitor = medusa_monitor_create(NULL);
        if (monitor == NULL) {
                return -1;
        }
        medusa_monitor_destroy(monitor);
        return 0;
}
