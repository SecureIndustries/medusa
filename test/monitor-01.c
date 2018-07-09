
#include <unistd.h>

#include "medusa/monitor.h"

int main (int argc, char *argv[])
{
        int rc;
        (void) argc;
        (void) argv;
        rc = medusa_monitor_init_options_default(NULL);
        if (rc == 0) {
                return -1;
        }
        return 0;
}
