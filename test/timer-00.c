
#include <unistd.h>

#include "medusa/time.h"
#include "medusa/timer.h"

int main (int argc, char *argv[])
{
        struct medusa_timer *timer;
        (void) argc;
        (void) argv;
        timer = medusa_timer_create();
        if (timer == NULL) {
                return -1;
        }
        return 0;
}
