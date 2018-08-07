
#include <stdio.h>
#include <unistd.h>

#include "medusa/error.h"
#include "medusa/timer.h"

int main (int argc, char *argv[])
{
        struct medusa_timer *timer;
        (void) argc;
        (void) argv;
        timer = medusa_timer_create(NULL, NULL, NULL);
        if (!MEDUSA_IS_ERR_OR_NULL(timer)) {
                fprintf(stderr, "error\n");
                return -1;
        }
        fprintf(stderr, "success\n");
        return 0;
}
