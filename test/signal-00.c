
#include <stdio.h>
#include <unistd.h>

#include "medusa/error.h"
#include "medusa/signal.h"

int main (int argc, char *argv[])
{
        struct medusa_signal *signal;
        (void) argc;
        (void) argv;
        signal = medusa_signal_create(NULL, -1, NULL, NULL);
        if (!MEDUSA_IS_ERR_OR_NULL(signal)) {
                fprintf(stderr, "error\n");
                return -1;
        }
        fprintf(stderr, "success\n");
        return 0;
}
