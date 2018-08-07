
#include <stdio.h>
#include <unistd.h>

#include "medusa/error.h"
#include "medusa/io.h"

int main (int argc, char *argv[])
{
        struct medusa_io *io;
        (void) argc;
        (void) argv;
        io = medusa_io_create(NULL, -1, NULL, NULL);
        if (!MEDUSA_IS_ERR_OR_NULL(io)) {
                fprintf(stderr, "error\n");
                return -1;
        }
        fprintf(stderr, "success\n");
        return 0;
}
