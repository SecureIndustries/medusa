
#include <unistd.h>

#include "medusa/io.h"

int main (int argc, char *argv[])
{
        struct medusa_io *io;
        (void) argc;
        (void) argv;
        io = medusa_io_create();
        if (io == NULL) {
                return -1;
        }
        medusa_io_destroy(io);
        return 0;
}
