
#include <unistd.h>

#include "medusa/io.h"

int main (int argc, char *argv[])
{
        struct medusa_io *io;
        (void) argc;
        (void) argv;
        io = medusa_io_create(NULL);
        if (io != NULL) {
                return -1;
        }
        return 0;
}
