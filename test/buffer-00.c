
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include "medusa/error.h"
#include "medusa/buffer.h"

int main (int argc, char *argv[])
{
        struct medusa_buffer *buffer;
        (void) argc;
        (void) argv;
        buffer = medusa_buffer_create(-1);
        if (!MEDUSA_IS_ERR_OR_NULL(buffer)) {
                fprintf(stderr, "error\n");
                return -1;
        }
        fprintf(stderr, "success\n");
        return 0;
}
