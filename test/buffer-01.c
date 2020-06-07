
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include "medusa/error.h"
#include "medusa/buffer.h"

static const unsigned int g_types[] = {
        MEDUSA_BUFFER_TYPE_DEFAULT,
        MEDUSA_BUFFER_TYPE_SIMPLE,
        MEDUSA_BUFFER_TYPE_RING
};

static int test_buffer (unsigned int type)
{
        struct medusa_buffer *buffer;
        buffer = medusa_buffer_create(type);
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -1;
        }
        medusa_buffer_destroy(buffer);
        return 0;
}

int main (int argc, char *argv[])
{
        int rc;
        unsigned int i;
        (void) argc;
        (void) argv;
        fprintf(stderr, "start\n");
        for (i = 0; i < sizeof(g_types) / sizeof(g_types[0]); i++) {
                fprintf(stderr, "type: %d\n", g_types[i]);
                rc = test_buffer(g_types[i]);
                if (rc != 0) {
                        fprintf(stderr, "fail\n");
                        return -1;
                }
        }
        fprintf(stderr, "success\n");
        return 0;
}
