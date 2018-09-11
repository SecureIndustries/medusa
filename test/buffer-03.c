
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "medusa/error.h"
#include "medusa/buffer.h"

static const unsigned int g_types[] = {
        MEDUSA_BUFFER_TYPE_SIMPLE,
        MEDUSA_BUFFER_TYPE_CHUNKED,
};

static int test_buffer (unsigned int type, unsigned int count)
{
        char *data;

        unsigned int i;
        unsigned int j;

        int rc;
        struct medusa_buffer *buffer;

        int niovecs;
        struct medusa_buffer_iovec *iovecs;

        data = malloc(count);
        if (data == NULL) {
                fprintf(stderr, "malloc failed\n");
                return -1;
        }
        for (i = 0; i < count; i++) {
                data[i] = rand() % 0xff;
        }

        buffer = medusa_buffer_create(type);
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                fprintf(stderr, "medusa_buffer_create failed\n");
                return -1;
        }

        niovecs = medusa_buffer_reserve(buffer, count, NULL, 0);
        if (niovecs < 0) {
                fprintf(stderr, "medusa_buffer_reserve failed\n");
                return -1;
        }
        iovecs = malloc(sizeof(struct medusa_buffer_iovec) * niovecs);
        if (iovecs == NULL) {
                fprintf(stderr, "malloc failed\n");
                return -1;
        }

        niovecs = medusa_buffer_reserve(buffer, count, iovecs, niovecs);
        if (niovecs < 0) {
                fprintf(stderr, "medusa_buffer_reserve failed\n");
                return -1;
        }

        j = 0;
        for (i = 0; i < (unsigned int) niovecs; i++) {
                if (iovecs[i].length > count - j) {
                        return -1;
                }
                memcpy(iovecs[i].data, data + j, iovecs[i].length);
                j += iovecs[i].length;
        }

        rc = medusa_buffer_commit(buffer, iovecs, niovecs);
        if (rc != niovecs) {
                fprintf(stderr, "medusa_buffer_commit failed: %d != %d, count: %d\n", rc, niovecs, count);
                return -1;
        }

        free(iovecs);

        niovecs = medusa_buffer_peek(buffer, 0, -1, NULL, 0);
        if (niovecs < 0) {
                fprintf(stderr, "medusa_buffer_peek failed\n");
                return -1;
        }

        iovecs = malloc(sizeof(struct medusa_buffer_iovec) * niovecs);
        if (iovecs == NULL) {
                fprintf(stderr, "malloc failed\n");
                return -1;
        }

        niovecs = medusa_buffer_peek(buffer, 0, -1, iovecs, niovecs);
        if (niovecs < 0) {
                fprintf(stderr, "medusa_buffer_peek failed, count: %d\n", count);
                return -1;
        }

        j = 0;
        for (i = 0; i < (unsigned int) niovecs; i++) {
                if (iovecs[i].length > count - j) {
                        return -1;
                }
                rc = memcmp(data + j, iovecs[i].data, iovecs[i].length);
                if (rc != 0) {
                        fprintf(stderr, "data mismatch @ i: %d / %d, j: %d / %d, iov: %ld\n", i, niovecs, j, count, iovecs[i].length);
                        return -1;
                }
                j += iovecs[i].length;
        }
        if (count != j) {
                fprintf(stderr, "count: %d != j: %d, i: %d / %d\n", count, j, i, niovecs);
                return -1;
        }

        free(iovecs);
        medusa_buffer_destroy(buffer);
        free(data);
        return 0;
}

int main (int argc, char *argv[])
{
        int rc;
        unsigned int i;
        unsigned int j;
        (void) argc;
        (void) argv;
        fprintf(stderr, "start\n");
        for (i = 0; i < sizeof(g_types) / sizeof(g_types[0]); i++) {
                fprintf(stderr, "type: %d\n", g_types[i]);
                for (j = 0; j < 1000; j++) {
                        rc = test_buffer(g_types[i], 1040);
                        if (rc != 0) {
                                fprintf(stderr, "fail\n");
                                return -1;
                        }
                }
        }
        fprintf(stderr, "success\n");
        return 0;
}
