
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

#include "medusa/pool.h"

static void contructor (void *ptr, void *context)
{
        (void) ptr;
        (void) context;
}

static void destructor (void *ptr, void *context)
{
        (void) ptr;
        (void) context;
}

int main (int argc, char *argv[])
{
        unsigned int i;
        unsigned int a;
        unsigned int seed;
        unsigned int allocs;

        unsigned int size;
        unsigned int align;
        unsigned int count;

        struct medusa_pool *pool;
        void **ptrs;

        (void) argc;
        (void) argv;

        seed = time(NULL);
        srand(seed);

        fprintf(stderr, "seed  : %d\n", seed);

        size = rand() % 256;
        align = rand() % 16;
        count = rand() % 1024;

        fprintf(stderr, "size  : %d\n", size);
        fprintf(stderr, "align : %d\n", align);
        fprintf(stderr, "count : %d\n", count);

        allocs = rand() % 100000;
        fprintf(stderr, "allocs: %d\n", allocs);

        pool = medusa_pool_create("pool", size, align, count, MEDUSA_POOL_FLAG_DEFAULT, contructor, destructor, NULL);
        if (pool == NULL) {
                return -1;
        }

        ptrs = malloc(sizeof(void *) * allocs);
        if (ptrs == NULL) {
                return -1;
        }
        memset(ptrs, 0, sizeof(void *) * allocs);

        a = 0;
        while (a != allocs) {
                i = rand() % allocs;
                if (ptrs[i] == NULL) {
                        ptrs[i] = medusa_pool_malloc(pool);
                        a += 1;
                } else {
                        medusa_pool_free(ptrs[i]);
                        ptrs[i] = NULL;
                }
        }
        for (i = 0; i < allocs; i++) {
                medusa_pool_free(ptrs[i]);
        }

        medusa_pool_destroy(pool);

        free(ptrs);
        return 0;
}
