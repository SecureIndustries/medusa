
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../src/pool.h"
#include "../src/pool.c"

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
        unsigned int seed;
        unsigned int allocs;

        unsigned int size;
        unsigned int align;
        unsigned int count;

        struct pool *pool;
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

        allocs = rand() % 10000;
        fprintf(stderr, "allocs: %d\n", allocs);

        pool = pool_create("pool", size, align, count, POOL_FLAG_DEFAULT, contructor, destructor, NULL);
        if (pool == NULL) {
                return -1;
        }

        ptrs = malloc(sizeof(void *) * allocs);
        if (ptrs == NULL) {
                return -1;
        }

        for (i = 0; i < allocs; i++) {
                ptrs[i] = pool_malloc(pool);
        }
        for (i = 0; i < allocs; i++) {
                pool_free(ptrs[i]);
        }

        pool_destroy(pool);

        free(ptrs);
        return 0;
}
