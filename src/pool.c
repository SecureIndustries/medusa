
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "queue.h"
#include "pool.h"

SLIST_HEAD(entries, entry);
struct entry {
        SLIST_ENTRY(entry) list;
        unsigned char data[0];
};

TAILQ_HEAD(blocks, block);
struct block {
        struct pool *pool;
        TAILQ_ENTRY(block) list;
        struct entries free;
        unsigned int nused;
        unsigned char data[0];
};

struct pool {
        char *name;
        struct blocks free;
        struct blocks half;
        struct blocks full;
        unsigned int size;
        unsigned int count;
        unsigned int flags;
        unsigned int page_size;
        unsigned int block_count;
        void (*constructor) (void *ptr, void *context);
        void (*destructor) (void *ptr, void *context);
        void *context;
};

static inline int aligncount (unsigned int size, unsigned int count, unsigned int page_size)
{
        count *= size;
        count = (count + sizeof(void *) * 4 + (page_size - 1)) & ~(page_size - 1);
        count = count - sizeof(void *) * 4;
        count /= size;
        return count;
}

static void block_destroy (struct block *block)
{
        struct entry *entry;
        if (block == NULL) {
                return;
        }
        while (!SLIST_EMPTY(&block->free)) {
                entry = SLIST_FIRST(&block->free);
                SLIST_REMOVE_HEAD(&block->free, list);
                if (block->pool != NULL &&
                    block->pool->destructor != NULL) {
                        block->pool->destructor(entry->data, block->pool->context);
                }
        }
        free(block);
}

static struct block * block_create (struct pool *pool)
{
        unsigned int i;
        struct entry *entry;
        struct block *block;
        block = malloc(sizeof(struct block) + pool->size * pool->block_count);
        if (block == NULL) {
                goto bail;
        }
        memset(block, 0, sizeof(struct block));
        block->pool = pool;
        SLIST_INIT(&block->free);
        for (i = 0; i < pool->block_count; i++) {
                entry = (struct entry *) (block->data + pool->size * i);
                SLIST_INSERT_HEAD(&block->free, entry, list);
                if (pool->constructor != NULL) {
                        pool->constructor(entry->data, pool->context);
                }
        }
        return block;
bail:   if (block != NULL) {
                block_destroy(block);
        }
        return NULL;
}

struct pool * pool_create (
                const char *name,
                unsigned int size,
                unsigned int align,
                unsigned int count,
                unsigned int flags,
                void (*constructor) (void *ptr, void *context),
                void (*destructor) (void *ptr, void *context),
                void *context)
{
        struct pool *pool;
        if (align == 0) {
                align = 16;
        }
        if (count == 0) {
                count = 1;
        }
        pool = malloc(sizeof(struct pool));
        if (pool == NULL) {
                goto bail;
        }
        memset(pool, 0, sizeof(struct pool));
        TAILQ_INIT(&pool->free);
        TAILQ_INIT(&pool->half);
        TAILQ_INIT(&pool->full);
        if (name != NULL) {
                pool->name = strdup(name);
                if (pool->name == NULL) {
                        goto bail;
                }
        }
        pool->size = sizeof(struct entry) + size;
        pool->size = (pool->size + align - 1) & ~(align - 1);
        pool->count = count;
        pool->flags = flags;
        pool->constructor = constructor;
        pool->destructor = destructor;
        pool->context = context;
        pool->page_size = getpagesize();
        pool->block_count = aligncount(pool->size, pool->count, pool->page_size - sizeof(struct block));
        fprintf(stderr, "size: %d, count: %d, bcount: %d, sentry: %ld\n", pool->size, pool->count, pool->block_count, sizeof(struct entry));
        return pool;
bail:   if (pool != NULL) {
                pool_destroy(pool);
        }
        return NULL;
}

void pool_destroy (struct pool *pool)
{
        struct block *block;
        struct block *nblock;
        if (pool == NULL) {
                return;
        }
        if (pool->name != NULL) {
                free(pool->name);
        }
        TAILQ_FOREACH_SAFE(block, &pool->free, list, nblock) {
                TAILQ_REMOVE(&pool->free, block, list);
                block_destroy(block);
        }
        TAILQ_FOREACH_SAFE(block, &pool->half, list, nblock) {
                TAILQ_REMOVE(&pool->half, block, list);
                block_destroy(block);
        }
        TAILQ_FOREACH_SAFE(block, &pool->full, list, nblock) {
                TAILQ_REMOVE(&pool->full, block, list);
                block_destroy(block);
        }
        free(pool);
}

void * pool_malloc (struct pool *pool)
{
        struct entry *entry;
        struct block *block;
        struct blocks *rblocks;
        struct blocks *ablocks;
        if (pool == NULL) {
                goto bail;
        }
        if (!TAILQ_EMPTY(&pool->half)) {
                rblocks = &pool->half;
        } else if (!TAILQ_EMPTY(&pool->free)) {
                rblocks = &pool->free;
        } else {
                rblocks = NULL;
                block = block_create(pool);
                if (block == NULL) {
                        goto bail;
                }
        }
        if (rblocks != NULL) {
                block = TAILQ_FIRST(rblocks);
        }
        entry = SLIST_FIRST(&block->free);
        SLIST_REMOVE_HEAD(&block->free, list);
        block->nused += 1;
        if (SLIST_EMPTY(&block->free)) {
                ablocks = &pool->full;
        } else {
                ablocks = &pool->half;
        }
        if (rblocks != ablocks) {
                if (rblocks != NULL) {
                        TAILQ_REMOVE(rblocks, block, list);
                }
                TAILQ_INSERT_HEAD(ablocks, block, list);
        }
        entry->list.sle_next = (void *) block;
        return entry->data;
bail:   return NULL;
}

void pool_free (void *ptr)
{
        struct pool *pool;
        struct block *block;
        struct entry *entry;
        if (ptr == NULL) {
                return;
        }
        entry = (struct entry *) (((unsigned char *) ptr) - sizeof(struct entry));
        block = (struct block *) entry->list.sle_next;
        pool = block->pool;
        if (SLIST_EMPTY(&block->free)) {
                TAILQ_REMOVE(&pool->full, block, list);
        } else {
                TAILQ_REMOVE(&pool->half, block, list);
        }
        SLIST_INSERT_HEAD(&block->free, entry, list);
        block->nused -= 1;
        if (block->nused == 0) {
                block_destroy(block);
        } else {
                TAILQ_INSERT_HEAD(&pool->half, block, list);
        }
}
