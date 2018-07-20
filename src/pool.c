
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "queue.h"
#include "pool.h"

TAILQ_HEAD(entries, entry);
struct entry {
        struct block *block;
        TAILQ_ENTRY(entry) list;
        unsigned char data[0];
};

TAILQ_HEAD(blocks, block);
struct block {
        struct pool *pool;
        TAILQ_ENTRY(block) list;
        struct entries free;
        struct entries used;
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
        void (*constructor) (void *ptr, void *context);
        void (*destructor) (void *ptr, void *context);
        void *context;
};

static unsigned int page_size = 0;

static inline int aligncount (unsigned int size, unsigned int count)
{
        count *= size;
        count = (count + sizeof(void *) * 4 + (page_size - 1)) & ~(page_size - 1);
        count = count - sizeof(void *) * 4;
        count /= size;
        return count;
}

static void entry_destroy (struct entry *entry)
{
        if (entry == NULL) {
                return;
        }
        if (entry->block != NULL &&
            entry->block->pool != NULL &&
            entry->block->pool->destructor != NULL) {
                entry->block->pool->destructor(entry->data, entry->block->pool->context);
        }
}

static void entry_create (struct entry *entry)
{
        if (entry == NULL) {
                return;
        }
        if (entry->block != NULL &&
            entry->block->pool != NULL &&
            entry->block->pool->constructor != NULL) {
                entry->block->pool->constructor(entry->data, entry->block->pool->context);
        }
}

static void block_destroy (struct block *block)
{
        struct entry *entry;
        struct entry *nentry;
        if (block == NULL) {
                return;
        }
        TAILQ_FOREACH_SAFE(entry, &block->free, list, nentry) {
                TAILQ_REMOVE(&block->free, entry, list);
                entry_destroy(entry);
        }
        TAILQ_FOREACH_SAFE(entry, &block->used, list, nentry) {
                TAILQ_REMOVE(&block->used, entry, list);
                entry_destroy(entry);
        }
        free(block);
}

static struct block * block_create (struct pool *pool)
{
        unsigned int i;
        unsigned int count;
        struct entry *entry;
        struct block *block;
        count = aligncount(pool->size, pool->count);
        block = malloc(sizeof(struct block) + pool->size * count);
        if (block == NULL) {
                goto bail;
        }
        memset(block, 0, sizeof(struct block));
        block->pool = pool;
        TAILQ_INIT(&block->free);
        TAILQ_INIT(&block->used);
        for (i = 0; i < count; i++) {
                entry = (struct entry *) (block->data + pool->size * i);
                entry->block = block;
                TAILQ_INSERT_HEAD(&block->free, entry, list);
                entry_create(entry);
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
        struct blocks *blocks;
        if (pool == NULL) {
                goto bail;
        }
        if (!TAILQ_EMPTY(&pool->half)) {
                blocks = &pool->half;
        } else if (!TAILQ_EMPTY(&pool->free)) {
                blocks = &pool->free;
        } else {
                block = block_create(pool);
                if (block == NULL) {
                        goto bail;
                }
                TAILQ_INSERT_HEAD(&pool->free, block, list);
                blocks = &pool->free;
        }
        block = TAILQ_FIRST(blocks);
        TAILQ_REMOVE(blocks, block, list);
        entry = TAILQ_FIRST(&block->free);
        TAILQ_REMOVE(&block->free, entry, list);
        TAILQ_INSERT_HEAD(&block->used, entry, list);
        if (TAILQ_EMPTY(&block->free)) {
                TAILQ_INSERT_HEAD(&pool->full, block, list);
        } else {
                TAILQ_INSERT_HEAD(&pool->half, block, list);
        }
        return entry->data;
bail:   return NULL;
}

void pool_free (void *ptr)
{
        struct entry *entry;
        struct blocks *blocks;
        if (ptr == NULL) {
                return;
        }
        entry = (struct entry *) (((unsigned char *) ptr) - sizeof(struct entry));
        if (TAILQ_EMPTY(&entry->block->free)) {
                blocks = &entry->block->pool->full;
        } else {
                blocks = &entry->block->pool->half;
        }
        TAILQ_REMOVE(&entry->block->used, entry, list);
        TAILQ_INSERT_HEAD(&entry->block->free, entry, list);
        TAILQ_REMOVE(blocks, entry->block, list);
        if (TAILQ_EMPTY(&entry->block->used)) {
                TAILQ_INSERT_HEAD(&entry->block->pool->free, entry->block, list);
        } else {
                TAILQ_INSERT_HEAD(&entry->block->pool->half, entry->block, list);
        }
}

__attribute__ ((constructor)) static void pool_constructor (void)
{
        page_size = getpagesize();
}
