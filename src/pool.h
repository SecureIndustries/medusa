
#if !defined(MEDUSA_POOL_H)
#define MEDUSA_POOL_H

struct pool;

enum {
        POOL_FLAG_NONE          = 0x00000000,
        POOL_FLAG_POISON        = 0x00000001,
        POOL_FLAG_RED_ZONE      = 0x00000002
#define POOL_FLAG_NONE          POOL_FLAG_NONE
#define POOL_FLAG_POISON        POOL_FLAG_POISON
#define POOL_FLAG_RED_ZONE      POOL_FLAG_RED_ZONE
};

struct pool * pool_create (
                const char *name,
                unsigned int size,
                unsigned int align,
                unsigned int count,
                unsigned int flags,
                void (*constructor) (void *ptr, void *context),
                void (*destructor) (void *ptr, void *context),
                void *context);
void pool_destroy (struct pool *pool);

void * pool_malloc (struct pool *pool);
void pool_free (void *ptr);

#endif
