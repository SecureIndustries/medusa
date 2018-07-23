
#if !defined(MEDUSA_POOL_H)
#define MEDUSA_POOL_H

struct pool;

enum {
        POOL_FLAG_DEFAULT               = 0x00000000,
        POOL_FLAG_POISON                = 0x00000001,
        POOL_FLAG_RED_ZONE              = 0x00000002,
        POOL_FLAG_RESERVE_NONE          = 0x00000004,
        POOL_FLAG_RESERVE_SINGLE        = 0x00000008,
        POOL_FLAG_RESERVE_HEURISTIC     = 0x00000010,
#define POOL_FLAG_DEFAULT               POOL_FLAG_DEFAULT
#define POOL_FLAG_POISON                POOL_FLAG_POISON
#define POOL_FLAG_RED_ZONE              POOL_FLAG_RED_ZONE
#define POOL_FLAG_RESERVE_NONE          POOL_FLAG_RESERVE_NONE
#define POOL_FLAG_RESERVE_SINGLE        POOL_FLAG_RESERVE_SINGLE
#define POOL_FLAG_RESERVE_HEURISTIC     POOL_FLAG_RESERVE_HEURISTIC
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
