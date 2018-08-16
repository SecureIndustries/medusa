
#if !defined(MEDUSA_POOL_H)
#define MEDUSA_POOL_H

struct medusa_pool;

enum {
        MEDUSA_POOL_FLAG_DEFAULT                = 0x00000000,
        MEDUSA_POOL_FLAG_POISON                 = 0x00000001,
        MEDUSA_POOL_FLAG_RED_ZONE               = 0x00000002,
        MEDUSA_POOL_FLAG_RESERVE_NONE           = 0x00000004,
        MEDUSA_POOL_FLAG_RESERVE_SINGLE         = 0x00000008,
        MEDUSA_POOL_FLAG_RESERVE_HEURISTIC      = 0x00000010,
        MEDUSA_POOL_FLAG_THREAD_SAFE            = 0x00000020
#define MEDUSA_POOL_FLAG_DEFAULT                MEDUSA_POOL_FLAG_DEFAULT
#define MEDUSA_POOL_FLAG_POISON                 MEDUSA_POOL_FLAG_POISON
#define MEDUSA_POOL_FLAG_RED_ZONE               MEDUSA_POOL_FLAG_RED_ZONE
#define MEDUSA_POOL_FLAG_RESERVE_NONE           MEDUSA_POOL_FLAG_RESERVE_NONE
#define MEDUSA_POOL_FLAG_RESERVE_SINGLE         MEDUSA_POOL_FLAG_RESERVE_SINGLE
#define MEDUSA_POOL_FLAG_RESERVE_HEURISTIC      MEDUSA_POOL_FLAG_RESERVE_HEURISTIC
#define MEDUSA_POOL_FLAG_THREAD_SAFE            MEDUSA_POOL_FLAG_THREAD_SAFE
};

struct medusa_pool * medusa_pool_create (
                const char *name,
                unsigned int size,
                unsigned int align,
                unsigned int count,
                unsigned int flags,
                void (*constructor) (void *ptr, void *context),
                void (*destructor) (void *ptr, void *context),
                void *context);
void medusa_pool_destroy (struct medusa_pool *pool);

void * medusa_pool_malloc (struct medusa_pool *pool);
void medusa_pool_free (void *ptr);

#endif
