
#if !defined(MEDUSA_ERROR_H)
#define MEDUSA_ERROR_H

#include <string.h>

#define MAX_ERRNO       4095

#define MEDUSA_IS_ERR_VALUE(x) ((unsigned long) (void *) (x) >= (unsigned long) -MAX_ERRNO)

static inline void * MEDUSA_ERR_PTR (long error)
{
        return (void *) error;
}

static inline long MEDUSA_PTR_ERR (const void *ptr)
{
        return (long) ptr;
}

static inline int MEDUSA_IS_ERR (const void *ptr)
{
        return MEDUSA_IS_ERR_VALUE((unsigned long) ptr);
}

static inline int MEDUSA_IS_ERR_OR_NULL (const void *ptr)
{
        return (!ptr) || MEDUSA_IS_ERR_VALUE((unsigned long) ptr);
}

static inline char * medusa_strerror (int error)
{
        if (error < 0) {
                return strerror(-error);
        } else {
                return strerror(error);
        }
}

#endif
