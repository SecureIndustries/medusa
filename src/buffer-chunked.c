
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>

#include "queue.h"

#include "error.h"
#include "pool.h"
#include "buffer.h"
#include "buffer-struct.h"
#include "buffer-chunked.h"
#include "buffer-chunked-struct.h"

#define MIN(a, b)                               (((a) < (b)) ? (a) : (b))

#define MEDUSA_BUFFER_USE_POOL      1
#if defined(MEDUSA_BUFFER_USE_POOL) && (MEDUSA_BUFFER_USE_POOL == 1)
static struct medusa_pool *g_pool_buffer_chunked;
static struct medusa_pool *g_pool_buffer_chunked_entry_128;
static struct medusa_pool *g_pool_buffer_chunked_entry_256;
static struct medusa_pool *g_pool_buffer_chunked_entry_512;
static struct medusa_pool *g_pool_buffer_chunked_entry_1024;
#endif

static int chunked_buffer_resize (struct medusa_buffer *buffer, int64_t size)
{
        unsigned int i;
        unsigned int c;
        unsigned int falloc;
        struct medusa_buffer_chunked_entry *entry;
        struct medusa_buffer_chunked *chunked = (struct medusa_buffer_chunked *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(chunked)) {
                return -EINVAL;
        }
        if (size < 0) {
                return -EINVAL;
        }
        if (chunked->total_size >= size) {
                return 0;
        }
        c  = size - chunked->total_size;
        c += chunked->chunk_size - 1;
        c /= chunked->chunk_size;
        for (i = 0; i < c; i++) {
                falloc = 0;
#if defined(MEDUSA_BUFFER_USE_POOL) && (MEDUSA_BUFFER_USE_POOL == 1)
                if (chunked->chunk_size == 128) {
                        entry = medusa_pool_malloc(g_pool_buffer_chunked_entry_128);
                } else if (chunked->chunk_size == 256) {
                        entry = medusa_pool_malloc(g_pool_buffer_chunked_entry_256);
                } else if (chunked->chunk_size == 512) {
                        entry = medusa_pool_malloc(g_pool_buffer_chunked_entry_512);
                } else if (chunked->chunk_size == 1024) {
                        entry = medusa_pool_malloc(g_pool_buffer_chunked_entry_1024);
                } else {
                        entry = malloc(sizeof(struct medusa_buffer_chunked_entry) + chunked->chunk_size);
                        falloc = MEDUSA_BUFFER_CHUNKED_ENTRY_FLAG_ALLOC;
                }
#else
                entry = malloc(sizeof(struct medusa_buffer_chunked_entry) + chunked->chunk_size);
                falloc = MEDUSA_BUFFER_CHUNKED_ENTRY_FLAG_ALLOC;
#endif
                if (entry == NULL) {
                        return -ENOMEM;
                }
                memset(entry, 0, sizeof(struct medusa_buffer_chunked_entry));
                entry->flags = MEDUSA_BUFFER_CHUNKED_ENTRY_FLAG_DEFAULT | falloc;
                entry->offset = 0;
                entry->length = 0;
                entry->size = chunked->chunk_size;
                TAILQ_INSERT_TAIL(&chunked->entries, entry, list);
                chunked->total_size += entry->size;
        }
        return 0;
}

static int64_t chunked_buffer_get_size (const struct medusa_buffer *buffer)
{
        struct medusa_buffer_chunked *chunked = (struct medusa_buffer_chunked *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(chunked)) {
                return -EINVAL;
        }
        return chunked->total_size;
}

static int64_t chunked_buffer_get_length (const struct medusa_buffer *buffer)
{
        struct medusa_buffer_chunked *chunked = (struct medusa_buffer_chunked *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(chunked)) {
                return -EINVAL;
        }
        return chunked->total_length;
}

static int chunked_buffer_prepend (struct medusa_buffer *buffer, const void *data, int64_t length)
{
        int64_t w;
        int64_t l;
        unsigned int i;
        unsigned int c;
        unsigned int falloc;
        struct medusa_buffer_chunked_entry *entry;
        struct medusa_buffer_chunked *chunked = (struct medusa_buffer_chunked *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(chunked)) {
                return -EINVAL;
        }
        if (length < 0) {
                return -EINVAL;
        }
        if (length == 0) {
                return 0;
        }
        if (MEDUSA_IS_ERR_OR_NULL(data)) {
                return -EINVAL;
        }
        c  = length;
        c += chunked->chunk_size - 1;
        c /= chunked->chunk_size;
        for (i = 0; i < c; i++) {
                falloc = 0;
#if defined(MEDUSA_BUFFER_USE_POOL) && (MEDUSA_BUFFER_USE_POOL == 1)
                if (chunked->chunk_size == 128) {
                        entry = medusa_pool_malloc(g_pool_buffer_chunked_entry_128);
                } else if (chunked->chunk_size == 256) {
                        entry = medusa_pool_malloc(g_pool_buffer_chunked_entry_256);
                } else if (chunked->chunk_size == 512) {
                        entry = medusa_pool_malloc(g_pool_buffer_chunked_entry_512);
                } else if (chunked->chunk_size == 1024) {
                        entry = medusa_pool_malloc(g_pool_buffer_chunked_entry_1024);
                } else {
                        entry = malloc(sizeof(struct medusa_buffer_chunked_entry) + chunked->chunk_size);
                        falloc = MEDUSA_BUFFER_CHUNKED_ENTRY_FLAG_ALLOC;
                }
#else
                entry = malloc(sizeof(struct medusa_buffer_chunked_entry) + chunked->chunk_size);
                falloc = MEDUSA_BUFFER_CHUNKED_ENTRY_FLAG_ALLOC;
#endif
                if (entry == NULL) {
                        return -ENOMEM;
                }
                memset(entry, 0, sizeof(struct medusa_buffer_chunked_entry));
                entry->flags = MEDUSA_BUFFER_CHUNKED_ENTRY_FLAG_DEFAULT | falloc;
                entry->offset = 0;
                entry->length = 0;
                entry->size = chunked->chunk_size;
                TAILQ_INSERT_HEAD(&chunked->entries, entry, list);
                chunked->total_size += entry->size;
        }
        w = 0;
        TAILQ_FOREACH(entry, &chunked->entries, list) {
                if (w == length) {
                        break;
                }
                l = MIN(length - w, entry->size);
                memcpy(entry->data, data + w, l);
                w += l;
                entry->length = l;
                chunked->total_length += l;
        }
        return length;
}

static int chunked_buffer_append (struct medusa_buffer *buffer, const void *data, int64_t length)
{
        int rc;
        int64_t w;
        int64_t l;
        struct medusa_buffer_chunked *chunked = (struct medusa_buffer_chunked *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(chunked)) {
                return -EINVAL;
        }
        if (length < 0) {
                return -EINVAL;
        }
        if (length == 0) {
                return 0;
        }
        if (MEDUSA_IS_ERR_OR_NULL(data)) {
                return -EINVAL;
        }
        rc = chunked_buffer_resize(buffer, chunked->total_length + length);
        if (rc < 0) {
                return rc;
        }
        w = 0;
        while (w != length) {
                if (chunked->active == NULL) {
                        chunked->active = TAILQ_FIRST(&chunked->entries);
                        continue;
                }
                if (chunked->active->size - chunked->active->length <= 0) {
                        chunked->active = TAILQ_NEXT(chunked->active, list);
                        continue;
                }
                l = MIN(length - w, chunked->active->size - chunked->active->length);
                memcpy(chunked->active->data + chunked->active->length, data + w, l);
                w += l;
                chunked->active->length += l;
                chunked->total_length += l;
        }
        return length;
}

static int chunked_buffer_vprintf (struct medusa_buffer *buffer, const char *format, va_list va)
{
        int rc;
        int size;
        va_list vs;
        struct medusa_buffer_chunked_entry *entry;
        struct medusa_buffer_chunked *chunked = (struct medusa_buffer_chunked *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(chunked)) {
                return -EINVAL;
        }
        va_copy(vs, va);
        size = vsnprintf(NULL, 0, format, vs);
        if (size < 0) {
                va_end(vs);
                return -EIO;
        }
        rc = chunked_buffer_resize(buffer, chunked->total_length + size + 1);
        if (rc < 0) {
                va_end(vs);
                return rc;
        }
        va_end(vs);
        if (chunked->active == NULL) {
                chunked->active = TAILQ_FIRST(&chunked->entries);
        }
        if (chunked->active->size - chunked->active->length < size + 1) {
                entry = malloc(sizeof(struct medusa_buffer_chunked_entry) + size + 1);
                if (entry == NULL) {
                        return -ENOMEM;
                }
                memset(entry, 0, sizeof(struct medusa_buffer_chunked_entry));
                entry->flags = MEDUSA_BUFFER_CHUNKED_ENTRY_FLAG_DEFAULT | MEDUSA_BUFFER_CHUNKED_ENTRY_FLAG_ALLOC;
                entry->offset = 0;
                entry->length = 0;
                entry->size = size + 1;
                TAILQ_INSERT_HEAD(&chunked->entries, entry, list);
                chunked->total_size += entry->size;
                chunked->active = entry;
        }
        va_copy(vs, va);
        rc = vsnprintf((char *) chunked->active->data + chunked->active->length, size + 1, format, vs);
        if (rc <= 0) {
                va_end(vs);
                return -EIO;
        }
        chunked->active->length += rc;
        chunked->total_length += rc;
        va_end(vs);
        return rc;
}

static int chunked_buffer_reserve (struct medusa_buffer *buffer, int64_t length, struct medusa_buffer_iovec *iovecs, int niovecs)
{
        int rc;
        int n;
        int64_t w;
        int64_t l;
        unsigned int c;
        struct medusa_buffer_chunked_entry *entry;
        struct medusa_buffer_chunked *chunked = (struct medusa_buffer_chunked *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(chunked)) {
                return -EINVAL;
        }
        if (length < 0) {
                return -EINVAL;
        }
        if (length == 0) {
                return 0;
        }
        if (niovecs < 0) {
                return -EINVAL;
        }
        if (niovecs == 0) {
                c  = length;
                c += chunked->chunk_size - 1;
                c /= chunked->chunk_size;
                return c;
        }
        rc = chunked_buffer_resize(buffer, chunked->total_length + length);
        if (rc < 0) {
                return rc;
        }
        if (chunked->active == NULL) {
                chunked->active = TAILQ_FIRST(&chunked->entries);
        }
        n = 0;
        w = 0;
        entry = chunked->active;
        while (n < niovecs && w != length) {
                if (entry == NULL) {
                        return -EIO;
                }
                if (entry->size - entry->length <= 0) {
                        entry = TAILQ_NEXT(entry, list);
                        continue;
                }
                l = MIN(length - w, entry->size - entry->length);
                w += l;
                iovecs[n].data   = entry->data + entry->length;
                iovecs[n].length = l;
                entry = TAILQ_NEXT(entry, list);
                n += 1;
        }
        return n;
}

static int chunked_buffer_commit (struct medusa_buffer *buffer, const struct medusa_buffer_iovec *iovecs, int niovecs)
{
        int i;
        struct medusa_buffer_chunked *chunked = (struct medusa_buffer_chunked *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(chunked)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(iovecs)) {
                return -EINVAL;
        }
        if (niovecs < 0) {
                return -EINVAL;
        }
        if (niovecs == 0) {
                return 0;
        }
        if (MEDUSA_IS_ERR_OR_NULL(chunked->active)) {
                return -EIO;
        }
        for (i = 0; i < niovecs; i++) {
                if (chunked->active->data > (uint8_t *) iovecs[i].data) {
                        return -EINVAL;
                }
                if (chunked->active->data + chunked->active->length > (uint8_t *) iovecs[i].data) {
                        return -EINVAL;
                }
                if (chunked->active->data + chunked->active->size < (uint8_t *) iovecs[i].data + iovecs[i].length) {
                        return -EINVAL;
                }
                chunked->active->length += iovecs[i].length;
                chunked->active = TAILQ_NEXT(chunked->active, list);
                chunked->total_length += iovecs[i].length;
        }
        return i;
}

static int chunked_buffer_peek (struct medusa_buffer *buffer, int64_t offset, int64_t length, struct medusa_buffer_iovec *iovecs, int niovecs)
{
        int n;
        int64_t w;
        int64_t l;
        unsigned int c;
        struct medusa_buffer_chunked_entry *entry;
        struct medusa_buffer_chunked *chunked = (struct medusa_buffer_chunked *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(chunked)) {
                return -EINVAL;
        }
        if (offset < 0) {
                return -EINVAL;
        }
        if (niovecs < 0) {
                return -EINVAL;
        }
        if (length < 0) {
                length = chunked->total_length;
        } else {
                length = MIN(length, chunked->total_length);
        }
        if (length == 0) {
                return 0;
        }
        if (niovecs == 0) {
                c  = length;
                c += chunked->chunk_size - 1;
                c /= chunked->chunk_size;
                return c;
        }
        n = 0;
        w = 0;
        entry = TAILQ_FIRST(&chunked->entries);
        while (n < niovecs && w != length) {
                if (entry == NULL) {
                        return -EIO;
                }
                if (entry->length - entry->offset <= 0) {
                        entry = TAILQ_NEXT(entry, list);
                        continue;
                }
                l = MIN(length - w, entry->length - entry->offset);
                w += l;
                iovecs[n].data   = entry->data + entry->offset;
                iovecs[n].length = l;
                entry = TAILQ_NEXT(entry, list);
                n += 1;
        }
        return n;
}

static int chunked_buffer_choke (struct medusa_buffer *buffer, int64_t length)
{
        int64_t w;
        int64_t l;
        struct medusa_buffer_chunked_entry *entry;
        struct medusa_buffer_chunked_entry *nentry;
        struct medusa_buffer_chunked *chunked = (struct medusa_buffer_chunked *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(chunked)) {
                return -EINVAL;
        }
        if (length < 0) {
                length = chunked->total_length;
        }
        if (chunked->total_length < length) {
                length = chunked->total_length;
        }
        if (chunked->total_length > length) {
                w = 0;
                TAILQ_FOREACH_SAFE(entry, &chunked->entries, list, nentry) {
                        if (w == length) {
                                break;
                        }
                        l = MIN(length - w, entry->length - entry->offset);
                        if (l < entry->length - entry->offset) {
                                entry->offset += l;
                        } else {
                                if (entry == chunked->active) {
                                        chunked->active = NULL;
                                }
                                TAILQ_REMOVE(&chunked->entries, entry, list);
                                chunked->total_size -= entry->size;
                                if (entry->flags & MEDUSA_BUFFER_CHUNKED_ENTRY_FLAG_ALLOC) {
                                        free(entry);
                                } else {
                                        medusa_pool_free(entry);
                                }
                        }
                        w += l;
                        chunked->total_length -= l;
                }
        } else {
                TAILQ_FOREACH_SAFE(entry, &chunked->entries, list, nentry) {
                        TAILQ_REMOVE(&chunked->entries, entry, list);
                        if (entry->flags & MEDUSA_BUFFER_CHUNKED_ENTRY_FLAG_ALLOC) {
                                free(entry);
                        } else {
                                medusa_pool_free(entry);
                        }
                }
                chunked->total_length = 0;
                chunked->total_size = 0;
                chunked->active = NULL;
        }
        return 0;
}

static int chunked_buffer_reset (struct medusa_buffer *buffer)
{
        struct medusa_buffer_chunked_entry *entry;
        struct medusa_buffer_chunked_entry *nentry;
        struct medusa_buffer_chunked *chunked = (struct medusa_buffer_chunked *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(chunked)) {
                return -EINVAL;
        }
        TAILQ_FOREACH_SAFE(entry, &chunked->entries, list, nentry) {
                TAILQ_REMOVE(&chunked->entries, entry, list);
                if (entry->flags & MEDUSA_BUFFER_CHUNKED_ENTRY_FLAG_ALLOC) {
                        free(entry);
                } else {
                        medusa_pool_free(entry);
                }
        }
        chunked->total_length = 0;
        chunked->total_size = 0;
        chunked->active = NULL;
        return 0;
}

static void chunked_buffer_destroy (struct medusa_buffer *buffer)
{
        struct medusa_buffer_chunked_entry *entry;
        struct medusa_buffer_chunked_entry *nentry;
        struct medusa_buffer_chunked *chunked = (struct medusa_buffer_chunked *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(chunked)) {
                return;;
        }
        TAILQ_FOREACH_SAFE(entry, &chunked->entries, list, nentry) {
                TAILQ_REMOVE(&chunked->entries, entry, list);
                if (entry->flags & MEDUSA_BUFFER_CHUNKED_ENTRY_FLAG_ALLOC) {
                        free(entry);
                } else {
                        medusa_pool_free(entry);
                }
        }
#if defined(MEDUSA_BUFFER_USE_POOL) && (MEDUSA_BUFFER_USE_POOL == 1)
        medusa_pool_free(chunked);
#else
        free(chunked);
#endif
}

const struct medusa_buffer_backend chunked_buffer_backend = {
        .get_size       = chunked_buffer_get_size,
        .get_length     = chunked_buffer_get_length,

        .prepend        = chunked_buffer_prepend,
        .append         = chunked_buffer_append,
        .vprintf        = chunked_buffer_vprintf,

        .reserve        = chunked_buffer_reserve,
        .commit         = chunked_buffer_commit,

        .peek           = chunked_buffer_peek,

        .choke          = chunked_buffer_choke,

        .reset          = chunked_buffer_reset,

        .destroy        = chunked_buffer_destroy
};

int medusa_buffer_chunked_init_options_default (struct medusa_buffer_chunked_init_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_buffer_chunked_init_options));
        options->flags = MEDUSA_BUFFER_CHUNKED_FLAG_DEFAULT;
        options->chunk = MEDUSA_BUFFER_CHUNKED_DEFAULT_CHUNK_SIZE;
        return 0;
}

struct medusa_buffer * medusa_buffer_chunked_create (unsigned int flags, unsigned int grow)
{
        int rc;
        struct medusa_buffer_chunked_init_options options;
        rc = medusa_buffer_chunked_init_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.flags = flags;
        options.chunk = grow;
        return medusa_buffer_chunked_create_with_options(&options);

}

struct medusa_buffer * medusa_buffer_chunked_create_with_options (const struct medusa_buffer_chunked_init_options *options)
{
        struct medusa_buffer_chunked *chunked;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
#if defined(MEDUSA_BUFFER_USE_POOL) && (MEDUSA_BUFFER_USE_POOL == 1)
        chunked = medusa_pool_malloc(g_pool_buffer_chunked);
#else
        chunked = malloc(sizeof(struct medusa_buffer_chunked));
#endif
        if (MEDUSA_IS_ERR_OR_NULL(chunked)) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(chunked, 0, sizeof(struct medusa_buffer_chunked));
        TAILQ_INIT(&chunked->entries);
        chunked->chunk_size = options->chunk;
        if (chunked->chunk_size <= 0) {
                chunked->chunk_size = MEDUSA_BUFFER_CHUNKED_DEFAULT_CHUNK_SIZE;
        }
        chunked->buffer.backend = &chunked_buffer_backend;
        return &chunked->buffer;
}

__attribute__ ((constructor)) static void buffer_chunked_constructor (void)
{
#if defined(MEDUSA_BUFFER_USE_POOL) && (MEDUSA_BUFFER_USE_POOL == 1)
        g_pool_buffer_chunked = medusa_pool_create("medusa-buffer-chunked", sizeof(struct medusa_buffer_chunked), 0, 0, MEDUSA_POOL_FLAG_DEFAULT | MEDUSA_POOL_FLAG_THREAD_SAFE, NULL, NULL, NULL);
        g_pool_buffer_chunked_entry_128 = medusa_pool_create("medusa-buffer-chunked-entry-128", sizeof(struct medusa_buffer_chunked_entry) + 128, 0, 128, MEDUSA_POOL_FLAG_DEFAULT | MEDUSA_POOL_FLAG_THREAD_SAFE, NULL, NULL, NULL);
        g_pool_buffer_chunked_entry_256 = medusa_pool_create("medusa-buffer-chunked-entry-256", sizeof(struct medusa_buffer_chunked_entry) + 256, 0, 128, MEDUSA_POOL_FLAG_DEFAULT | MEDUSA_POOL_FLAG_THREAD_SAFE, NULL, NULL, NULL);
        g_pool_buffer_chunked_entry_512 = medusa_pool_create("medusa-buffer-chunked-entry-512", sizeof(struct medusa_buffer_chunked_entry) + 512, 0, 128, MEDUSA_POOL_FLAG_DEFAULT | MEDUSA_POOL_FLAG_THREAD_SAFE, NULL, NULL, NULL);
        g_pool_buffer_chunked_entry_1024 = medusa_pool_create("medusa-buffer-chunked-entry-1024", sizeof(struct medusa_buffer_chunked_entry) + 1024, 0, 128, MEDUSA_POOL_FLAG_DEFAULT | MEDUSA_POOL_FLAG_THREAD_SAFE, NULL, NULL, NULL);
#endif
}

__attribute__ ((destructor)) static void buffer_chunked_destructor (void)
{
#if defined(MEDUSA_BUFFER_USE_POOL) && (MEDUSA_BUFFER_USE_POOL == 1)
        if (g_pool_buffer_chunked != NULL) {
                medusa_pool_destroy(g_pool_buffer_chunked);
        }
        if (g_pool_buffer_chunked_entry_128 != NULL) {
                medusa_pool_destroy(g_pool_buffer_chunked_entry_128);
        }
        if (g_pool_buffer_chunked_entry_256 != NULL) {
                medusa_pool_destroy(g_pool_buffer_chunked_entry_256);
        }
        if (g_pool_buffer_chunked_entry_512 != NULL) {
                medusa_pool_destroy(g_pool_buffer_chunked_entry_512);
        }
        if (g_pool_buffer_chunked_entry_1024 != NULL) {
                medusa_pool_destroy(g_pool_buffer_chunked_entry_1024);
        }
#endif
}
