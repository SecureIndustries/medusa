
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>

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
#endif

static int chunked_buffer_resize (struct medusa_buffer *buffer, int64_t size)
{
        void *data;
        unsigned int s;
        struct medusa_buffer_chunked *chunked = (struct medusa_buffer_chunked *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(chunked)) {
                return -EINVAL;
        }
        if (size < 0) {
                return -EINVAL;
        }
        if (chunked->size >= size) {
                return 0;
        }
        s = chunked->grow;
        while (s < size) {
                s += chunked->grow;
        }
        data = realloc(chunked->data, size);
        if (data == NULL) {
                data = malloc(size);
                if (data == NULL) {
                        return -ENOMEM;
                }
                if (chunked->length > 0) {
                        memcpy(data, chunked->data, chunked->length);
                }
                free(chunked->data);
                chunked->data = data;
        } else {
                chunked->data = data;
        }
        chunked->size = size;
        return 0;
}

static int64_t chunked_buffer_get_size (const struct medusa_buffer *buffer)
{
        struct medusa_buffer_chunked *chunked = (struct medusa_buffer_chunked *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(chunked)) {
                return -EINVAL;
        }
        return chunked->size;
}

static int64_t chunked_buffer_get_length (const struct medusa_buffer *buffer)
{
        struct medusa_buffer_chunked *chunked = (struct medusa_buffer_chunked *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(chunked)) {
                return -EINVAL;
        }
        return chunked->length;
}

static int chunked_buffer_prepend (struct medusa_buffer *buffer, const void *data, int64_t length)
{
        int rc;
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
        rc = chunked_buffer_resize(buffer, chunked->length + length);
        if (rc < 0) {
                return rc;
        }
        memmove(chunked->data + length, chunked->data, chunked->length);
        memcpy(chunked->data, data, length);
        chunked->length += length;
        return length;
}

static int chunked_buffer_append (struct medusa_buffer *buffer, const void *data, int64_t length)
{
        int rc;
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
        rc = chunked_buffer_resize(buffer, chunked->length + length);
        if (rc < 0) {
                return rc;
        }
        memcpy(chunked->data + chunked->length, data, length);
        chunked->length += length;
        return length;
}

static int chunked_buffer_vprintf (struct medusa_buffer *buffer, const char *format, va_list va)
{
        int rc;
        int size;
        va_list vs;
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
        rc = chunked_buffer_resize(buffer, chunked->length + size + 1);
        if (rc < 0) {
                va_end(vs);
                return rc;
        }
        va_end(vs);
        va_copy(vs, va);
        rc = vsnprintf(chunked->data + chunked->length, size + 1, format, vs);
        if (rc <= 0) {
                va_end(vs);
                return -EIO;
        }
        chunked->length += rc;
        va_end(vs);
        return rc;
}

static int chunked_buffer_reserve (struct medusa_buffer *buffer, int64_t length, struct medusa_buffer_iovec *iovecs, int niovecs)
{
        int rc;
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
                return 1;
        }
        rc = chunked_buffer_resize(buffer, chunked->length + length);
        if (rc < 0) {
                return rc;
        }
        iovecs[0].data = chunked->data + chunked->length;
        iovecs[0].length = chunked->size - chunked->length;
        return 1;
}

static int chunked_buffer_commit (struct medusa_buffer *buffer, const struct medusa_buffer_iovec *iovecs, int niovecs)
{
        struct medusa_buffer_chunked *chunked = (struct medusa_buffer_chunked *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(chunked)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(iovecs)) {
                return -EINVAL;
        }
        if (niovecs != 1) {
                return -EINVAL;
        }
        if ((chunked->data > iovecs[0].data) ||
            (chunked->data + chunked->size < iovecs[0].data + iovecs[0].length)) {
                return -EINVAL;
        }
        chunked->length += iovecs->length;
        return 0;
}

static int chunked_buffer_peek (struct medusa_buffer *buffer, int64_t offset, int64_t length, struct medusa_buffer_iovec *iovecs, int niovecs)
{
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
        if (niovecs == 0) {
                return 1;
        }
        if (length < 0) {
                length = chunked->length;
        } else {
                length = MIN(length, chunked->length);
        }
        if (length == 0) {
                return 0;
        }
        iovecs[0].data = chunked->data;
        iovecs[0].length = length;
        return 1;
}

static int chunked_buffer_choke (struct medusa_buffer *buffer, int64_t length)
{
        struct medusa_buffer_chunked *chunked = (struct medusa_buffer_chunked *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(chunked)) {
                return -EINVAL;
        }
        if (length < 0) {
                length = chunked->length;
        }
        if (chunked->length < length) {
                length = chunked->length;
        }
        if (chunked->length > length) {
                memmove(chunked->data, chunked->data + length, chunked->length - length);
                chunked->length -= length;
        } else {
                chunked->length = 0;
        }
        return 0;
}

static int chunked_buffer_reset (struct medusa_buffer *buffer)
{
        struct medusa_buffer_chunked *chunked = (struct medusa_buffer_chunked *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(chunked)) {
                return -EINVAL;
        }
        chunked->length = 0;
        return 0;
}

static void chunked_buffer_destroy (struct medusa_buffer *buffer)
{
        struct medusa_buffer_chunked *chunked = (struct medusa_buffer_chunked *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(chunked)) {
                return;;
        }
        if (chunked->data != NULL) {
                free(chunked->data);
        }
#if defined(MEDUSA_BUFFER_USE_POOL) && (MEDUSA_BUFFER_USE_POOL == 1)
        medusa_pool_free(chunked);
#else
        free(chunked);
#endif
}

const struct medusa_buffer_backend chunked_buffer_backend = {
        .resize         = chunked_buffer_resize,

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
        options->grow = MEDUSA_BUFFER_CHUNKED_DEFAULT_GROW;
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
        options.grow = grow;
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
        chunked->grow = options->grow;
        if (chunked->grow <= 0) {
                chunked->grow = MEDUSA_BUFFER_CHUNKED_DEFAULT_GROW;
        }
        chunked->buffer.backend = &chunked_buffer_backend;
        return &chunked->buffer;
}

__attribute__ ((constructor)) static void buffer_chunked_constructor (void)
{
#if defined(MEDUSA_BUFFER_USE_POOL) && (MEDUSA_BUFFER_USE_POOL == 1)
        g_pool_buffer_chunked = medusa_pool_create("medusa-buffer-chunked", sizeof(struct medusa_buffer_chunked), 0, 0, MEDUSA_POOL_FLAG_DEFAULT | MEDUSA_POOL_FLAG_THREAD_SAFE, NULL, NULL, NULL);
#endif
}

__attribute__ ((destructor)) static void buffer_chunked_destructor (void)
{
#if defined(MEDUSA_BUFFER_USE_POOL) && (MEDUSA_BUFFER_USE_POOL == 1)
        if (g_pool_buffer_chunked != NULL) {
                medusa_pool_destroy(g_pool_buffer_chunked);
        }
#endif
}
