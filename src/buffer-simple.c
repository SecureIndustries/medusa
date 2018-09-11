
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
#include "buffer-simple.h"
#include "buffer-simple-struct.h"

#define MIN(a, b)                               (((a) < (b)) ? (a) : (b))

#define MEDUSA_BUFFER_USE_POOL      1
#if defined(MEDUSA_BUFFER_USE_POOL) && (MEDUSA_BUFFER_USE_POOL == 1)
static struct medusa_pool *g_pool_buffer_simple;
#endif

static int simple_buffer_resize (struct medusa_buffer *buffer, int64_t size)
{
        void *data;
        unsigned int s;
        struct medusa_buffer_simple *simple = (struct medusa_buffer_simple *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(simple)) {
                return -EINVAL;
        }
        if (size < 0) {
                return -EINVAL;
        }
        if (simple->size >= size) {
                return 0;
        }
        s = simple->grow;
        while (s < size) {
                s += simple->grow;
        }
        data = realloc(simple->data, size);
        if (data == NULL) {
                data = malloc(size);
                if (data == NULL) {
                        return -ENOMEM;
                }
                if (simple->length > 0) {
                        memcpy(data, simple->data, simple->length);
                }
                free(simple->data);
                simple->data = data;
        } else {
                simple->data = data;
        }
        simple->size = size;
        return 0;
}

static int64_t simple_buffer_get_size (const struct medusa_buffer *buffer)
{
        struct medusa_buffer_simple *simple = (struct medusa_buffer_simple *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(simple)) {
                return -EINVAL;
        }
        return simple->size;
}

static int64_t simple_buffer_get_length (const struct medusa_buffer *buffer)
{
        struct medusa_buffer_simple *simple = (struct medusa_buffer_simple *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(simple)) {
                return -EINVAL;
        }
        return simple->length;
}

static int simple_buffer_prepend (struct medusa_buffer *buffer, const void *data, int64_t length)
{
        int rc;
        struct medusa_buffer_simple *simple = (struct medusa_buffer_simple *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(simple)) {
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
        rc = simple_buffer_resize(buffer, simple->length + length);
        if (rc < 0) {
                return rc;
        }
        memmove(simple->data + length, simple->data, simple->length);
        memcpy(simple->data, data, length);
        simple->length += length;
        return length;
}

static int simple_buffer_append (struct medusa_buffer *buffer, const void *data, int64_t length)
{
        int rc;
        struct medusa_buffer_simple *simple = (struct medusa_buffer_simple *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(simple)) {
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
        rc = simple_buffer_resize(buffer, simple->length + length);
        if (rc < 0) {
                return rc;
        }
        memcpy(simple->data + simple->length, data, length);
        simple->length += length;
        return length;
}

static int simple_buffer_vprintf (struct medusa_buffer *buffer, const char *format, va_list va)
{
        int rc;
        int size;
        va_list vs;
        struct medusa_buffer_simple *simple = (struct medusa_buffer_simple *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(simple)) {
                return -EINVAL;
        }
        va_copy(vs, va);
        size = vsnprintf(NULL, 0, format, vs);
        if (size < 0) {
                va_end(vs);
                return -EIO;
        }
        rc = simple_buffer_resize(buffer, simple->length + size + 1);
        if (rc < 0) {
                va_end(vs);
                return rc;
        }
        va_end(vs);
        va_copy(vs, va);
        rc = vsnprintf(simple->data + simple->length, size + 1, format, vs);
        if (rc <= 0) {
                va_end(vs);
                return -EIO;
        }
        simple->length += rc;
        va_end(vs);
        return rc;
}

static int simple_buffer_reserve (struct medusa_buffer *buffer, int64_t length, struct medusa_buffer_iovec *iovecs, int niovecs)
{
        int rc;
        struct medusa_buffer_simple *simple = (struct medusa_buffer_simple *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(simple)) {
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
        rc = simple_buffer_resize(buffer, simple->length + length);
        if (rc < 0) {
                return rc;
        }
        iovecs[0].data = simple->data + simple->length;
        iovecs[0].length = simple->size - simple->length;
        return 1;
}

static int simple_buffer_commit (struct medusa_buffer *buffer, const struct medusa_buffer_iovec *iovecs, int niovecs)
{
        struct medusa_buffer_simple *simple = (struct medusa_buffer_simple *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(simple)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(iovecs)) {
                return -EINVAL;
        }
        if (niovecs == 0) {
                return 0;
        }
        if (niovecs != 1) {
                return -EINVAL;
        }
        if ((simple->data > iovecs[0].data) ||
            (simple->data + simple->length > iovecs[0].data) ||
            (simple->data + simple->size < iovecs[0].data + iovecs[0].length)) {
                return -EINVAL;
        }
        simple->length += iovecs->length;
        return niovecs;
}

static int simple_buffer_peek (struct medusa_buffer *buffer, int64_t offset, int64_t length, struct medusa_buffer_iovec *iovecs, int niovecs)
{
        struct medusa_buffer_simple *simple = (struct medusa_buffer_simple *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(simple)) {
                return -EINVAL;
        }
        if (offset < 0) {
                return -EINVAL;
        }
        if (niovecs < 0) {
                return -EINVAL;
        }
        if (length < 0) {
                length = simple->length;
        } else {
                length = MIN(length, simple->length);
        }
        if (length == 0) {
                return 0;
        }
        if (niovecs == 0) {
                return 1;
        }
        iovecs[0].data = simple->data;
        iovecs[0].length = length;
        return 1;
}

static int simple_buffer_choke (struct medusa_buffer *buffer, int64_t length)
{
        struct medusa_buffer_simple *simple = (struct medusa_buffer_simple *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(simple)) {
                return -EINVAL;
        }
        if (length < 0) {
                length = simple->length;
        }
        if (simple->length < length) {
                length = simple->length;
        }
        if (simple->length > length) {
                memmove(simple->data, simple->data + length, simple->length - length);
                simple->length -= length;
        } else {
                simple->length = 0;
        }
        return 0;
}

static int simple_buffer_reset (struct medusa_buffer *buffer)
{
        struct medusa_buffer_simple *simple = (struct medusa_buffer_simple *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(simple)) {
                return -EINVAL;
        }
        simple->length = 0;
        return 0;
}

static void simple_buffer_destroy (struct medusa_buffer *buffer)
{
        struct medusa_buffer_simple *simple = (struct medusa_buffer_simple *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(simple)) {
                return;;
        }
        if (simple->data != NULL) {
                free(simple->data);
        }
#if defined(MEDUSA_BUFFER_USE_POOL) && (MEDUSA_BUFFER_USE_POOL == 1)
        medusa_pool_free(simple);
#else
        free(simple);
#endif
}

const struct medusa_buffer_backend simple_buffer_backend = {
        .get_size       = simple_buffer_get_size,
        .get_length     = simple_buffer_get_length,

        .prepend        = simple_buffer_prepend,
        .append         = simple_buffer_append,
        .vprintf        = simple_buffer_vprintf,

        .reserve        = simple_buffer_reserve,
        .commit         = simple_buffer_commit,

        .peek           = simple_buffer_peek,

        .choke          = simple_buffer_choke,

        .reset          = simple_buffer_reset,

        .destroy        = simple_buffer_destroy
};

int medusa_buffer_simple_init_options_default (struct medusa_buffer_simple_init_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_buffer_simple_init_options));
        options->flags = MEDUSA_BUFFER_SIMPLE_FLAG_DEFAULT;
        options->grow = MEDUSA_BUFFER_SIMPLE_DEFAULT_GROW;
        return 0;
}

struct medusa_buffer * medusa_buffer_simple_create (unsigned int flags, unsigned int grow)
{
        int rc;
        struct medusa_buffer_simple_init_options options;
        rc = medusa_buffer_simple_init_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.flags = flags;
        options.grow = grow;
        return medusa_buffer_simple_create_with_options(&options);

}

struct medusa_buffer * medusa_buffer_simple_create_with_options (const struct medusa_buffer_simple_init_options *options)
{
        struct medusa_buffer_simple *simple;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
#if defined(MEDUSA_BUFFER_USE_POOL) && (MEDUSA_BUFFER_USE_POOL == 1)
        simple = medusa_pool_malloc(g_pool_buffer_simple);
#else
        simple = malloc(sizeof(struct medusa_buffer_simple));
#endif
        if (MEDUSA_IS_ERR_OR_NULL(simple)) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(simple, 0, sizeof(struct medusa_buffer_simple));
        simple->grow = options->grow;
        if (simple->grow <= 0) {
                simple->grow = MEDUSA_BUFFER_SIMPLE_DEFAULT_GROW;
        }
        simple->buffer.backend = &simple_buffer_backend;
        return &simple->buffer;
}

__attribute__ ((constructor)) static void buffer_simple_constructor (void)
{
#if defined(MEDUSA_BUFFER_USE_POOL) && (MEDUSA_BUFFER_USE_POOL == 1)
        g_pool_buffer_simple = medusa_pool_create("medusa-buffer-simple", sizeof(struct medusa_buffer_simple), 0, 0, MEDUSA_POOL_FLAG_DEFAULT | MEDUSA_POOL_FLAG_THREAD_SAFE, NULL, NULL, NULL);
#endif
}

__attribute__ ((destructor)) static void buffer_simple_destructor (void)
{
#if defined(MEDUSA_BUFFER_USE_POOL) && (MEDUSA_BUFFER_USE_POOL == 1)
        if (g_pool_buffer_simple != NULL) {
                medusa_pool_destroy(g_pool_buffer_simple);
        }
#endif
}
