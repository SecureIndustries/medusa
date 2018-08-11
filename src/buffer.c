
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

#define MEDUSA_BUFFER_USE_POOL      1
#if defined(MEDUSA_BUFFER_USE_POOL) && (MEDUSA_BUFFER_USE_POOL == 1)
static struct medusa_pool *g_pool;
#endif

__attribute__ ((visibility ("default"))) int medusa_buffer_resize (struct medusa_buffer *buffer, int size)
{
        void *data;
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (buffer->size >= size) {
                return 0;
        }
        data = realloc(buffer->buffer, size);
        if (data == NULL) {
                data = malloc(size);
                if (data == NULL) {
                        return -ENOMEM;
                }
                if (buffer->length > 0) {
                        memcpy(data, buffer->buffer, buffer->length);
                }
                free(buffer->buffer);
                buffer->buffer = data;
        } else {
                buffer->buffer = data;
        }
        buffer->size = size;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_buffer_grow (struct medusa_buffer *buffer, int size)
{
        return medusa_buffer_resize(buffer, medusa_buffer_length(buffer) + size);
}

__attribute__ ((visibility ("default"))) void medusa_buffer_reset (struct medusa_buffer *buffer)
{
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return;
        }
        buffer->length = 0;
}

__attribute__ ((visibility ("default"))) void * medusa_buffer_base (const struct medusa_buffer *buffer)
{
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return buffer->buffer;
}

__attribute__ ((visibility ("default"))) int medusa_buffer_length (const struct medusa_buffer *buffer)
{
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        return buffer->length;
}

__attribute__ ((visibility ("default"))) int medusa_buffer_set_length (struct medusa_buffer *buffer, int length)
{
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (length > buffer->size) {
                return -EINVAL;
        }
        buffer->length = length;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_buffer_push (struct medusa_buffer *buffer, const void *data, int length)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
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
        rc = medusa_buffer_resize(buffer, buffer->length + length);
        if (rc < 0) {
                return rc;
        }
        memcpy(buffer->buffer + buffer->length, data, length);
        buffer->length += length;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_buffer_printf (struct medusa_buffer *buffer, const char *format, ...)
{
        int rc;
        int size;
        va_list va;
        va_start(va, format);
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                va_end(va);
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(format)) {
                va_end(va);
                return -EINVAL;
        }
        size = vsnprintf(NULL, 0, format, va);
        if (size < 0) {
                va_end(va);
                return -EIO;
        }
        rc = medusa_buffer_grow(buffer, size + 1);
        if (rc < 0) {
                va_end(va);
                return rc;
        }
        va_end(va);
        va_start(va, format);
        rc = vsnprintf(medusa_buffer_base(buffer) + medusa_buffer_length(buffer), size + 1, format, va);
        if (rc <= 0) {
                va_end(va);
                return -EIO;
        }
        buffer->length += rc;
        va_end(va);
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_buffer_vprintf (struct medusa_buffer *buffer, const char *format, va_list va)
{
        int rc;
        int size;
        va_list vs;
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        va_copy(vs, va);
        size = vsnprintf(NULL, 0, format, vs);
        if (size < 0) {
                va_end(vs);
                return -EIO;
        }
        rc = medusa_buffer_grow(buffer, size + 1);
        if (rc < 0) {
                va_end(vs);
                return rc;
        }
        va_end(vs);
        va_copy(vs, va);
        rc = vsnprintf(medusa_buffer_base(buffer) + medusa_buffer_length(buffer), size + 1, format, vs);
        if (rc <= 0) {
                va_end(vs);
                return -EIO;
        }
        buffer->length += rc;
        va_end(vs);
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_buffer_eat (struct medusa_buffer *buffer, int length)
{
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (length < 0) {
                length = buffer->length;
        }
        if (buffer->length < length) {
                length = buffer->length;
        }
        if (buffer->length > length) {
                memmove(buffer->buffer, buffer->buffer + length, buffer->length - length);
                buffer->length -= length;
        } else {
                buffer->length = 0;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_buffer_size (const struct medusa_buffer *buffer)
{
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        return buffer->size;
}

__attribute__ ((visibility ("default"))) int medusa_buffer_init (struct medusa_buffer *buffer)
{
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        memset(buffer, 0, sizeof(struct medusa_buffer));
        return 0;
}

__attribute__ ((visibility ("default"))) void medusa_buffer_uninit (struct medusa_buffer *buffer)
{
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return;
        }
        if (buffer->buffer != NULL) {
                free(buffer->buffer);
        }
}

__attribute__ ((visibility ("default"))) void medusa_buffer_destroy (struct medusa_buffer *buffer)
{
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return;
        }
        if (buffer->buffer != NULL) {
                free(buffer->buffer);
        }
#if defined(MEDUSA_BUFFER_USE_POOL) && (MEDUSA_BUFFER_USE_POOL == 1)
        medusa_pool_free(buffer);
#else
        free(buffer);
#endif
}

__attribute__ ((visibility ("default"))) struct medusa_buffer * medusa_buffer_create (void)
{
        struct medusa_buffer *buffer;
#if defined(MEDUSA_BUFFER_USE_POOL) && (MEDUSA_BUFFER_USE_POOL == 1)
        buffer = medusa_pool_malloc(g_pool);
#else
        buffer = malloc(sizeof(struct medusa_buffer));
#endif
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(buffer, 0, sizeof(struct medusa_buffer));
        return buffer;
}

__attribute__ ((constructor)) static void buffer_constructor (void)
{
#if defined(MEDUSA_BUFFER_USE_POOL) && (MEDUSA_BUFFER_USE_POOL == 1)
        g_pool = medusa_pool_create("medusa-buffer", sizeof(struct medusa_buffer), 0, 0, MEDUSA_POOL_FLAG_DEFAULT, NULL, NULL, NULL);
#endif
}

__attribute__ ((destructor)) static void buffer_destructor (void)
{
#if defined(MEDUSA_BUFFER_USE_POOL) && (MEDUSA_BUFFER_USE_POOL == 1)
        if (g_pool != NULL) {
                medusa_pool_destroy(g_pool);
        }
#endif
}
