
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>

#include <sys/uio.h>

#include "error.h"
#include "buffer.h"
#include "buffer-struct.h"
#include "buffer-simple.h"

__attribute__ ((visibility ("default"))) int medusa_buffer_reset (struct medusa_buffer *buffer)
{
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(buffer->backend)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(buffer->backend->reset)) {
                return -EINVAL;
        }
        return buffer->backend->reset(buffer);
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_get_size (const struct medusa_buffer *buffer)
{
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(buffer->backend)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(buffer->backend->get_size)) {
                return -EINVAL;
        }
        return buffer->backend->get_size(buffer);
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_get_length (const struct medusa_buffer *buffer)
{
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(buffer->backend)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(buffer->backend->get_length)) {
                return -EINVAL;
        }
        return buffer->backend->get_length(buffer);
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_prepend (struct medusa_buffer *buffer, const void *data, int64_t length)
{
        int64_t niovecs;
        struct iovec iovecs[1];
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(data)) {
                return -EINVAL;
        }
        if (length < 0) {
                return -EINVAL;
        }
        if (length == 0) {
                return 0;
        }
        niovecs = 1;
        iovecs[0].iov_base = (void *) data;
        iovecs[0].iov_len  = length;
        return medusa_buffer_prependv(buffer, iovecs, niovecs);
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_prependv (struct medusa_buffer *buffer, const struct iovec *iovecs, int64_t niovecs)
{
        return medusa_buffer_insertv(buffer, 0, iovecs, niovecs);
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_append (struct medusa_buffer *buffer, const void *data, int64_t length)
{
        int64_t niovecs;
        struct iovec iovecs[1];
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(data)) {
                return -EINVAL;
        }
        if (length < 0) {
                return -EINVAL;
        }
        if (length == 0) {
                return 0;
        }
        niovecs = 1;
        iovecs[0].iov_base = (void *) data;
        iovecs[0].iov_len  = length;
        return medusa_buffer_appendv(buffer, iovecs, niovecs);
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_appendv (struct medusa_buffer *buffer, const struct iovec *iovecs, int64_t niovecs)
{
        return medusa_buffer_insertv(buffer, medusa_buffer_get_length(buffer), iovecs, niovecs);
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_insert (struct medusa_buffer *buffer, int64_t offset, const void *data, int64_t length)
{
        int64_t niovecs;
        struct iovec iovecs[1];
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(data)) {
                return -EINVAL;
        }
        if (length < 0) {
                return -EINVAL;
        }
        if (length == 0) {
                return 0;
        }
        niovecs = 1;
        iovecs[0].iov_base = (void *) data;
        iovecs[0].iov_len  = length;
        return medusa_buffer_insertv(buffer, offset, iovecs, niovecs);
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_insertv (struct medusa_buffer *buffer, int64_t offset, const struct iovec *iovecs, int64_t niovecs)
{
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(buffer->backend)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(buffer->backend->insertv)) {
                return -EINVAL;
        }
        if (niovecs < 0) {
                return -EINVAL;
        }
        if (niovecs == 0) {
                return 0;
        }
        if (MEDUSA_IS_ERR_OR_NULL(iovecs)) {
                return -EINVAL;
        }
        return buffer->backend->insertv(buffer, offset, iovecs, niovecs);
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_prependf (struct medusa_buffer *buffer, const char *format, ...)
{
        int rc;
        va_list ap;
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(format)) {
                return -EINVAL;
        }
        va_start(ap, format);
        rc = medusa_buffer_prependfv(buffer, format, ap);
        va_end(ap);
        return rc;
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_prependfv (struct medusa_buffer *buffer, const char *format, va_list va)
{
        return medusa_buffer_insertfv(buffer, 0, format, va);
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_appendf (struct medusa_buffer *buffer, const char *format, ...)
{
        int rc;
        va_list ap;
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(format)) {
                return -EINVAL;
        }
        va_start(ap, format);
        rc = medusa_buffer_appendfv(buffer, format, ap);
        va_end(ap);
        return rc;
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_appendfv (struct medusa_buffer *buffer, const char *format, va_list va)
{
        return medusa_buffer_insertfv(buffer, medusa_buffer_get_length(buffer), format, va);
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_insertf (struct medusa_buffer *buffer, int64_t offset, const char *format, ...)
{
        int rc;
        va_list ap;
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(format)) {
                return -EINVAL;
        }
        va_start(ap, format);
        rc = medusa_buffer_insertfv(buffer, offset, format, ap);
        va_end(ap);
        return rc;
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_insertfv (struct medusa_buffer *buffer, int64_t offset, const char *format, va_list va)
{
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(buffer->backend)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(buffer->backend->insertfv)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(format)) {
                return -EINVAL;
        }
        return buffer->backend->insertfv(buffer, offset, format, va);
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_printf (struct medusa_buffer *buffer, const char *format, ...)
{
        int rc;
        va_list ap;
        va_start(ap, format);
        rc = medusa_buffer_vprintf(buffer, format, ap);
        va_end(ap);
        return rc;
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_vprintf (struct medusa_buffer *buffer, const char *format, va_list va)
{
        return medusa_buffer_appendfv(buffer, format, va);
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_reserve (struct medusa_buffer *buffer, int64_t length, struct iovec *iovecs, int64_t niovecs)
{
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(buffer->backend)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(buffer->backend->reserve)) {
                return -EINVAL;
        }
        if (length < 0) {
                return -EINVAL;
        }
        if (niovecs < 0) {
                return -EINVAL;
        }
        return buffer->backend->reserve(buffer, length, iovecs, niovecs);
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_commit (struct medusa_buffer *buffer, const struct iovec *iovecs, int64_t niovecs)
{
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(buffer->backend)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(buffer->backend->commit)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(iovecs)) {
                return -EINVAL;
        }
        if (niovecs < 0) {
                return -EINVAL;
        }
        return buffer->backend->commit(buffer, iovecs, niovecs);
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_peek (struct medusa_buffer *buffer, int64_t offset, int64_t length, struct iovec *iovecs, int64_t niovecs)
{
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(buffer->backend)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(buffer->backend->peek)) {
                return -EINVAL;
        }
        return buffer->backend->peek(buffer, offset, length, iovecs, niovecs);
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_choke (struct medusa_buffer *buffer, int64_t offset, int64_t length)
{
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(buffer->backend)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(buffer->backend->choke)) {
                return -EINVAL;
        }
        return buffer->backend->choke(buffer, offset, length);
}

int medusa_buffer_memcmp (struct medusa_buffer *buffer, int64_t offset, const void *data, int64_t length)
{
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(data)) {
                return -EINVAL;
        }
        if (length <= 0) {
                return -EINVAL;
        }
        (void) offset;
        return -EIO;
}

int64_t medusa_buffer_memmem (struct medusa_buffer *buffer, int64_t offset, const void *data, int64_t length)
{
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(data)) {
                return -EINVAL;
        }
        if (length <= 0) {
                return -EINVAL;
        }
        (void) offset;
        return -EIO;
}

__attribute__ ((visibility ("default"))) int medusa_buffer_init_options_default (struct medusa_buffer_init_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_buffer_init_options));
        options->type = MEDUSA_BUFFER_TYPE_SIMPLE;
        options->flags = MEDUSA_BUFFER_FLAG_DEFAULT;
        options->u.simple.grow_size = MEDUSA_BUFFER_DEFAULT_GROW_SIZE;
        return 0;
}

__attribute__ ((visibility ("default"))) struct medusa_buffer * medusa_buffer_create (unsigned int type)
{
        int rc;
        struct medusa_buffer_init_options options;
        rc = medusa_buffer_init_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.type = type;
        return medusa_buffer_create_with_options(&options);
}

__attribute__ ((visibility ("default"))) struct medusa_buffer * medusa_buffer_create_with_options (const struct medusa_buffer_init_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (options->type == MEDUSA_BUFFER_TYPE_SIMPLE) {
                int rc;
                struct medusa_buffer_simple_init_options simple_options;
                rc = medusa_buffer_simple_init_options_default(&simple_options);
                if (rc < 0) {
                        return MEDUSA_ERR_PTR(rc);
                }
                simple_options.flags = MEDUSA_BUFFER_SIMPLE_FLAG_DEFAULT;
                simple_options.grow = options->u.simple.grow_size;
                return medusa_buffer_simple_create_with_options(&simple_options);
        } else {
                return MEDUSA_ERR_PTR(-ENOENT);
        }
}

__attribute__ ((visibility ("default"))) void medusa_buffer_destroy (struct medusa_buffer *buffer)
{
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return;
        }
        if (MEDUSA_IS_ERR_OR_NULL(buffer->backend)) {
                return;
        }
        if (MEDUSA_IS_ERR_OR_NULL(buffer->backend->destroy)) {
                return;
        }
        buffer->backend->destroy(buffer);
}
