
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <endian.h>
#include <errno.h>

#include <sys/uio.h>

#include "error.h"
#include "buffer.h"
#include "buffer-struct.h"
#include "buffer-simple.h"

#define MIN(a, b)       (((a) < (b)) ? (a) : (b))

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

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_append_uint8 (struct medusa_buffer *buffer, uint8_t value)
{
        return medusa_buffer_append(buffer, &value, sizeof(uint8_t));
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_append_uint8_le (struct medusa_buffer *buffer, uint8_t value)
{
        return medusa_buffer_append(buffer, &value, sizeof(uint8_t));
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_append_uint8_be (struct medusa_buffer *buffer, uint8_t value)
{
        return medusa_buffer_append(buffer, &value, sizeof(uint8_t));
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_append_uint16 (struct medusa_buffer *buffer, uint16_t value)
{
        return medusa_buffer_append(buffer, &value, sizeof(uint16_t));
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_append_uint16_le (struct medusa_buffer *buffer, uint16_t value)
{
        value = htole16(value);
        return medusa_buffer_append(buffer, &value, sizeof(uint16_t));
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_append_uint16_be (struct medusa_buffer *buffer, uint16_t value)
{
        value = htobe16(value);
        return medusa_buffer_append(buffer, &value, sizeof(uint16_t));
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_append_uint32 (struct medusa_buffer *buffer, uint32_t value)
{
        return medusa_buffer_append(buffer, &value, sizeof(uint32_t));
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_append_uint32_le (struct medusa_buffer *buffer, uint32_t value)
{
        value = htole32(value);
        return medusa_buffer_append(buffer, &value, sizeof(uint32_t));
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_append_uint32_be (struct medusa_buffer *buffer, uint32_t value)
{
        value = htobe32(value);
        return medusa_buffer_append(buffer, &value, sizeof(uint32_t));
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_append_uint64 (struct medusa_buffer *buffer, uint64_t value)
{
        return medusa_buffer_append(buffer, &value, sizeof(uint64_t));
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_append_uint64_le (struct medusa_buffer *buffer, uint64_t value)
{
        value = htole64(value);
        return medusa_buffer_append(buffer, &value, sizeof(uint64_t));
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_append_uint64_be (struct medusa_buffer *buffer, uint64_t value)
{
        value = htobe64(value);
        return medusa_buffer_append(buffer, &value, sizeof(uint64_t));
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

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_peek (const struct medusa_buffer *buffer, int64_t offset, int64_t length, struct iovec *iovecs, int64_t niovecs)
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

__attribute__ ((visibility ("default"))) int medusa_buffer_memcmp (const struct medusa_buffer *buffer, int64_t offset, const void *data, int64_t length)
{
        int ret;
        int64_t i;
        int64_t l;
        int64_t niovecs;
        struct iovec *iovecs;
        struct iovec _iovecs[16];
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(data)) {
                return -EINVAL;
        }
        if (length < 0) {
                return -EINVAL;
        }
        l = medusa_buffer_get_length(buffer);
        if (length == 0 &&
            l == 0) {
                return 0;
        }
        if (l < length) {
                return -1;
        }
        niovecs = medusa_buffer_peek(buffer, offset, length, NULL, 0);
        if (niovecs < 0) {
                return niovecs;
        }
        if (niovecs > (int64_t) (sizeof(_iovecs) / sizeof(_iovecs[0]))) {
                iovecs = malloc(sizeof(struct iovec) * niovecs);
                if (iovecs == NULL) {
                        return -ENOMEM;
                }
        } else {
                iovecs = _iovecs;
        }
        niovecs = medusa_buffer_peek(buffer, offset, length, iovecs, niovecs);
        if (niovecs < 0) {
                ret = niovecs;
                goto out;
        }
        for (i = 0; l > 0 && i < niovecs; i++) {
                l = MIN(length, (int64_t) iovecs[i].iov_len);
                ret = memcmp(data, iovecs[i].iov_base, l);
                if (ret != 0) {
                        break;
                }
                length -= l;
                data   += l;
        }
        if (length > 0) {
                ret = -1;
        }
out:    if (iovecs != NULL &&
            iovecs != _iovecs) {
                free(iovecs);
        }
        return ret;
}

__attribute__ ((visibility ("default"))) int64_t medusa_buffer_memmem (const struct medusa_buffer *buffer, int64_t offset, const void *data, int64_t length)
{
        int rc;
        int64_t i;
        int64_t l;
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(data)) {
                return -EINVAL;
        }
        if (length < 0) {
                return -EINVAL;
        }
        l = medusa_buffer_get_length(buffer);
        if (length == 0 &&
            l == 0) {
                return 0;
        }
        if (l < length) {
                return -1;
        }
        for (i = offset; i <= l - length; i++) {
                rc = medusa_buffer_memcmp(buffer, i, data, length);
                if (rc == 0) {
                        return i;
                }
        }
        return -1;
}

__attribute__ ((visibility ("default"))) int medusa_buffer_peek_data (const struct medusa_buffer *buffer, int64_t offset, void *data, int64_t length)
{
        int ret;
        int64_t i;
        int64_t l;
        int64_t niovecs;
        struct iovec *iovecs;
        struct iovec _iovecs[16];
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(data)) {
                return -EINVAL;
        }
        if (length < 0) {
                return -EINVAL;
        }
        l = medusa_buffer_get_length(buffer);
        if (length == 0 &&
            l == 0) {
                return 0;
        }
        if (l < length) {
                return -1;
        }
        niovecs = medusa_buffer_peek(buffer, offset, length, NULL, 0);
        if (niovecs < 0) {
                return niovecs;
        }
        if (niovecs > (int64_t) (sizeof(_iovecs) / sizeof(_iovecs[0]))) {
                iovecs = malloc(sizeof(struct iovec) * niovecs);
                if (iovecs == NULL) {
                        return -ENOMEM;
                }
        } else {
                iovecs = _iovecs;
        }
        ret = 0;
        niovecs = medusa_buffer_peek(buffer, offset, length, iovecs, niovecs);
        if (niovecs < 0) {
                ret = niovecs;
                goto out;
        }
        for (i = 0; i < niovecs; i++) {
                memcpy(data, iovecs[i].iov_base, MIN(length, (int64_t) iovecs[i].iov_len));
                length -= iovecs[i].iov_len;
                data   += iovecs[i].iov_len;
        }
        if (length > 0) {
                ret = -EIO;
        }
out:    if (iovecs != NULL &&
            iovecs != _iovecs) {
                free(iovecs);
        }
        return ret;
}

__attribute__ ((visibility ("default"))) int medusa_buffer_peek_uint8 (const struct medusa_buffer *buffer, int64_t offset, uint8_t *value)
{
        int rc;
        uint8_t v;
        rc = medusa_buffer_peek_data(buffer, offset, &v, sizeof(uint8_t));
        if (rc < 0) {
                return rc;
        }
        memcpy(value, &v, sizeof(uint8_t));
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_buffer_peek_uint8_le (const struct medusa_buffer *buffer, int64_t offset, uint8_t *value)
{
        int rc;
        uint8_t v;
        rc = medusa_buffer_peek_data(buffer, offset, &v, sizeof(uint8_t));
        if (rc < 0) {
                return rc;
        }
        memcpy(value, &v, sizeof(uint8_t));
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_buffer_peek_uint8_be (const struct medusa_buffer *buffer, int64_t offset, uint8_t *value)
{
        int rc;
        uint8_t v;
        rc = medusa_buffer_peek_data(buffer, offset, &v, sizeof(uint8_t));
        if (rc < 0) {
                return rc;
        }
        memcpy(value, &v, sizeof(uint8_t));
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_buffer_peek_uint16 (const struct medusa_buffer *buffer, int64_t offset, uint16_t *value)
{
        int rc;
        uint16_t v;
        rc = medusa_buffer_peek_data(buffer, offset, &v, sizeof(uint16_t));
        if (rc < 0) {
                return rc;
        }
        memcpy(value, &v, sizeof(uint16_t));
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_buffer_peek_uint16_le (const struct medusa_buffer *buffer, int64_t offset, uint16_t *value)
{
        int rc;
        uint16_t v;
        rc = medusa_buffer_peek_data(buffer, offset, &v, sizeof(uint16_t));
        if (rc < 0) {
                return rc;
        }
        v = le16toh(v);
        memcpy(value, &v, sizeof(uint16_t));
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_buffer_peek_uint16_be (const struct medusa_buffer *buffer, int64_t offset, uint16_t *value)
{
        int rc;
        uint16_t v;
        rc = medusa_buffer_peek_data(buffer, offset, &v, sizeof(uint16_t));
        if (rc < 0) {
                return rc;
        }
        v = be16toh(v);
        memcpy(value, &v, sizeof(uint16_t));
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_buffer_peek_uint32 (const struct medusa_buffer *buffer, int64_t offset, uint32_t *value)
{
        int rc;
        uint32_t v;
        rc = medusa_buffer_peek_data(buffer, offset, &v, sizeof(uint32_t));
        if (rc < 0) {
                return rc;
        }
        memcpy(value, &v, sizeof(uint32_t));
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_buffer_peek_uint32_le (const struct medusa_buffer *buffer, int64_t offset, uint32_t *value)
{
        int rc;
        uint32_t v;
        rc = medusa_buffer_peek_data(buffer, offset, &v, sizeof(uint32_t));
        if (rc < 0) {
                return rc;
        }
        v = le32toh(v);
        memcpy(value, &v, sizeof(uint32_t));
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_buffer_peek_uint32_be (const struct medusa_buffer *buffer, int64_t offset, uint32_t *value)
{
        int rc;
        uint32_t v;
        rc = medusa_buffer_peek_data(buffer, offset, &v, sizeof(uint32_t));
        if (rc < 0) {
                return rc;
        }
        v = be32toh(v);
        memcpy(value, &v, sizeof(uint32_t));
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_buffer_peek_uint64 (const struct medusa_buffer *buffer, int64_t offset, uint64_t *value)
{
        int rc;
        uint64_t v;
        rc = medusa_buffer_peek_data(buffer, offset, &v, sizeof(uint64_t));
        if (rc < 0) {
                return rc;
        }
        memcpy(value, &v, sizeof(uint64_t));
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_buffer_peek_uint64_le (const struct medusa_buffer *buffer, int64_t offset, uint64_t *value)
{
        int rc;
        uint64_t v;
        rc = medusa_buffer_peek_data(buffer, offset, &v, sizeof(uint64_t));
        if (rc < 0) {
                return rc;
        }
        v = le64toh(v);
        memcpy(value, &v, sizeof(uint64_t));
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_buffer_peek_uint64_be (const struct medusa_buffer *buffer, int64_t offset, uint64_t *value)
{
        int rc;
        uint64_t v;
        rc = medusa_buffer_peek_data(buffer, offset, &v, sizeof(uint64_t));
        if (rc < 0) {
                return rc;
        }
        v = be64toh(v);
        memcpy(value, &v, sizeof(uint64_t));
        return 0;
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
