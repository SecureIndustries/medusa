
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>

#include <sys/uio.h>

#include "error.h"
#include "pool.h"
#include "buffer.h"
#include "buffer-struct.h"
#include "buffer-ring.h"
#include "buffer-ring-struct.h"

#define MIN(a, b)                       (((a) < (b)) ? (a) : (b))

#define MEDUSA_BUFFER_RING_USE_POOL   1
#if defined(MEDUSA_BUFFER_RING_USE_POOL) && (MEDUSA_BUFFER_RING_USE_POOL == 1)
static struct medusa_pool *g_pool_buffer_ring;
#endif

static int ring_buffer_resize (struct medusa_buffer *buffer, int64_t size)
{
        void *data;
        unsigned int s;
        struct medusa_buffer_ring *ring = (struct medusa_buffer_ring *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(ring)) {
                return -EINVAL;
        }
        if (size < 0) {
                return -EINVAL;
        }
        if (ring->size >= size) {
                return 0;
        }
        s = ring->grow;
        while (s < size) {
                s += ring->grow;
        }
#if 1
        data = realloc(ring->data, size);
        if (data == NULL) {
#else
        if (1) {
#endif
                data = malloc(size);
                if (data == NULL) {
                        return -ENOMEM;
                }
                if (ring->length > 0) {
                        memcpy(data, ring->data, ring->length);
                }
                free(ring->data);
                ring->data = data;
        } else {
                ring->data = data;
        }
        ring->size = size;
        return 0;
}

static int64_t ring_buffer_get_size (const struct medusa_buffer *buffer)
{
        struct medusa_buffer_ring *ring = (struct medusa_buffer_ring *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(ring)) {
                return -EINVAL;
        }
        return ring->size;
}

static int64_t ring_buffer_get_length (const struct medusa_buffer *buffer)
{
        struct medusa_buffer_ring *ring = (struct medusa_buffer_ring *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(ring)) {
                return -EINVAL;
        }
        return ring->length;
}

static int64_t ring_buffer_insertv (struct medusa_buffer *buffer, int64_t offset, const struct iovec *iovecs, int64_t niovecs)
{
        int rc;
        int64_t i;
        int64_t length;
        struct medusa_buffer_ring *ring = (struct medusa_buffer_ring *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(ring)) {
                return -EINVAL;
        }
        if (offset < 0) {
                offset = ring->length + offset;
        }
        if (offset < 0) {
                return -EINVAL;
        }
        if (offset > ring->length) {
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
        length = 0;
        for (i = 0; i < niovecs; i++) {
                length += iovecs[i].iov_len;
        }
        rc = ring_buffer_resize(buffer, ring->length + length);
        if (rc < 0) {
                return rc;
        }
        if (offset != ring->length) {
                memmove(ring->data + offset + length, ring->data + offset, ring->length - offset);
        }
        length = 0;
        for (i = 0; i < niovecs; i++) {
                memcpy(ring->data + offset + length, iovecs[i].iov_base, iovecs[i].iov_len);
                length += iovecs[i].iov_len;
        }
        ring->length += length;
        return length;
}

static int64_t ring_buffer_insertfv (struct medusa_buffer *buffer, int64_t offset, const char *format, va_list va)
{
        int rc;
        int length;
        va_list vs;
        struct medusa_buffer_ring *ring = (struct medusa_buffer_ring *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(ring)) {
                return -EINVAL;
        }
        if (offset < 0) {
                offset = ring->length + offset;
        }
        if (offset < 0) {
                return -EINVAL;
        }
        if (offset > ring->length) {
                return -EINVAL;
        }
        va_copy(vs, va);
        length = vsnprintf(NULL, 0, format, vs);
        va_end(vs);
        if (length < 0) {
                return -EIO;
        }
        rc = ring_buffer_resize(buffer, ring->length + length + 1);
        if (rc < 0) {
                return rc;
        }
        if (offset != ring->length) {
                memmove(ring->data + offset + length, ring->data + offset, ring->length - offset);
        }
        va_copy(vs, va);
        rc = vsnprintf(ring->data + ring->length, length + 1, format, vs);
        va_end(vs);
        if (rc < 0) {
                return -EIO;
        }
        ring->length += rc;
        return rc;
}

static int64_t ring_buffer_reservev (struct medusa_buffer *buffer, int64_t length, struct iovec *iovecs, int64_t niovecs)
{
        int rc;
        struct medusa_buffer_ring *ring = (struct medusa_buffer_ring *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(ring)) {
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
        rc = ring_buffer_resize(buffer, ring->length + length);
        if (rc < 0) {
                return rc;
        }
        iovecs[0].iov_base = ring->data + ring->length;
        iovecs[0].iov_len  = ring->size - ring->length;
        return 1;
}

static int64_t ring_buffer_commitv (struct medusa_buffer *buffer, const struct iovec *iovecs, int64_t niovecs)
{
        struct medusa_buffer_ring *ring = (struct medusa_buffer_ring *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(ring)) {
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
        if (niovecs != 1) {
                return -EINVAL;
        }
        if ((ring->data + ring->length != iovecs[0].iov_base) ||
            (ring->data + ring->size < iovecs[0].iov_base + iovecs[0].iov_len)) {
                return -EINVAL;
        }
        ring->length += iovecs[0].iov_len;
        return 1;
}

static int64_t ring_buffer_peekv (const struct medusa_buffer *buffer, int64_t offset, int64_t length, struct iovec *iovecs, int64_t niovecs)
{
        struct medusa_buffer_ring *ring = (struct medusa_buffer_ring *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(ring)) {
                return -EINVAL;
        }
        if (niovecs < 0) {
                return -EINVAL;
        }
        if (offset < 0) {
                offset = ring->length + offset;
        }
        if (offset < 0) {
                return -EINVAL;
        }
        if (offset > ring->length) {
                offset = ring->length;
        }
        if (length < 0) {
                length = ring->length - offset;
        }
        if (length < 0) {
                return -EINVAL;
        }
        if (length > ring->length - offset) {
                length = ring->length - offset;
        }
        if (length == 0) {
                return 0;
        }
        if (niovecs == 0) {
                return 1;
        }
        iovecs[0].iov_base = ring->data + offset;
        iovecs[0].iov_len  = length;
        return 1;
}

static int64_t ring_buffer_choke (struct medusa_buffer *buffer, int64_t offset, int64_t length)
{
        struct medusa_buffer_ring *ring = (struct medusa_buffer_ring *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(ring)) {
                return -EINVAL;
        }
        if (offset < 0) {
                offset = ring->length + offset;
        }
        if (offset < 0) {
                return -EINVAL;
        }
        if (offset > ring->length) {
                offset = ring->length;
        }
        if (length < 0) {
                length = ring->length - offset;
        }
        if (length < 0) {
                return -EINVAL;
        }
        if (length > ring->length - offset) {
                length = ring->length - offset;
        }
        if (length == 0) {
                return 0;
        }
        memmove(ring->data + offset, ring->data + offset + length, ring->length - offset - length);
        ring->length -= length;
        return length;
}

static void * ring_buffer_linearize (struct medusa_buffer *buffer, int64_t offset, int64_t length)
{
        struct medusa_buffer_ring *ring = (struct medusa_buffer_ring *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(ring)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (offset < 0) {
                offset = ring->length + offset;
        }
        if (offset < 0) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (offset > ring->length) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (length < 0) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (offset + length > ring->length) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return ring->data + offset;
}

static int ring_buffer_reset (struct medusa_buffer *buffer)
{
        struct medusa_buffer_ring *ring = (struct medusa_buffer_ring *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(ring)) {
                return -EINVAL;
        }
        ring->length = 0;
        ring->rpos   = 0;
        ring->wpos   = 0;
        return 0;
}

static void ring_buffer_destroy (struct medusa_buffer *buffer)
{
        struct medusa_buffer_ring *ring = (struct medusa_buffer_ring *) buffer;
        if (MEDUSA_IS_ERR_OR_NULL(ring)) {
                return;;
        }
        if (ring->data != NULL) {
                free(ring->data);
        }
#if defined(MEDUSA_BUFFER_RING_USE_POOL) && (MEDUSA_BUFFER_RING_USE_POOL == 1)
        medusa_pool_free(ring);
#else
        free(ring);
#endif
}

const struct medusa_buffer_backend ring_buffer_backend = {
        .get_size       = ring_buffer_get_size,
        .get_length     = ring_buffer_get_length,

        .insertv        = ring_buffer_insertv,
        .insertfv       = ring_buffer_insertfv,

        .reservev       = ring_buffer_reservev,
        .commitv        = ring_buffer_commitv,

        .peekv          = ring_buffer_peekv,
        .choke          = ring_buffer_choke,

        .linearize      = ring_buffer_linearize,

        .reset          = ring_buffer_reset,
        .destroy        = ring_buffer_destroy
};

int medusa_buffer_ring_init_options_default (struct medusa_buffer_ring_init_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_buffer_ring_init_options));
        options->flags = MEDUSA_BUFFER_RING_FLAG_DEFAULT;
        options->grow = MEDUSA_BUFFER_RING_DEFAULT_GROW;
        return 0;
}

struct medusa_buffer * medusa_buffer_ring_create (unsigned int flags, unsigned int grow)
{
        int rc;
        struct medusa_buffer_ring_init_options options;
        rc = medusa_buffer_ring_init_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.flags = flags;
        options.grow  = grow;
        return medusa_buffer_ring_create_with_options(&options);
}

struct medusa_buffer * medusa_buffer_ring_create_with_options (const struct medusa_buffer_ring_init_options *options)
{
        struct medusa_buffer_ring *ring;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
#if defined(MEDUSA_BUFFER_RING_USE_POOL) && (MEDUSA_BUFFER_RING_USE_POOL == 1)
        ring = medusa_pool_malloc(g_pool_buffer_ring);
#else
        ring = malloc(sizeof(struct medusa_buffer_ring));
#endif
        if (MEDUSA_IS_ERR_OR_NULL(ring)) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(ring, 0, sizeof(struct medusa_buffer_ring));
        ring->grow   = options->grow;
        ring->length = 0;
        ring->size   = 0;
        ring->rpos   = 0;
        ring->wpos   = 0;
        ring->data   = NULL;
        if (ring->grow <= 0) {
                ring->grow = MEDUSA_BUFFER_RING_DEFAULT_GROW;
        }
        ring->buffer.backend = &ring_buffer_backend;
        return &ring->buffer;
}

__attribute__ ((constructor)) static void buffer_ring_constructor (void)
{
#if defined(MEDUSA_BUFFER_RING_USE_POOL) && (MEDUSA_BUFFER_RING_USE_POOL == 1)
        g_pool_buffer_ring = medusa_pool_create("medusa-buffer-ring", sizeof(struct medusa_buffer_ring), 0, 0, MEDUSA_POOL_FLAG_DEFAULT | MEDUSA_POOL_FLAG_THREAD_SAFE, NULL, NULL, NULL);
#endif
}

__attribute__ ((destructor)) static void buffer_ring_destructor (void)
{
#if defined(MEDUSA_BUFFER_RING_USE_POOL) && (MEDUSA_BUFFER_RING_USE_POOL == 1)
        if (g_pool_buffer_ring != NULL) {
                medusa_pool_destroy(g_pool_buffer_ring);
        }
#endif
}
