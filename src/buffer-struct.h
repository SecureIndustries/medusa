
#if !defined(MEDUSA_BUFFER_STRUCT_H)
#define MEDUSA_BUFFER_STRUCT_H

struct iovec;
struct medusa_buffer;

struct medusa_buffer_backend {
        int64_t (*get_size) (const struct medusa_buffer *buffer);
        int64_t (*get_length) (const struct medusa_buffer *buffer);

        int64_t (*insertv) (struct medusa_buffer *buffer, int64_t offset, const struct iovec *iovecs, int64_t niovecs);

        int64_t (*reserve) (struct medusa_buffer *buffer, int64_t length, struct iovec *iovecs, int64_t niovecs);
        int64_t (*commit) (struct medusa_buffer *buffer, const struct iovec *iovecs, int64_t niovecs);

        int64_t (*peek) (struct medusa_buffer *buffer, int64_t offset, int64_t length, struct iovec *iovecs, int64_t niovecs);
        int64_t (*choke) (struct medusa_buffer *buffer, int64_t offset, int64_t length);

        int64_t (*memcmp) (struct medusa_buffer *buffer, int64_t offset, const void *data, int64_t length);
        int64_t (*memmem) (struct medusa_buffer *buffer, int64_t offset, const void *data, int64_t length);

        int (*reset) (struct medusa_buffer *buffer);
        void (*destroy) (struct medusa_buffer *buffer);
};

struct medusa_buffer {
        const struct medusa_buffer_backend *backend;
};

#endif
