
#if !defined(MEDUSA_BUFFER_CHUNKED_STRUCT_H)
#define MEDUSA_BUFFER_CHUNKED_STRUCT_H

struct medusa_buffer_chunked {
        struct medusa_buffer buffer;
        int64_t grow;
        int64_t length;
        int64_t size;
        void *data;
};

#endif
