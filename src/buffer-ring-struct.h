
#if !defined(MEDUSA_BUFFER_RING_STRUCT_H)
#define MEDUSA_BUFFER_RING_STRUCT_H

struct medusa_buffer_ring {
        struct medusa_buffer buffer;
        int64_t grow;
        int64_t length;
        int64_t size;
        int64_t head;
        void *data;
};

#endif
