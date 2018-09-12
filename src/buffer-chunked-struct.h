
#if !defined(MEDUSA_BUFFER_CHUNKED_STRUCT_H)
#define MEDUSA_BUFFER_CHUNKED_STRUCT_H

enum {
        MEDUSA_BUFFER_CHUNKED_ENTRY_FLAG_NONE           = 0x00000000,
        MEDUSA_BUFFER_CHUNKED_ENTRY_FLAG_ALLOC          = 0x00000001,
        MEDUSA_BUFFER_CHUNKED_ENTRY_FLAG_DEFAULT        = MEDUSA_BUFFER_CHUNKED_ENTRY_FLAG_NONE,
#define MEDUSA_BUFFER_CHUNKED_ENTRY_FLAG_NONE           MEDUSA_BUFFER_CHUNKED_ENTRY_FLAG_NONE
#define MEDUSA_BUFFER_CHUNKED_ENTRY_FLAG_ALLOC          MEDUSA_BUFFER_CHUNKED_ENTRY_FLAG_ALLOC
#define MEDUSA_BUFFER_CHUNKED_ENTRY_FLAG_DEFAULT        MEDUSA_BUFFER_CHUNKED_ENTRY_FLAG_DEFAULT
};

TAILQ_HEAD(medusa_buffer_chunked_entries, medusa_buffer_chunked_entry);
struct medusa_buffer_chunked_entry {
        TAILQ_ENTRY(medusa_buffer_chunked_entry) list;
        unsigned int flags;
        int64_t offset;
        int64_t length;
        int64_t size;
        uint8_t data[0];
};

struct medusa_buffer_chunked {
        struct medusa_buffer buffer;
        struct medusa_buffer_chunked_entries entries;
        struct medusa_buffer_chunked_entry *active;
        int64_t chunk_size;
        int64_t chunk_count;
        int64_t total_size;
        int64_t total_length;
        struct medusa_buffer_chunked_entry_pool *chunk_pool;
};

#endif
