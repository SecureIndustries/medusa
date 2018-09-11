
#if !defined(MEDUSA_BUFFER_CHUNKED_H)
#define MEDUSA_BUFFER_CHUNKED_H

struct medusa_buffer_chunked;

enum {
        MEDUSA_BUFFER_CHUNKED_FLAG_NONE          = 0x00000000,
        MEDUSA_BUFFER_CHUNKED_FLAG_DEFAULT       = MEDUSA_BUFFER_CHUNKED_FLAG_NONE,
};

#define MEDUSA_BUFFER_CHUNKED_DEFAULT_GROW       1024

struct medusa_buffer_chunked_init_options {
        unsigned int flags;
        unsigned int grow;
};

int medusa_buffer_chunked_init_options_default (struct medusa_buffer_chunked_init_options *options);

struct medusa_buffer * medusa_buffer_chunked_create (unsigned int flags, unsigned int grow);
struct medusa_buffer * medusa_buffer_chunked_create_with_options (const struct medusa_buffer_chunked_init_options *options);

#endif
