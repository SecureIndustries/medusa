
#if !defined(MEDUSA_BUFFER_SIMPLE_H)
#define MEDUSA_BUFFER_SIMPLE_H

struct medusa_buffer_simple;

enum {
        MEDUSA_BUFFER_SIMPLE_FLAG_NONE          = 0x00000000,
        MEDUSA_BUFFER_SIMPLE_FLAG_DEFAULT       = MEDUSA_BUFFER_SIMPLE_FLAG_NONE,
};

#define MEDUSA_BUFFER_SIMPLE_DEFAULT_GROW       4096

struct medusa_buffer_simple_init_options {
        unsigned int flags;
        unsigned int grow;
};

#ifdef __cplusplus
extern "C"
{
#endif

int medusa_buffer_simple_init_options_default (struct medusa_buffer_simple_init_options *options);

struct medusa_buffer * medusa_buffer_simple_create (unsigned int flags, unsigned int grow);
struct medusa_buffer * medusa_buffer_simple_create_with_options (const struct medusa_buffer_simple_init_options *options);

#ifdef __cplusplus
}
#endif

#endif
