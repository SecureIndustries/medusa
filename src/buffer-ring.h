
#if !defined(MEDUSA_BUFFER_RING_H)
#define MEDUSA_BUFFER_RING_H

struct medusa_buffer_ring;

enum {
        MEDUSA_BUFFER_RING_FLAG_NONE          = 0x00000000,
        MEDUSA_BUFFER_RING_FLAG_DEFAULT       = MEDUSA_BUFFER_RING_FLAG_NONE,
};

#define MEDUSA_BUFFER_RING_DEFAULT_GROW       4096

struct medusa_buffer_ring_init_options {
        unsigned int flags;
        unsigned int grow;
};

#ifdef __cplusplus
extern "C"
{
#endif

int medusa_buffer_ring_init_options_default (struct medusa_buffer_ring_init_options *options);

struct medusa_buffer * medusa_buffer_ring_create (unsigned int flags, unsigned int grow);
struct medusa_buffer * medusa_buffer_ring_create_with_options (const struct medusa_buffer_ring_init_options *options);

#ifdef __cplusplus
}
#endif

#endif
