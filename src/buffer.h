
#if !defined(MEDUSA_BUFFER_H)
#define MEDUSA_BUFFER_H

struct medusa_buffer;

enum {
        MEDUSA_BUFFER_TYPE_SIMPLE,
        MEDUSA_BUFFER_TYPE_CHUNKED,
        MEDUSA_BUFFER_TYPE_DEFAULT      = MEDUSA_BUFFER_TYPE_CHUNKED,
#define MEDUSA_BUFFER_TYPE_SIMPLE       MEDUSA_BUFFER_TYPE_SIMPLE
#define MEDUSA_BUFFER_TYPE_CHUNKED      MEDUSA_BUFFER_TYPE_CHUNKED
#define MEDUSA_BUFFER_TYPE_DEFAULT      MEDUSA_BUFFER_TYPE_DEFAULT
};

enum {
        MEDUSA_BUFFER_FLAG_NONE         = 0x00000001,
        MEDUSA_BUFFER_FLAG_THREAD_SAFE  = 0x00000002,
        MEDUSA_BUFFER_FLAG_DEFAULT      = MEDUSA_BUFFER_FLAG_THREAD_SAFE,
#define MEDUSA_BUFFER_FLAG_NONE         MEDUSA_BUFFER_FLAG_NONE
#define MEDUSA_BUFFER_FLAG_THREAD_SAFE  MEDUSA_BUFFER_FLAG_THREAD_SAFE
#define MEDUSA_BUFFER_FLAG_DEFAULT      MEDUSA_BUFFER_FLAG_DEFAULT
};

#define MEDUSA_BUFFER_DEFAULT_GROW_SIZE         1024
#define MEDUSA_BUFFER_DEFAULT_CHUNK_SIZE        1024

struct medusa_buffer_init_options {
        unsigned int type;
        unsigned int flags;
        union {
                struct {
                        unsigned int grow_size;
                } simple;
                struct {
                        unsigned int chunk_size;
                } chunked;
        } u;
};

int medusa_buffer_init_options_default (struct medusa_buffer_init_options *options);

struct medusa_buffer * medusa_buffer_create (unsigned int type);
struct medusa_buffer * medusa_buffer_create_with_options (const struct medusa_buffer_init_options *options);
void medusa_buffer_destroy (struct medusa_buffer *buffer);

int medusa_buffer_resize (struct medusa_buffer *buffer, int64_t size);
int medusa_buffer_grow (struct medusa_buffer *buffer, int64_t size);
int medusa_buffer_reset (struct medusa_buffer *buffer);

int64_t medusa_buffer_get_size (const struct medusa_buffer *buffer);
int64_t medusa_buffer_get_length (const struct medusa_buffer *buffer);

int medusa_buffer_prepend (struct medusa_buffer *buffer, const void *data, int64_t length);
int medusa_buffer_append (struct medusa_buffer *buffer, const void *data, int64_t length);
int medusa_buffer_printf (struct medusa_buffer *buffer, const char *format, ...)  __attribute__((format(printf, 2, 3)));
int medusa_buffer_vprintf (struct medusa_buffer *buffer, const char *format, va_list va);
int medusa_buffer_choke (struct medusa_buffer *buffer, int64_t length);

#endif
