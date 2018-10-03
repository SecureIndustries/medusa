
#if !defined(MEDUSA_BUFFER_H)
#define MEDUSA_BUFFER_H

struct iovec;
struct medusa_buffer;

enum {
        MEDUSA_BUFFER_TYPE_SIMPLE       = 0
#define MEDUSA_BUFFER_TYPE_SIMPLE       MEDUSA_BUFFER_TYPE_SIMPLE
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

struct medusa_buffer_init_options {
        unsigned int type;
        unsigned int flags;
        union {
                struct {
                        unsigned int grow_size;
                } simple;
        } u;
};

#ifdef __cplusplus
extern "C"
{
#endif

int medusa_buffer_init_options_default (struct medusa_buffer_init_options *options);

struct medusa_buffer * medusa_buffer_create (unsigned int type);
struct medusa_buffer * medusa_buffer_create_with_options (const struct medusa_buffer_init_options *options);
void medusa_buffer_destroy (struct medusa_buffer *buffer);

int medusa_buffer_reset (struct medusa_buffer *buffer);

int64_t medusa_buffer_get_size (const struct medusa_buffer *buffer);
int64_t medusa_buffer_get_length (const struct medusa_buffer *buffer);

int64_t medusa_buffer_prepend (struct medusa_buffer *buffer, const void *data, int64_t length);
int64_t medusa_buffer_prependv (struct medusa_buffer *buffer, const struct iovec *iovecs, int64_t niovecs);
int64_t medusa_buffer_append (struct medusa_buffer *buffer, const void *data, int64_t length);
int64_t medusa_buffer_appendv (struct medusa_buffer *buffer, const struct iovec *iovecs, int64_t niovecs);
int64_t medusa_buffer_insert (struct medusa_buffer *buffer, int64_t offset, const void *data, int64_t length);
int64_t medusa_buffer_insertv (struct medusa_buffer *buffer, int64_t offset, const struct iovec *iovecs, int64_t niovecs);

int64_t medusa_buffer_prependf (struct medusa_buffer *buffer, const char *format, ...)  __attribute__((format(printf, 2, 3)));
int64_t medusa_buffer_prependfv (struct medusa_buffer *buffer, const char *format, va_list va);
int64_t medusa_buffer_appendf (struct medusa_buffer *buffer, const char *format, ...)  __attribute__((format(printf, 2, 3)));
int64_t medusa_buffer_appendfv (struct medusa_buffer *buffer, const char *format, va_list va);
int64_t medusa_buffer_insertf (struct medusa_buffer *buffer, int64_t offset, const char *format, ...)  __attribute__((format(printf, 3, 4)));
int64_t medusa_buffer_insertfv (struct medusa_buffer *buffer, int64_t offset, const char *format, va_list va);

int64_t medusa_buffer_printf (struct medusa_buffer *buffer, const char *format, ...)  __attribute__((format(printf, 2, 3)));
int64_t medusa_buffer_vprintf (struct medusa_buffer *buffer, const char *format, va_list va);

int64_t medusa_buffer_reserve (struct medusa_buffer *buffer, int64_t length, struct iovec *iovecs, int64_t niovecs);
int64_t medusa_buffer_commit (struct medusa_buffer *buffer, const struct iovec *iovecs, int64_t niovecs);

int64_t medusa_buffer_peek (struct medusa_buffer *buffer, int64_t offset, int64_t length, struct iovec *iovecs, int64_t niovecs);
int64_t medusa_buffer_choke (struct medusa_buffer *buffer, int64_t offset, int64_t length);

int medusa_buffer_memcmp (struct medusa_buffer *buffer, int64_t offset, const void *data, int64_t length);
int64_t medusa_buffer_memmem (struct medusa_buffer *buffer, int64_t offset, const void *data, int64_t length);

#ifdef __cplusplus
}
#endif

#endif
