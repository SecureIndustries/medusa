
#if !defined(MEDUSA_BUFFER_H)
#define MEDUSA_BUFFER_H

struct medusa_buffer;

struct medusa_buffer * medusa_buffer_create (void);
void medusa_buffer_destroy (struct medusa_buffer *buffer);

int medusa_buffer_resize (struct medusa_buffer *buffer, int64_t size);
int medusa_buffer_grow (struct medusa_buffer *buffer, int64_t size);
void medusa_buffer_reset (struct medusa_buffer *buffer);

void * medusa_buffer_get_base (const struct medusa_buffer *buffer);
int64_t medusa_buffer_get_size (const struct medusa_buffer *buffer);

int64_t medusa_buffer_get_length (const struct medusa_buffer *buffer);
int medusa_buffer_set_length (struct medusa_buffer *buffer, int64_t length);

int medusa_buffer_push (struct medusa_buffer *buffer, const void *data, int64_t length);
int medusa_buffer_printf (struct medusa_buffer *buffer, const char *format, ...)  __attribute__((format(printf, 2, 3)));
int medusa_buffer_vprintf (struct medusa_buffer *buffer, const char *format, va_list va);
int medusa_buffer_eat (struct medusa_buffer *buffer, int64_t length);

#endif
