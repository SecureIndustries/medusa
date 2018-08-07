
struct medusa_buffer;

struct medusa_buffer * medusa_buffer_create (void);
void medusa_buffer_destroy (struct medusa_buffer *buffer);

int medusa_buffer_resize (struct medusa_buffer *buffer, int size);
int medusa_buffer_grow (struct medusa_buffer *buffer, int size);
void medusa_buffer_reset (struct medusa_buffer *buffer);

void * medusa_buffer_base (const struct medusa_buffer *buffer);
int medusa_buffer_size (const struct medusa_buffer *buffer);

int medusa_buffer_length (const struct medusa_buffer *buffer);
int medusa_buffer_set_length (struct medusa_buffer *buffer, int length);

int medusa_buffer_push (struct medusa_buffer *buffer, const void *data, int length);
int medusa_buffer_printf (struct medusa_buffer *buffer, const char *format, ...)  __attribute__((format(printf, 2, 3)));
int medusa_buffer_vprintf (struct medusa_buffer *buffer, const char *format, va_list va);
int medusa_buffer_eat (struct medusa_buffer *buffer, int length);
