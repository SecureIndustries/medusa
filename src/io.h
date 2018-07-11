
struct medusa_io;
struct medusa_monitor;

struct medusa_io * medusa_io_create (void);
void medusa_io_destroy (struct medusa_io *io);

int medusa_io_set_fd (struct medusa_io *io, int fd);
int medusa_io_get_fd (const struct medusa_io *io);

int medusa_io_set_events (struct medusa_io *io, unsigned int events);
unsigned int medusa_io_get_events (const struct medusa_io *io);

int medusa_io_set_activated_callback (struct medusa_io *io, void (*activated) (struct medusa_io *io, unsigned int events, void *context), void *context);

int medusa_io_set_enabled (struct medusa_io *io, int enabled);
int medusa_io_get_enabled (const struct medusa_io *io);

int medusa_io_is_valid (const struct medusa_io *io);
struct medusa_monitor * medusa_io_get_monitor (struct medusa_io *io);
