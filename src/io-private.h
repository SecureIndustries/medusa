
#if !defined(MEDUSA_IO_PRIVATE_H)
#define MEDUSA_IO_PRIVATE_H

struct medusa_io;

struct medusa_io * medusa_io_create_with_options_unlocked (const struct medusa_io_init_options *options);

void medusa_io_uninit_unlocked (struct medusa_io *io);
void medusa_io_destroy_unlocked (struct medusa_io *io);

int medusa_io_get_fd_unlocked (const struct medusa_io *io);

int medusa_io_set_events_unlocked (struct medusa_io *io, unsigned int events);
int medusa_io_add_events_unlocked (struct medusa_io *io, unsigned int events);
int medusa_io_del_events_unlocked (struct medusa_io *io, unsigned int events);
unsigned int medusa_io_get_events_unlocked (const struct medusa_io *io);

int medusa_io_set_enabled_unlocked (struct medusa_io *io, int enabled);
int medusa_io_get_enabled_unlocked (const struct medusa_io *io);

struct medusa_monitor * medusa_io_get_monitor_unlocked (const struct medusa_io *io);

int medusa_io_onevent_unlocked (struct medusa_io *io, unsigned int events);
int medusa_io_onevent (struct medusa_io *io, unsigned int events);

int medusa_io_is_valid_unlocked (const struct medusa_io *io);

#endif
