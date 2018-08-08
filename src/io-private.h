
#if !defined(MEDUSA_IO_PRIVATE_H)
#define MEDUSA_IO_PRIVATE_H

struct medusa_io;

int medusa_io_onevent (struct medusa_io *io, unsigned int events);
int medusa_io_is_valid (const struct medusa_io *io);

#endif
