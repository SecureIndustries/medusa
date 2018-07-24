
struct medusa_io {
        struct medusa_subject subject;
        int fd;
        unsigned int events;
        int (*onevent) (struct medusa_io *io, unsigned int events, void *context);
        void *context;
        int enabled;
};

int medusa_io_init (struct medusa_monitor *monitor, struct medusa_io *io, int fd, int (*onevent) (struct medusa_io *io, unsigned int events, void *context), void *context);
void medusa_io_uninit (struct medusa_io *io);
