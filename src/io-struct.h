
struct medusa_io {
        struct medusa_subject subject;
        int fd;
        unsigned int events;
        int (*callback) (struct medusa_io *io, unsigned int events, void *context);
        void *context;
        int enabled;
        struct timespec timeout;
};
