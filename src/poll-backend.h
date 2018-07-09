
struct medusa_monitor;

struct medusa_poll_backend {
        const char *name;
        int (*add) (struct medusa_poll_backend *backend, struct medusa_subject *subject, unsigned int events);
        int (*mod) (struct medusa_poll_backend *backend, struct medusa_subject *subject, unsigned int events);
        int (*del) (struct medusa_poll_backend *backend, struct medusa_subject *subject);
        int (*run) (struct medusa_poll_backend *backend, struct medusa_timespec *timespec);
        void (*destroy) (struct medusa_poll_backend *backend);
        struct medusa_monitor *monitor;
};
