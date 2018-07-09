
struct medusa_monitor;

struct medusa_monitor_backend {
        const char *name;
        int (*add) (struct medusa_monitor_backend *backend, struct medusa_subject *subject, unsigned int events);
        int (*mod) (struct medusa_monitor_backend *backend, struct medusa_subject *subject, unsigned int events);
        int (*del) (struct medusa_monitor_backend *backend, struct medusa_subject *subject);
        int (*run) (struct medusa_monitor_backend *backend, struct medusa_timespec *timespec);
        void (*destroy) (struct medusa_monitor_backend *backend);
        struct medusa_monitor *monitor;
};
