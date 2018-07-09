
struct medusa_monitor;

struct medusa_timer_backend {
        const char *name;
        int (*set) (struct medusa_timer_backend *backend, struct medusa_timerspec *timerspec);
        int (*get) (struct medusa_timer_backend *backend, struct medusa_timerspec *timerspec);
        void (*destroy) (struct medusa_timer_backend *backend);
        struct medusa_monitor *monitor;
};
