
#if !defined(MEDUSA_TIMER_BACKEND_H)
#define MEDUSA_TIMER_BACKEND_H

struct timespec;
struct medusa_monitor;

struct medusa_timer_backend {
        const char *name;
        int (*fd) (struct medusa_timer_backend *backend);
        int (*set) (struct medusa_timer_backend *backend, struct timespec *timerspec);
        int (*get) (struct medusa_timer_backend *backend, struct timespec *timerspec);
        void (*destroy) (struct medusa_timer_backend *backend);
        struct medusa_monitor *monitor;
};

#endif
