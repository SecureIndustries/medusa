
#if !defined(MEDUSA_SIGNAL_BACKEND_H)
#define MEDUSA_SIGNAL_BACKEND_H

struct medusa_signal;
struct medusa_monitor;

struct medusa_signal_backend {
        const char *name;
        int (*fd) (struct medusa_signal_backend *backend);
        int (*add) (struct medusa_signal_backend *backend, struct medusa_signal *signal);
        int (*del) (struct medusa_signal_backend *backend, struct medusa_signal *signal);
        void (*destroy) (struct medusa_signal_backend *backend);
        struct medusa_monitor *monitor;
};

#endif
