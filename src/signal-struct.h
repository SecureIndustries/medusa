
#if !defined(MEDUSA_SIGNAL_STRUCT_H)
#define MEDUSA_SIGNAL_STRUCT_H

struct medusa_monitor;
struct medusa_signal_init_options;

struct medusa_signal {
        struct medusa_subject subject;
        unsigned int flags;
        int number;
        int (*onevent) (struct medusa_signal *signal, unsigned int events, void *context, void *param);
        void *context;
        void *userdata;
};

int medusa_signal_init (struct medusa_signal *signal, struct medusa_monitor *monitor, int number, int (*onevent) (struct medusa_signal *signal, unsigned int events, void *context, void *param), void *context);
int medusa_signal_init_with_options (struct medusa_signal *signal, const struct medusa_signal_init_options *options);
void medusa_signal_uninit (struct medusa_signal *signal);

#endif
