
#if !defined(MEDUSA_POLL_SELECT_H)
#define MEDUSA_POLL_SELECT_H

struct medusa_monitor_select_init_options {
        int (*onevent) (struct medusa_poll_backend *backend, struct medusa_io *io, unsigned int events, void *context, void *param);
        void *context;
};

struct medusa_poll_backend * medusa_monitor_select_create (const struct medusa_monitor_select_init_options *options);

#endif
