
#if !defined(MEDUSA_UDPSOCKET_STRUCT_H)
#define MEDUSA_UDPSOCKET_STRUCT_H

struct medusa_udpsocket {
        struct medusa_subject subject;
        unsigned int flags;
        int (*onevent) (struct medusa_udpsocket *udpsocket, unsigned int events, void *context, void *param);
        void *context;
        struct medusa_io *io;
        struct medusa_timer *ctimer;
        struct medusa_timer *rtimer;
        void *userdata;
};

int medusa_udpsocket_init (struct medusa_udpsocket *udpsocket, struct medusa_monitor *monitor, int (*onevent) (struct medusa_udpsocket *udpsocket, unsigned int events, void *context, void *param), void *context);
int medusa_udpsocket_init_with_options (struct medusa_udpsocket *udpsocket, const struct medusa_udpsocket_init_options *options);
void medusa_udpsocket_uninit (struct medusa_udpsocket *udpsocket);

#endif
