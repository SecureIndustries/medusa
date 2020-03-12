
#if !defined(MEDUSA_UDPSOCKET_STRUCT_H)
#define MEDUSA_UDPSOCKET_STRUCT_H

struct medusa_udpsocket {
        struct medusa_subject subject;
        int (*onevent) (struct medusa_udpsocket *udpsocket, unsigned int events, void *context, void *param);
        void *context;
        unsigned int flags;
        unsigned int state;
        unsigned int error;
        struct medusa_io *io;
        struct medusa_timer *rtimer;
        void *userdata;
};

#endif
