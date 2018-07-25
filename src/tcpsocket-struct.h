
struct medusa_tcpsocket {
        struct medusa_io io;
        unsigned int flags;
        unsigned int state;
        int backlog;
        int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context);
};

int medusa_tcpsocket_init (struct medusa_monitor *monitor, struct medusa_tcpsocket *tcpsocket, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context), void *context);
void medusa_tcpsocket_uninit (struct medusa_tcpsocket *tcpsocket);
