
struct medusa_tcpsocket {
        struct medusa_io io;
        unsigned int flags;
        int backlog;
        int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context);
        struct medusa_buffer rbuffer;
        struct medusa_buffer wbuffer;
};

int medusa_tcpsocket_init (struct medusa_monitor *monitor, struct medusa_tcpsocket *tcpsocket, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context), void *context);
void medusa_tcpsocket_uninit (struct medusa_tcpsocket *tcpsocket);

int medusa_tcpsocket_accept_init (struct medusa_tcpsocket *tcpsocket, struct medusa_tcpsocket *accepted, int (*onevent) (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context), void *context);
