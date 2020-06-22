
#if !defined(MEDUSA_WEBSOCKETSERVER_STRUCT_H)
#define MEDUSA_WEBSOCKETSERVER_STRUCT_H

struct medusa_websocketserver {
        struct medusa_subject subject;
        unsigned int state;
        int (*onevent) (struct medusa_websocketserver *websocketserver, unsigned int events, void *context, void *param);
        void *context;
        void *userdata;
        unsigned int protocol;
        char *address;
        unsigned short port;
        char *servername;
        struct medusa_tcpsocket *tcpsocket;
};

int medusa_websocketserver_init (struct medusa_websocketserver *websocketserver, struct medusa_monitor *monitor, int (*onevent) (struct medusa_websocketserver *websocketserver, unsigned int events, void *context, void *param), void *context);
int medusa_websocketserver_init_with_options (struct medusa_websocketserver *websocketserver, const struct medusa_websocketserver_init_options *options);
void medusa_websocketserver_uninit (struct medusa_websocketserver *websocketserver);

#endif
