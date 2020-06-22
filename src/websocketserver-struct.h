
#if !defined(MEDUSA_WEBSOCKETSERVER_STRUCT_H)
#define MEDUSA_WEBSOCKETSERVER_STRUCT_H

TAILQ_HEAD(medusa_websocketserver_clients, medusa_websocketserver_client);
struct medusa_websocketserver_client {
        TAILQ_ENTRY(medusa_websocketserver_client) list;
        struct medusa_tcpsocket *tcpsocket;
        struct medusa_websocketserver *websocketserver;
};

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
        int buffered;
        struct medusa_tcpsocket *tcpsocket;
        struct medusa_websocketserver_clients clients;
};

#endif
