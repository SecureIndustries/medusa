
#if !defined(MEDUSA_HTTPREQUEST_STRUCT_H)
#define MEDUSA_HTTPREQUEST_STRUCT_H

struct medusa_httprequest {
        struct medusa_subject subject;
        unsigned int state;
        int (*onevent) (struct medusa_httprequest *httprequest, unsigned int events, void *context, void *param);
        void *context;
        struct medusa_buffer *headers;
        struct medusa_buffer *wbuffer;
        struct medusa_buffer *rbuffer;
        struct medusa_tcpsocket *tcpsocket;
        double connect_timeout;
        double read_timeout;
        http_parser http_parser;
        http_parser_settings http_parser_settings;
        struct medusa_httprequest_reply *reply;
};

int medusa_httprequest_init (struct medusa_httprequest *httprequest, struct medusa_monitor *monitor, int (*onevent) (struct medusa_httprequest *httprequest, unsigned int events, void *context, void *param), void *context);
int medusa_httprequest_init_with_options (struct medusa_httprequest *httprequest, const struct medusa_httprequest_init_options *options);
void medusa_httprequest_uninit (struct medusa_httprequest *httprequest);

#endif
