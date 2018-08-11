
#if !defined(MEDUSA_HTTP_H)
#define MEDUSA_HTTP_H

enum {
        MEDUSA_HTTP_PROTOCOL_ANY        = 0,
        MEDUSA_HTTP_PROTOCOL_IPV4       = 1,
        MEDUSA_HTTP_PROTOCOL_IPV6       = 2
#define MEDUSA_HTTP_PROTOCOL_ANY        MEDUSA_HTTP_PROTOCOL_ANY
#define MEDUSA_HTTP_PROTOCOL_IPV4       MEDUSA_HTTP_PROTOCOL_IPV4
#define MEDUSA_HTTP_PROTOCOL_IPV6       MEDUSA_HTTP_PROTOCOL_IPV6
};

struct medusa_http_stat {
        long long size;
        long long mtime;
        int seekable;
        int chunked;
};

#endif
