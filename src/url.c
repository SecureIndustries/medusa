
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "error.h"
#include "url.h"

struct medusa_url {
        char *base;
        char *scheme;
        char *host;
        unsigned short port;
        char *path;
        int ssl;
};

struct medusa_url * medusa_url_parse (const char *uri)
{
        char *i;
        char *s;
        char *p;
        char *e;
        char *t;

        int rs;
        struct medusa_url *url;

        rs = -EIO;
        url = NULL;

        if (uri == NULL) {
                rs = -EINVAL;
                goto bail;
        }

        url = malloc(sizeof(struct medusa_url));
        if (url == NULL) {
                rs = -ENOMEM;
                goto bail;
        }
        memset(url, 0, sizeof(struct medusa_url));

        url->base = strdup(uri);
        if (url->base == NULL) {
                rs = -ENOMEM;
                goto bail;
        }

        if (url->base[0] == '<') {
                memmove(url->base, url->base + 1, strlen(url->base) - 1);
                t = strchr(url->base, '>');
                if (t != NULL) {
                        *t = '\0';
                }
        }

        i = url->base;

        s = strstr(url->base, "://");
        e = strchr(i, '/');
        if (s == NULL || e < s) {
                url->scheme = NULL;
        } else {
                url->scheme = i;
                *(e - 1) = '\0';
                i = s + 3;

                if (strcasecmp(url->scheme, "http") == 0) {
                        url->port = 80;
                } else if (strcasecmp(url->scheme, "https") == 0) {
                        url->port = 443;
                        url->ssl  = 1;
                }
        }

        p = strchr(i, ':');
        e = strchr(i, '/');
        if (p != NULL && e < p) {
                url->port = atoi(p + 1);
                *p = '\0';
        }
        url->host = i;
        if (e != NULL) {
                *e = '\0';
        }

        if (e != NULL) {
                do {
                        e++;
                } while (*e == '/');
                url->path = e;
        }

        if (url->host == NULL) {
                rs = -EINVAL;
                goto bail;
        }

        return url;
bail:   if (url != NULL) {
                medusa_url_destroy(url);
        }
        return MEDUSA_ERR_PTR(rs);
}

void medusa_url_destroy (struct medusa_url *url)
{
        if (url == NULL) {
                return;
        }
        if (url->base != NULL) {
                free(url->base);
        }
        free(url);
}

const char * medusa_url_get_scheme (struct medusa_url *url)
{
        if (url == NULL) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return url->scheme;
}

const char * medusa_url_get_host (struct medusa_url *url)
{
        if (url == NULL) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return url->host;
}

int medusa_url_get_port (struct medusa_url *url)
{
        if (url == NULL) {
                return -EINVAL;
        }
        return url->port;
}

const char * medusa_url_get_path (struct medusa_url *url)
{
        if (url == NULL) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return url->path;
}

int medusa_url_get_ssl (struct medusa_url *url)
{
        if (url == NULL) {
                return -EINVAL;
        }
        return url->ssl;
}
