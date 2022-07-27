
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <medusa/error.h>
#include <medusa/url.h>

static int __strcasecmp (const char *s1, const char *s2)
{
        if (s1 == NULL && s2 != NULL) {
                return -1;
        }
        if (s1 != NULL && s2 == NULL) {
                return 1;
        }
        if (s1 == NULL && s2 == NULL) {
                return 0;
        }
        return strcasecmp(s1, s2);
}

static const struct {
        const char *url;
        const char *scheme;
        const char *host;
        unsigned short port;
        const char *path;
} g_tests[] = {
        { "", NULL, "", 0, NULL } ,
        { "a.com", NULL, "a.com", 0, NULL },
        { "a.com/", NULL, "a.com", 0, "" },
        { "a.com//", NULL, "a.com", 0, "" },
        { "a.com/a", NULL, "a.com", 0, "a" },
        { "a.com/a/", NULL, "a.com", 0, "a/" },
        { "a.com/a//", NULL, "a.com", 0, "a//" },
        { "a.com/a/b", NULL, "a.com", 0, "a/b" },
        { "a.com/a/b/", NULL, "a.com", 0, "a/b/" },
        { "a.com/a/b//", NULL, "a.com", 0, "a/b//" },
        { "a.com:1", NULL, "a.com", 1, NULL },
        { "a.com:1/", NULL, "a.com", 1, "" },
        { "a.com:1//", NULL, "a.com", 1, "" },
        { "a.com:1/a", NULL, "a.com", 1, "a" },
        { "a.com:1/a/", NULL, "a.com", 1, "a/" },
        { "a.com:1/a//", NULL, "a.com", 1, "a//" },
        { "a.com:1/a/b", NULL, "a.com", 1, "a/b" },
        { "a.com:1/a/b/", NULL, "a.com", 1, "a/b/" },
        { "a.com:1/a/b//", NULL, "a.com", 1, "a/b//" },
        { "a.com/:1", NULL, "a.com", 0, ":1" },
        { "a.com//:1", NULL, "a.com", 0, ":1" },
        { "a.com/a:1", NULL, "a.com", 0, "a:1" },
        { "a.com/a/:1", NULL, "a.com", 0, "a/:1" },
        { "a.com/a//:1", NULL, "a.com", 0, "a//:1" },
        { "a.com/a/b:1", NULL, "a.com", 0, "a/b:1" },
        { "a.com/a/b/:1", NULL, "a.com", 0, "a/b/:1" },
        { "a.com/a/b//:1", NULL, "a.com", 0, "a/b//:1" },
        { "a.com/http://", NULL, "a.com", 0, "http://" },
        { "a.com//http://", NULL, "a.com", 0, "http://" },
        { "a.com/ahttp://", NULL, "a.com", 0, "ahttp://" },
        { "a.com/a/http://", NULL, "a.com", 0, "a/http://" },
        { "a.com/a//http://", NULL, "a.com", 0, "a//http://" },
        { "a.com/a/bhttp://", NULL, "a.com", 0, "a/bhttp://" },
        { "a.com/a/b/http://", NULL, "a.com", 0, "a/b/http://" },
        { "a.com/a/b//http://", NULL, "a.com", 0, "a/b//http://" },
        { "http://", "http", "", 80, NULL } ,
        { "http://a.com", "http", "a.com", 80, NULL },
        { "http://a.com/", "http", "a.com", 80, "" },
        { "http://a.com//", "http", "a.com", 80, "" },
        { "http://a.com/a", "http", "a.com", 80, "a" },
        { "http://a.com/a/", "http", "a.com", 80, "a/" },
        { "http://a.com/a//", "http", "a.com", 80, "a//" },
        { "http://a.com/a/b", "http", "a.com", 80, "a/b" },
        { "http://a.com/a/b/", "http", "a.com", 80, "a/b/" },
        { "http://a.com/a/b//", "http", "a.com", 80, "a/b//" },
        { "http://a.com:1", "http", "a.com", 1, NULL },
        { "http://a.com:1/", "http", "a.com", 1, "" },
        { "http://a.com:1//", "http", "a.com", 1, "" },
        { "http://a.com:1/a", "http", "a.com", 1, "a" },
        { "http://a.com:1/a/", "http", "a.com", 1, "a/" },
        { "http://a.com:1/a//", "http", "a.com", 1, "a//" },
        { "http://a.com:1/a/b", "http", "a.com", 1, "a/b" },
        { "http://a.com:1/a/b/", "http", "a.com", 1, "a/b/" },
        { "http://a.com:1/a/b//", "http", "a.com", 1, "a/b//" },
        { "http://a.com/:1", "http", "a.com", 80, ":1" },
        { "http://a.com//:1", "http", "a.com", 80, ":1" },
        { "http://a.com/a:1", "http", "a.com", 80, "a:1" },
        { "http://a.com/a/:1", "http", "a.com", 80, "a/:1" },
        { "http://a.com/a//:1", "http", "a.com", 80, "a//:1" },
        { "http://a.com/a/b:1", "http", "a.com", 80, "a/b:1" },
        { "http://a.com/a/b/:1", "http", "a.com", 80, "a/b/:1" },
        { "http://a.com/a/b//:1", "http", "a.com", 80, "a/b//:1" }
};

int main (int argc, char *argv[])
{
        int i;
        struct medusa_url *url;
        (void) argc;
        (void) argv;
        fprintf(stderr, "start\n");
        for (i = 0; i < (int) (sizeof(g_tests) / sizeof(g_tests[0])); i++) {
                fprintf(stderr, "url: '%s'\n", g_tests[i].url);
                url = medusa_url_parse(g_tests[i].url);
                if (MEDUSA_IS_ERR_OR_NULL(url)) {
                        fprintf(stderr, "  fail error: %d\n", MEDUSA_PTR_ERR(url));
                        return -1;
                }
                if (__strcasecmp(g_tests[i].scheme, medusa_url_get_scheme(url)) != 0) {
                        fprintf(stderr, "  scheme mismatch: '%s' != '%s'\n", g_tests[i].url, medusa_url_get_scheme(url));
                        return -1;
                }
                if (__strcasecmp(g_tests[i].host, medusa_url_get_host(url))) {
                        fprintf(stderr, "  host mismatch: '%s' != '%s'\n", g_tests[i].host, medusa_url_get_host(url));
                        return -1;
                }
                if (g_tests[i].port != medusa_url_get_port(url)) {
                        fprintf(stderr, "  port mismatch: '%d' != '%d'\n", g_tests[i].port, medusa_url_get_port(url));
                        return -1;
                }
                if (__strcasecmp(g_tests[i].path, medusa_url_get_path(url))) {
                        fprintf(stderr, "  path mismatch: '%s' != '%s'\n", g_tests[i].path, medusa_url_get_path(url));
                        return -1;
                }
                medusa_url_destroy(url);
        }
        fprintf(stderr, "success\n");
        return 0;
}
