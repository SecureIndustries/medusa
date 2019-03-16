
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <getopt.h>

#include <medusa/error.h>
#include <medusa/httprequest.h>
#include <medusa/monitor.h>

#define OPTIONS_DEFAULT_URL             "http://127.0.0.1"
#define OPTIONS_DEFAULT_METHOD          "post"
#define OPTIONS_DEFAULT_DATA            NULL

#define OPTION_HELP                     'h'
#define OPTION_URL                      'u'
#define OPTION_METHOD                   'm'
#define OPTION_HEADER                   'e'
#define OPTION_DATA                     'd'
static struct option longopts[] = {
        { "help",               no_argument,            NULL,        OPTION_HELP        },
        { "url",                required_argument,      NULL,        OPTION_URL      },
        { "method",             required_argument,      NULL,        OPTION_METHOD      },
        { "header",             required_argument,      NULL,        OPTION_HEADER      },
        { "data",               required_argument,      NULL,        OPTION_DATA        },
        { NULL,                 0,                      NULL,        0                  },
};

static void usage (const char *pname)
{
        fprintf(stdout, "medusa http request tool\n");
        fprintf(stdout, "\n");
        fprintf(stdout, "usage:\n");
        fprintf(stdout, "  %s [options]\n", pname);
        fprintf(stdout, "\n");
        fprintf(stdout, "options:\n");
        fprintf(stdout, "  -u, --url   : request url (default: %s)\n", OPTIONS_DEFAULT_URL);
        fprintf(stdout, "  -m, --method: request method (default: %s)\n", OPTIONS_DEFAULT_METHOD);
        fprintf(stdout, "  -e, --header: add header\n");
        fprintf(stdout, "  -d, --data  : request data (default: %s)\n", (OPTIONS_DEFAULT_DATA) ? OPTIONS_DEFAULT_DATA : "(null)");
        fprintf(stdout, "  -h, --help  : this text\n");
        fprintf(stdout, "\n");
        fprintf(stdout, "example:\n");
        fprintf(stdout, "  %s -u http://127.0.0.1/ -m post -h 'a:b' -h 'c:d' -d 'data'\n", pname);
}

static int httprequest_onevent (struct medusa_httprequest *httprequest, unsigned int events, void *context, ...)
{
        (void) httprequest;
        (void) events;
        (void) context;
        fprintf(stderr, "httprequest events: 0x%08x\n", events);
        if (events & MEDUSA_HTTPREQUEST_EVENT_RECEIVED) {
                const struct medusa_httprequest_reply *httprequest_reply;
                const struct medusa_httprequest_reply_status *httprequest_reply_status;
                const struct medusa_httprequest_reply_header *httprequest_reply_header;
                const struct medusa_httprequest_reply_headers *httprequest_reply_headers;
                const struct medusa_httprequest_reply_body *httprequest_reply_body;

                httprequest_reply = medusa_httprequest_get_reply(httprequest);
                if (MEDUSA_IS_ERR_OR_NULL(httprequest_reply)) {
                        fprintf(stderr, "hettprequest reply is invalid\n");
                        goto bail;
                }

                httprequest_reply_status = medusa_httprequest_reply_get_status(httprequest_reply);
                if (MEDUSA_IS_ERR_OR_NULL(httprequest_reply_status)) {
                        fprintf(stderr, "hettprequest reply status is invalid\n");
                        goto bail;
                }
                fprintf(stderr, "status:\n");
                fprintf(stderr, "  code : %ld\n", medusa_httprequest_reply_status_get_code(httprequest_reply_status));
                fprintf(stderr, "  value: %s\n", medusa_httprequest_reply_status_get_value(httprequest_reply_status));

                httprequest_reply_headers = medusa_httprequest_reply_get_headers(httprequest_reply);
                if (MEDUSA_IS_ERR_OR_NULL(httprequest_reply_headers)) {
                        fprintf(stderr, "hettprequest reply headers is invalid\n");
                        goto bail;
                }
                fprintf(stderr, "headers:\n");
                fprintf(stderr, "  count: %ld\n", medusa_httprequest_reply_headers_get_count(httprequest_reply_headers));
                for (httprequest_reply_header = medusa_httprequest_reply_headers_get_first(httprequest_reply_headers);
                     httprequest_reply_header;
                     httprequest_reply_header = medusa_httprequest_reply_header_get_next(httprequest_reply_header)) {
                        fprintf(stderr, "  %s = %s\n",
                                medusa_httprequest_reply_header_get_key(httprequest_reply_header),
                                medusa_httprequest_reply_header_get_value(httprequest_reply_header));
                }

                httprequest_reply_body = medusa_httprequest_reply_get_body(httprequest_reply);
                if (MEDUSA_IS_ERR_OR_NULL(httprequest_reply_body)) {
                        fprintf(stderr, "hettprequest reply body is invalid\n");
                        goto bail;
                }
                fprintf(stderr, "body\n");
                fprintf(stderr, "  length: %ld\n", medusa_httprequest_reply_body_get_length(httprequest_reply_body));
                fprintf(stderr, "  value : %.*s\n",
                        (int) medusa_httprequest_reply_body_get_length(httprequest_reply_body),
                        (char *) medusa_httprequest_reply_body_get_value(httprequest_reply_body));

                medusa_monitor_break(medusa_httprequest_get_monitor(httprequest));
        }
        return 0;
bail:   return -1;
}

int main (int argc, char *argv[])
{
        int c;
        int _argc;
        char **_argv;

        const char *option_url;
        const char *option_method;
        const char *option_header;
        const char *option_data;

        int rc;
        struct medusa_monitor *monitor;

        struct medusa_httprequest_init_options httprequest_init_options;
        struct medusa_httprequest *httprequest;

        (void) option_header;
        (void) option_method;

        monitor = NULL;

        option_url    = OPTIONS_DEFAULT_URL;
        option_method = OPTIONS_DEFAULT_METHOD;
        option_header = NULL;
        option_data   = NULL;

        _argv = malloc(sizeof(char *) * (argc + 1));

        optind = 0;
        for (_argc = 0; _argc < argc; _argc++) {
                _argv[_argc] = argv[_argc];
        }
        while ((c = getopt_long(_argc, _argv, "hu:m:e:d:", longopts, NULL)) != -1) {
                switch (c) {
                        case OPTION_HELP:
                                usage(argv[0]);
                                goto out;
                        case OPTION_URL:
                                option_url = optarg;
                                break;
                        case OPTION_METHOD:
                                option_method = optarg;
                                break;
                        case OPTION_HEADER:
                                option_header = optarg;
                                break;
                        case OPTION_DATA:
                                option_data = optarg;
                                break;
                        default:
                                fprintf(stderr, "invalid option: %s\n", argv[optind - 1]);
                                goto bail;
                }
        }

        monitor = medusa_monitor_create(NULL);
        if (monitor == NULL) {
                fprintf(stderr, "can not create monitor\n");
                goto bail;
        }

        medusa_httprequest_init_options_default(&httprequest_init_options);
        httprequest_init_options.monitor = monitor;
        httprequest_init_options.onevent = httprequest_onevent;
        httprequest_init_options.context = NULL;

        httprequest = medusa_httprequest_create_with_options(&httprequest_init_options);
        if (MEDUSA_IS_ERR_OR_NULL(httprequest)) {
                fprintf(stderr, "can not create httprequest\n");
                goto bail;
        }

        optind = 0;
        for (_argc = 0; _argc < argc; _argc++) {
                _argv[_argc] = argv[_argc];
        }
        while ((c = getopt_long(_argc, _argv, ":e:", longopts, NULL)) != -1) {
                switch (c) {
                        case OPTION_HEADER:
                                option_header = optarg;
                                rc = medusa_httprequest_add_header(httprequest, optarg, NULL);
                                break;
                }
        }

        rc = medusa_httprequest_make_post(httprequest, option_url, option_data, (option_data) ? (strlen(option_data) + 1) : 0);
        if (rc < 0) {
                fprintf(stderr, "can not make post\n");
                goto bail;
        }

        while (1) {
                rc = medusa_monitor_run_timeout(monitor, 1.0);
                if (rc < 0) {
                        fprintf(stderr, "monitor failed\n");
                        goto bail;
                }
                if (rc == 0) {
                        break;
                }
        }

        medusa_monitor_destroy(monitor);
out:    free(_argv);
        return 0;

bail:   if (monitor != NULL) {
                medusa_monitor_destroy(monitor);
        }
        free(_argv);
        return -1;
}
