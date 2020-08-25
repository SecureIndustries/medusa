
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <getopt.h>
#include <signal.h>

#include <medusa/error.h>
#include <medusa/httpserver.h>
#include <medusa/monitor.h>

#define OPTIONS_DEFAULT_ADDRESS         "127.0.0.1"
#define OPTIONS_DEFAULT_PORT            12345

#define OPTION_HELP                     'h'
#define OPTION_ADDRESS                  'a'
#define OPTION_PORT                     'p'

static int g_running = 0;

static struct option longopts[] = {
        { "help",               no_argument,            NULL,        OPTION_HELP                },
        { "address",            required_argument,      NULL,        OPTION_ADDRESS             },
        { "port",               required_argument,      NULL,        OPTION_PORT                },
        { NULL,                 0,                      NULL,        0                          },
};

static void usage (const char *pname)
{
        fprintf(stdout, "medusa http server\n");
        fprintf(stdout, "\n");
        fprintf(stdout, "usage:\n");
        fprintf(stdout, "  %s [options]\n", pname);
        fprintf(stdout, "\n");
        fprintf(stdout, "options:\n");
        fprintf(stdout, "  -a, --address: address to run on (default: %s)\n", OPTIONS_DEFAULT_ADDRESS);
        fprintf(stdout, "  -p, --port   : port to run on (default: %d)\n", OPTIONS_DEFAULT_PORT);
        fprintf(stdout, "\n");
        fprintf(stdout, "example:\n");
        fprintf(stdout, "  %s -a 127.0.0.1 -p 12345\n", pname);
}

static int httpserver_onevent (struct medusa_httpserver *httpserver, unsigned int events, void *context, void *param)
{
        (void) httpserver;
        (void) events;
        (void) context;
        (void) param;
        fprintf(stderr, "httpserver state: %d, %s events: 0x%08x, %s\n", medusa_httpserver_get_state(httpserver), medusa_httpserver_state_string(medusa_httpserver_get_state(httpserver)), events, medusa_httpserver_event_string(events));
        return 0;
}

static void sigint_handler (int sig)
{
        (void) sig;
        g_running = 0;
}

int main (int argc, char *argv[])
{
        int c;
        int _argc;
        char **_argv;

        const char *option_address;
        int option_port;

        int rc;
        struct medusa_monitor *monitor;

        struct medusa_httpserver_init_options httpserver_init_options;
        struct medusa_httpserver *httpserver;

        g_running = 1;
        signal(SIGINT, sigint_handler);

        monitor = NULL;

        option_address  = OPTIONS_DEFAULT_ADDRESS;
        option_port     = OPTIONS_DEFAULT_PORT;

        _argv = malloc(sizeof(char *) * (argc + 1));

        optind = 0;
        for (_argc = 0; _argc < argc; _argc++) {
                _argv[_argc] = argv[_argc];
        }
        while ((c = getopt_long(_argc, _argv, "ha:p:", longopts, NULL)) != -1) {
                switch (c) {
                        case OPTION_HELP:
                                usage(argv[0]);
                                goto out;
                        case OPTION_ADDRESS:
                                option_address = optarg;
                                break;
                        case OPTION_PORT:
                                option_port = atoi(optarg);
                                break;
                        default:
                                fprintf(stderr, "invalid option: %s\n", argv[optind - 1]);
                                goto bail;
                }
        }

        monitor = medusa_monitor_create_with_options(NULL);
        if (monitor == NULL) {
                fprintf(stderr, "can not create monitor\n");
                goto bail;
        }

        medusa_httpserver_init_options_default(&httpserver_init_options);
        httpserver_init_options.address = option_address;
        httpserver_init_options.port    = option_port;
        httpserver_init_options.monitor = monitor;
        httpserver_init_options.onevent = httpserver_onevent;
        httpserver_init_options.context = NULL;

        httpserver = medusa_httpserver_create_with_options(&httpserver_init_options);
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                fprintf(stderr, "can not create httpserver errno: %ld, %s\n", MEDUSA_PTR_ERR(httpserver), strerror(MEDUSA_PTR_ERR(httpserver)));
                goto bail;
        }

        while (g_running) {
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
