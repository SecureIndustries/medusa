
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>

#include <sys/uio.h>

#include "medusa/error.h"
#include "medusa/dnsrequest.h"
#include "medusa/signal.h"
#include "medusa/monitor.h"

static int g_running;

#define OPTION_NAMESERVER_DEFAULT       "8.8.8.8"
#define OPTION_TYPE_DEFAULT             "A"
#define OPTION_NAME_DEFAULT             "www.google.com"

#define OPTION_HELP                     'h'
#define OPTION_NAMESERVER               's'
#define OPTION_TYPE                     't'
#define OPTION_NAME                     'n'
static struct option longopts[] = {
        { "help",                       no_argument,            NULL,   OPTION_HELP             },
        { "nameserver",                 required_argument,      NULL,   OPTION_NAMESERVER       },
        { "type",                       required_argument,      NULL,   OPTION_TYPE             },
        { "name",                       required_argument,      NULL,   OPTION_NAME             },
        { NULL,                         0,                      NULL,   0                       },
};

static void usage (const char *pname)
{
        fprintf(stdout, "usage: %s [-s nameserver] [-t type] -n name:\n", pname);
        fprintf(stdout, "  -h. --help      : this text\n");
        fprintf(stdout, "  -s, --nameserver: nameserver address (default: %s)\n", OPTION_NAMESERVER_DEFAULT);
        fprintf(stdout, "  -t. --type      : record type (default: %s)\n", OPTION_TYPE_DEFAULT);
        fprintf(stdout, "  -n. --name      : nameto lookup (default: %s)\n", OPTION_NAME_DEFAULT);
}

static int dnsrequest_onevent (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *context, void *param)
{
        (void) dnsrequest;
        (void) events;
        (void) context;
        (void) param;
        return 0;
}

static int signal_sigint_onevent (struct medusa_signal *signal, unsigned int events, void *context, void *param)
{
        (void) signal;
        (void) events;
        (void) context;
        (void) param;
        return medusa_monitor_break(medusa_signal_get_monitor(signal));
}

int main (int argc, char *argv[])
{
        int rc;
        int err;

        int c;
        const char *option_nameserver;
        const char *option_type;
        const char *option_name;

        struct medusa_dnsrequest *medusa_dnsrequest;
        struct medusa_dnsrequest_init_options medusa_dnsrequest_init_options;

        struct medusa_signal *medusa_signal;
        struct medusa_signal_init_options medusa_signal_init_options;

        struct medusa_monitor *medusa_monitor;
        struct medusa_monitor_init_options medusa_monitor_init_options;

        (void) argc;
        (void) argv;

        err = 0;
        medusa_monitor = NULL;

        option_nameserver       = OPTION_NAMESERVER_DEFAULT;
        option_type             = OPTION_TYPE_DEFAULT;
        option_name             = OPTION_NAME_DEFAULT;

        g_running = 1;

        while ((c = getopt_long(argc, argv, "hs:t:n:", longopts, NULL)) != -1) {
                switch (c) {
                        case OPTION_HELP:
                                usage(argv[0]);
                                goto out;
                        case OPTION_NAMESERVER:
                                option_nameserver = optarg;
                                break;
                        case OPTION_TYPE:
                                option_type = optarg;
                                break;
                        case OPTION_NAME:
                                option_name = optarg;
                                break;
                        default:
                                fprintf(stderr, "unknown option: %d\n", optopt);
                                err = -EINVAL;
                                goto out;
                }
        }

        if (medusa_dnsrequest_record_type_value(option_type) == MEDUSA_DNSREQUEST_RECORD_TYPE_INVALID) {
                fprintf(stderr, "type is invalid\n");
                err = -EINVAL;
                goto out;
        }
        if (medusa_dnsrequest_record_type_value(option_type) == MEDUSA_DNSREQUEST_RECORD_TYPE_UNKNOWN) {
                fprintf(stderr, "type is invalid\n");
                err = -EINVAL;
                goto out;
        }

        fprintf(stderr, "dns-lookup\n");
        fprintf(stderr, "  nameserver: %s\n", option_nameserver);
        fprintf(stderr, "  type      : %s, %d\n", option_type, medusa_dnsrequest_record_type_value(option_type));
        fprintf(stderr, "  name      : %s\n", option_name);

        rc = medusa_monitor_init_options_default(&medusa_monitor_init_options);
        if (rc < 0) {
                err = rc;
                goto out;
        }
        medusa_monitor = medusa_monitor_create_with_options(&medusa_monitor_init_options);
        if (MEDUSA_IS_ERR_OR_NULL(medusa_monitor)) {
                err = MEDUSA_PTR_ERR(medusa_monitor);
                goto out;
        }

        rc = medusa_signal_init_options_default(&medusa_signal_init_options);
        if (rc < 0) {
                err = rc;
                goto out;
        }
        medusa_signal_init_options.monitor     = medusa_monitor;
        medusa_signal_init_options.onevent     = signal_sigint_onevent;
        medusa_signal_init_options.context     = NULL;
        medusa_signal_init_options.enabled     = 1;
        medusa_signal_init_options.number      = SIGINT;
        medusa_signal_init_options.singleshot  = 0;
        medusa_signal = medusa_signal_create_with_options(&medusa_signal_init_options);
        if (MEDUSA_IS_ERR_OR_NULL(medusa_signal)) {
                err = MEDUSA_PTR_ERR(medusa_signal);
                goto out;
        }

        rc = medusa_dnsrequest_init_options_default(&medusa_dnsrequest_init_options);
        if (rc < 0) {
                err = rc;
                goto out;
        }
        medusa_dnsrequest_init_options.monitor     = medusa_monitor;
        medusa_dnsrequest_init_options.onevent     = dnsrequest_onevent;
        medusa_dnsrequest_init_options.context     = NULL;
        medusa_dnsrequest_init_options.nameserver  = option_nameserver;
        medusa_dnsrequest_init_options.type        = medusa_dnsrequest_record_type_value(option_type);
        medusa_dnsrequest_init_options.name        = option_name;
        medusa_dnsrequest = medusa_dnsrequest_create_with_options(&medusa_dnsrequest_init_options);
        if (MEDUSA_IS_ERR_OR_NULL(medusa_dnsrequest)) {
                err = MEDUSA_PTR_ERR(medusa_dnsrequest);
                goto out;
        }
        rc = medusa_dnsrequest_lookup(medusa_dnsrequest);
        if (rc < 0) {
                err = rc;
                goto out;
        }

        while (g_running == 1) {
                rc = medusa_monitor_run_once(medusa_monitor);
                if (rc < 0) {
                        err = rc;
                        break;
                } else if (rc == 0) {
                        err = 0;
                        break;
                }
        }

out:    if (!MEDUSA_IS_ERR_OR_NULL(medusa_monitor)) {
                medusa_monitor_destroy(medusa_monitor);
        }
        return err;
}

