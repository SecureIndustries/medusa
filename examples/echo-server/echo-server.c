
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <ctype.h>
#include <signal.h>
#include <errno.h>

#include <sys/uio.h>

#include "medusa/error.h"
#include "medusa/buffer.h"
#include "medusa/io.h"
#include "medusa/tcpsocket.h"
#include "medusa/signal.h"
#include "medusa/monitor.h"

static int g_running;

#define OPTION_ADDRESS_DEFAULT  "0.0.0.0"
#define OPTION_PORT_DEFAULT     12345

#define OPTION_HELP             'h'
#define OPTION_ADDRESS          'a'
#define OPTION_PORT             'p'

static struct option longopts[] = {
        { "help",               no_argument,            NULL,   OPTION_HELP     },
        { "address",            required_argument,      NULL,   OPTION_ADDRESS  },
        { "port",               required_argument,      NULL,   OPTION_PORT     },
        { NULL,                 0,                      NULL,   0               }
};

static void usage (const char *pname)
{
        fprintf(stdout, "usage: %s [-a address] [-p port]\n", pname);
        fprintf(stdout, "  -h. --help   : this text\n");
        fprintf(stdout, "  -a, --address: listening address (values: interface ip address, default: %s)\n", OPTION_ADDRESS_DEFAULT);
        fprintf(stdout, "  -p. --port   : listening port (values: 0 < port < 65536, default: %d)\n", OPTION_PORT_DEFAULT);
}

static int client_medusa_tcpsocket_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...)
{
        int rc;
        int64_t rlen;
        int64_t wlen;
        struct medusa_buffer *rbuffer;
        struct medusa_buffer *wbuffer;
        int64_t i;
        int64_t niovecs;
        struct iovec iovecs[16];
        (void) context;
        if (events & MEDUSA_TCPSOCKET_EVENT_BUFFERED_READ) {
                rbuffer = medusa_tcpsocket_get_read_buffer(tcpsocket);
                if (rbuffer == NULL) {
                        return MEDUSA_PTR_ERR(rbuffer);
                }
                niovecs = medusa_buffer_peek(rbuffer, 0, -1, iovecs, 16);
                if (niovecs < 0) {
                        return niovecs;
                }
                for (rlen = 0, i = 0; i < niovecs; i++) {
                        rlen += iovecs[i].iov_len;
                }
                wbuffer = medusa_tcpsocket_get_write_buffer(tcpsocket);
                if (wbuffer == NULL) {
                        return MEDUSA_PTR_ERR(wbuffer);
                }
                wlen = medusa_buffer_appendv(wbuffer, iovecs, niovecs);
                if (wlen < 0) {
                        return wlen;
                }
                if (wlen != rlen) {
                        return -EIO;
                }
                rc = medusa_buffer_choke(rbuffer, 0, wlen);
                if (rc < 0) {
                        return rc;
                }
        }
        return 0;
}

static int listener_medusa_tcpsocket_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...)
{
        int rc;
        struct medusa_tcpsocket *medusa_tcpsocket;
        struct medusa_tcpsocket_accept_options medusa_tcpsocket_accept_options;

        (void) context;

        if (events & MEDUSA_TCPSOCKET_EVENT_CONNECTION) {
                rc = medusa_tcpsocket_accept_options_default(&medusa_tcpsocket_accept_options);
                if (rc < 0) {
                        return rc;
                }
                medusa_tcpsocket_accept_options.tcpsocket   = tcpsocket;
                medusa_tcpsocket_accept_options.monitor     = NULL;
                medusa_tcpsocket_accept_options.onevent     = client_medusa_tcpsocket_onevent;
                medusa_tcpsocket_accept_options.context     = NULL;
                medusa_tcpsocket_accept_options.nonblocking = 1;
                medusa_tcpsocket_accept_options.enabled     = 1;
                medusa_tcpsocket_accept_options.buffered    = 1;
                medusa_tcpsocket = medusa_tcpsocket_accept_with_options(&medusa_tcpsocket_accept_options);
                if (MEDUSA_IS_ERR_OR_NULL(medusa_tcpsocket)) {
                        return MEDUSA_PTR_ERR(medusa_tcpsocket);
                }
        }
        return 0;
}

static int sigint_medusa_signal_onevent (struct medusa_signal *signal, unsigned int events, void *context, ...)
{
        (void) signal;
        (void) events;
        (void) context;
        g_running = 0;
        return medusa_monitor_break(medusa_signal_get_monitor(signal));
}

int main (int argc, char *argv[])
{
        int rc;
        int err;

        int c;
        int option_port;
        const char *option_address;

        struct medusa_tcpsocket *medusa_tcpsocket;
        struct medusa_tcpsocket_init_options medusa_tcpsocket_init_options;

        struct medusa_signal *medusa_signal;
        struct medusa_signal_init_options medusa_signal_init_options;

        struct medusa_monitor *medusa_monitor;
        struct medusa_monitor_init_options medusa_monitor_init_options;

        (void) argc;
        (void) argv;

        err             = 0;
        medusa_monitor  = NULL;

        option_port     = OPTION_PORT_DEFAULT;
        option_address  = OPTION_ADDRESS_DEFAULT;

        g_running = 1;

        while ((c = getopt_long(argc, argv, "ha:p:", longopts, NULL)) != -1) {
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
                                fprintf(stderr, "unknown option: %d\n", optopt);
                                err = -EINVAL;
                                goto out;
                }
        }

        rc = medusa_monitor_init_options_default(&medusa_monitor_init_options);
        if (rc < 0) {
                err = rc;
                goto out;
        }
        medusa_monitor = medusa_monitor_create(&medusa_monitor_init_options);
        if (MEDUSA_IS_ERR_OR_NULL(medusa_monitor)) {
                err = MEDUSA_PTR_ERR(medusa_monitor);
                goto out;
        }

        rc = medusa_signal_init_options_default(&medusa_signal_init_options);
        if (rc < 0) {
                err = rc;
                goto out;
        }
        medusa_signal_init_options.number     = SIGINT;
        medusa_signal_init_options.onevent    = sigint_medusa_signal_onevent;
        medusa_signal_init_options.context    = NULL;
        medusa_signal_init_options.singleshot = 0;
        medusa_signal_init_options.enabled    = 1;
        medusa_signal_init_options.monitor    = medusa_monitor;
        medusa_signal = medusa_signal_create_with_options(&medusa_signal_init_options);
        if (MEDUSA_IS_ERR_OR_NULL(medusa_signal)) {
                err = MEDUSA_PTR_ERR(medusa_signal);
                goto out;
        }

        rc = medusa_tcpsocket_init_options_default(&medusa_tcpsocket_init_options);
        if (rc < 0) {
                err = rc;
                goto out;
        }
        medusa_tcpsocket_init_options.monitor     = medusa_monitor;
        medusa_tcpsocket_init_options.onevent     = listener_medusa_tcpsocket_onevent;
        medusa_tcpsocket_init_options.context     = NULL;
        medusa_tcpsocket_init_options.nonblocking = 1;
        medusa_tcpsocket_init_options.reuseaddr   = 1;
        medusa_tcpsocket_init_options.reuseport   = 1;
        medusa_tcpsocket_init_options.backlog     = 128;
        medusa_tcpsocket_init_options.enabled     = 1;
        medusa_tcpsocket = medusa_tcpsocket_create_with_options(&medusa_tcpsocket_init_options);
        if (MEDUSA_IS_ERR_OR_NULL(medusa_tcpsocket)) {
                err = MEDUSA_PTR_ERR(medusa_tcpsocket);
                goto out;
        }
        rc = medusa_tcpsocket_bind(medusa_tcpsocket, MEDUSA_TCPSOCKET_PROTOCOL_ANY, option_address, option_port);
        if (rc < 0) {
                err = rc;
                goto out;
        }

        while (g_running == 1) {
                rc = medusa_monitor_run_once(medusa_monitor);
                if (rc < 0) {
                        err = rc;
                        goto out;
                }
        }

out:    if (!MEDUSA_IS_ERR_OR_NULL(medusa_monitor)) {
                medusa_monitor_destroy(medusa_monitor);
        }
        return err;
}
