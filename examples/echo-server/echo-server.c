
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>

#include <sys/uio.h>

#include <readline/readline.h>
#include <readline/history.h>

#include "medusa/error.h"
#include "medusa/buffer.h"
#include "medusa/io.h"
#include "medusa/tcpsocket.h"
#include "medusa/monitor.h"

static int g_running;

#define OPTION_ADDRESS_DEFAULT  "0.0.0.0"
#define OPTION_PORT_DEFAULT     12345
#define OPTION_CLI_DEFAULT      0

#define OPTION_HELP             'h'
#define OPTION_ADDRESS          'a'
#define OPTION_PORT             'p'
#define OPTION_CLI              'c'
static struct option longopts[] = {
        { "help",               no_argument,            NULL,   OPTION_HELP     },
        { "address",            required_argument,      NULL,   OPTION_ADDRESS  },
        { "port",               required_argument,      NULL,   OPTION_PORT     },
        { "cli",                required_argument,      NULL,   OPTION_CLI      },
        { NULL,                 0,                      NULL,   0               }
};

static void usage (const char *pname)
{
        fprintf(stdout, "usage: %s [-a address] [-p port] [-c cli]:\n", pname);
        fprintf(stdout, "  -h. --help   : this text\n");
        fprintf(stdout, "  -a, --address: listening address (values: interface ip address, default: %s)\n", OPTION_ADDRESS_DEFAULT);
        fprintf(stdout, "  -p. --port   : listening port (values: 0 < port < 65536, default: %d)\n", OPTION_PORT_DEFAULT);
        fprintf(stdout, "  -c. --cli    : enable cli (values: 1 / 0, default: %d)\n", OPTION_CLI_DEFAULT);
}

struct command {
        char *name;
        int (*func)(int argc, char *argv[]);
        char *help;
};

static int command_quit (int argc, char *argv[])
{
        (void) argc;
        (void) argv;
        g_running = 0;
        return 1;
}

static struct command *commands[] = {
        &(struct command) {
                "quit",
                command_quit,
                "quit application"
        },
        NULL,
};

static int readline_process (char *command)
{
        int ret;
        char *b;
        char *p;
        int argc;
        char **argv;
        struct command **pc;

        if (command == NULL) {
                return 0;
        }
        if (strlen(command) == 0) {
                return 0;
        }

        {
                HIST_ENTRY *hist;
                hist = current_history();
                if (hist == NULL ||
                    strcmp(hist->line, command) != 0) {
                        add_history(command);
                }
        }

        ret = 0;
        argc = 0;
        argv = NULL;
        b = strdup(command);
        p = b;

        while (*p) {
                while (isspace(*p)) {
                        p++;
                }

                if (*p == '"' || *p == '\'') {
                        char const delim = *p;
                        char *const begin = ++p;

                        while (*p && *p != delim) {
                                p++;
                        }
                        if (*p) {
                                *p++ = '\0';
                                argv = (char **) realloc(argv, sizeof(char *) * (argc + 1));
                                argv[argc] = begin;
                                argc++;
                        } else {
                                goto out;
                        }
                } else {
                        char *const begin = p;

                        while (*p && !isspace(*p)) {
                                p++;
                        }
                        if (*p) {
                                *p++ = '\0';
                                argv = (char **) realloc(argv, sizeof(char *) * (argc + 1));
                                argv[argc] = begin;
                                argc++;
                        } else if (p != begin) {
                                argv = (char **) realloc(argv, sizeof(char *) * (argc + 1));
                                argv[argc] = begin;
                                argc++;
                        }
                }
        }

        argv = (char **) realloc(argv, sizeof(char *) * (argc + 1));
        argv[argc] = NULL;

        if (strcmp(argv[0], "help") == 0) {
                fprintf(stdout, "mbus test client cli\n");
                fprintf(stdout, "\n");
                fprintf(stdout, "commands:\n");
                for (pc = commands; *pc; pc++) {
                        int l;
                        const char *h;
                        const char *e;
                        fprintf(stdout, "  %-15s - ", (*pc)->name);
                        l = 0;
                        h = (*pc)->help;
                        while (h != NULL && *h != '\0') {
                                e = strchr(h, '\n');
                                if (e == NULL) {
                                        e = h + strlen(h);
                                } else {
                                        e += 1;
                                }
                                if (l == 0) {
                                        fprintf(stdout, "%.*s", (int) (e - h), h);
                                } else {
                                        fprintf(stdout, "  %-15s   %.*s", "", (int) (e - h), h);
                                }
                                h = e;
                                l += 1;
                        }
                        fprintf(stdout, "\n");
                }
                fprintf(stdout, "\n");
                fprintf(stdout, "%-15s   - command specific help\n", "command --help");
        } else {
                for (pc = commands; *pc; pc++) {
                        if (strcmp((*pc)->name, argv[0]) == 0) {
                                ret = (*pc)->func(argc, &argv[0]);
                                if (ret < 0) {
                                        fprintf(stderr, "command: %s failed: %s\n", argv[0], (ret == -2) ? "invalid arguments" : "internal error");
                                }
                                break;
                        }
                }
                if (*pc == NULL) {
                        fprintf(stderr, "command: %s not found\n", argv[0]);
                }
        }

out:
        free(argv);
        free(b);
        return ret;
}

static char * readline_strip (char *buf)
{
        char *start;
        if (buf == NULL) {
                return NULL;
        }
        while ((*buf != '\0') && (buf[strlen(buf) - 1] < 33)) {
                buf[strlen(buf) - 1] = '\0';
        }
        start = buf;
        while (*start && (*start < 33)) {
                start++;
        }
        return start;
}

static void readline_process_line (char *line)
{
        if (line != NULL) {
                readline_strip(line);
                readline_process(line);
                free(line);
        }
}

static int readline_medusa_io_onevent (struct medusa_io *io, unsigned int events, void *context, ...)
{
        (void) io;
        (void) context;
        if (events & MEDUSA_IO_EVENT_IN) {
                rl_callback_read_char();
        }
        return 0;
}

static int client_medusa_tcpsocket_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, ...)
{
        int rc;
        int64_t rlen;
        int64_t wlen;
        struct medusa_buffer *rbuffer;
        int i;
        int niovecs;
        struct iovec iovecs[16];
        (void) context;
        if (events & MEDUSA_TCPSOCKET_EVENT_READ) {
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
                wlen = medusa_tcpsocket_writev(tcpsocket, iovecs, niovecs);
                if (wlen < 0) {
                        return wlen;
                }
                if (wlen != rlen) {
                        return -EIO;
                }
                rc = medusa_buffer_choke(rbuffer, wlen);
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
                medusa_tcpsocket = medusa_tcpsocket_accept_with_options(&medusa_tcpsocket_accept_options);
                if (MEDUSA_IS_ERR_OR_NULL(medusa_tcpsocket)) {
                        return MEDUSA_PTR_ERR(medusa_tcpsocket);
                }
        }
        return 0;
}

int main (int argc, char *argv[])
{
        int rc;
        int err;

        int c;
        int option_port;
        const char *option_address;
        int option_cli;

        struct medusa_io *medusa_io;
        struct medusa_io_init_options medusa_io_init_options;

        struct medusa_tcpsocket *medusa_tcpsocket;
        struct medusa_tcpsocket_init_options medusa_tcpsocket_init_options;

        struct medusa_monitor *medusa_monitor;
        struct medusa_monitor_init_options medusa_monitor_init_options;

        (void) argc;
        (void) argv;

        err             = 0;
        medusa_monitor  = NULL;

        option_port     = OPTION_PORT_DEFAULT;
        option_address  = OPTION_ADDRESS_DEFAULT;
        option_cli      = OPTION_CLI_DEFAULT;

        g_running = 1;

        while ((c = getopt_long(argc, argv, "ha:p:c:", longopts, NULL)) != -1) {
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
                        case OPTION_CLI:
                                option_cli = atoi(optarg);
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

        if (option_cli) {
                rc = medusa_io_init_options_default(&medusa_io_init_options);
                if (rc < 0) {
                        err = rc;
                        goto out;
                }
                medusa_io_init_options.monitor = medusa_monitor;
                medusa_io_init_options.fd      = 0;
                medusa_io_init_options.onevent = readline_medusa_io_onevent;
                medusa_io_init_options.context = NULL;
                medusa_io_init_options.events  = MEDUSA_IO_EVENT_IN;
                medusa_io_init_options.enabled = 1;
                medusa_io = medusa_io_create_with_options(&medusa_io_init_options);
                if (MEDUSA_IS_ERR_OR_NULL(medusa_io)) {
                        err = MEDUSA_PTR_ERR(medusa_io);
                        goto out;
                }
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

        if (option_cli) {
                rl_callback_handler_install("medusa-echo-server> ", readline_process_line);
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
        if (option_cli) {
                rl_cleanup_after_signal();
                clear_history();
        }
        return err;
}
