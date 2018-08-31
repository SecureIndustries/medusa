
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <getopt.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "medusa/error.h"
#include "medusa/clock.h"
#include "medusa/io.h"
#include "medusa/timer.h"
#include "medusa/monitor.h"

static const unsigned int g_polls[] = {
        MEDUSA_MONITOR_POLL_DEFAULT,
#if defined(__LINUX__)
        MEDUSA_MONITOR_POLL_EPOLL,
#endif
#if defined(__APPLE__)
        MEDUSA_MONITOR_POLL_KQUEUE,
#endif
        MEDUSA_MONITOR_POLL_POLL,
        MEDUSA_MONITOR_POLL_SELECT
};

static int g_backend;
static unsigned int g_nsamples;
static unsigned int g_ntests;
static unsigned int g_npackets;
static double g_pinterval;

struct sender {
        int fd;
        unsigned int npackets;
};

struct receiver {
        int fd;
        unsigned int npackets;
};

static int *g_pipes;
static struct sender *g_senders;
static struct receiver *g_receivers;
static unsigned int g_active_senders;
static unsigned int g_active_receivers;

static int receiver_io_onevent (struct medusa_io *io, unsigned int events, void *context, ...)
{
        int rc;
        char ch;
        struct receiver *receiver = context;
        if (events & MEDUSA_IO_EVENT_IN) {
                rc = read(receiver->fd, &ch, 1);
                if (rc != 1) {
                        return -1;
                }
                receiver->npackets += 1;
                if (receiver->npackets >= g_npackets) {
                        rc = medusa_io_set_enabled(io, 0);
                        if (rc < 0) {
                                return -1;
                        }
                        g_active_receivers -= 1;
                }
        }
        return 0;
}

static int sender_timer_onevent (struct medusa_timer *timer, unsigned int events, void *context, ...)
{
        int rc;
        struct sender *sender = context;
        if (events & MEDUSA_TIMER_EVENT_TIMEOUT) {
                rc = write(sender->fd, "e", 1);
                if (rc != 1) {
                        fprintf(stderr, "can not write\n");
                        return -1;
                }
                sender->npackets += 1;
                if (sender->npackets >= g_npackets) {
                        rc = medusa_timer_set_enabled(timer, 0);
                        if (rc < 0) {
                                fprintf(stderr, "can not disable\n");
                                return -1;
                        }
                        g_active_senders -= 1;
                }
        }
        return 0;
}

static int test_poll (unsigned int poll)
{
        int rc;
        unsigned int i;
        unsigned int j;

        struct medusa_io *io;
        struct medusa_io_init_options io_init_options;

        struct medusa_timer *timer;
        struct medusa_timer_init_options timer_init_options;

        struct medusa_monitor *monitor;
        struct medusa_monitor_init_options monitor_init_options;

        monitor = NULL;

        medusa_monitor_init_options_default(&monitor_init_options);
        monitor_init_options.poll.type = poll;

        g_active_senders   = g_ntests;
        g_active_receivers = g_ntests;

        for (j = 0; j < g_nsamples; j++) {
                monitor = medusa_monitor_create(&monitor_init_options);
                if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                        goto bail;
                }
                for (i = 0; i < g_ntests; i++) {
                        g_receivers[i].fd       = g_pipes[i * 2 + 0];
                        g_receivers[i].npackets = 0;

                        medusa_io_init_options_default(&io_init_options);
                        io_init_options.fd      = g_receivers[i].fd;
                        io_init_options.events  = MEDUSA_IO_EVENT_IN;
                        io_init_options.onevent = receiver_io_onevent;
                        io_init_options.context = &g_receivers[i];
                        io_init_options.enabled = 1;
                        io_init_options.monitor = monitor;
                        io = medusa_io_create_with_options(&io_init_options);
                        if (MEDUSA_IS_ERR_OR_NULL(io)) {
                                fprintf(stderr, "can not create io\n");
                                goto bail;
                        }

                        g_senders[i].fd       = g_pipes[i * 2 + 1];
                        g_senders[i].npackets = 0;

                        medusa_timer_init_options_default(&timer_init_options);
                        timer_init_options.initial    = drand48();
                        timer_init_options.interval   = g_pinterval;
                        timer_init_options.resolution = MEDUSA_TIMER_RESOLUTION_MILLISECONDS;
                        timer_init_options.singleshot = 0;
                        timer_init_options.onevent    = sender_timer_onevent;
                        timer_init_options.context    = &g_senders[i];
                        timer_init_options.enabled    = 1;
                        timer_init_options.monitor    = monitor;
                        timer = medusa_timer_create_with_options(&timer_init_options);
                        if (MEDUSA_IS_ERR_OR_NULL(timer)) {
                                fprintf(stderr, "can not create timer\n");
                                goto bail;
                        }

                }
                rc = medusa_monitor_run_once(monitor);
                if (rc < 0) {
                        fprintf(stderr, "can not run monitor\n");
                        goto bail;
                }

                while (1) {
                        rc = medusa_monitor_run_timeout(monitor, 1.0);
                        if (rc < 0) {
                                fprintf(stderr, "can not run monitor\n");
                                goto bail;
                        }
                        if (g_active_senders == 0 &&
                            g_active_receivers == 0) {
                                break;
                        }
                }

                medusa_monitor_destroy(monitor);
        }

        return 0;
bail:   if (monitor != NULL) {
                medusa_monitor_destroy(monitor);
        }
        return -1;
}

int main (int argc, char *argv[])
{
        int c;
        int rc;
        unsigned int i;

        g_backend   = -1;
        g_nsamples  = 1;
        g_ntests    = 100;
        g_npackets  = 100;
        g_pinterval = 0.001;

        while ((c = getopt(argc, argv, "hb:s:t:p:i:")) != -1) {
                switch (c) {
                        case 'b':
                                g_backend = atoi(optarg);
                                break;
                        case 's':
                                g_nsamples = atoi(optarg);
                                break;
                        case 't':
                                g_ntests = atoi(optarg);
                                break;
                        case 'p':
                                g_npackets = atoi(optarg);
                                break;
                        case 'i':
                                g_pinterval = atof(optarg);
                                break;
                        case 'h':
                                fprintf(stderr, "%s [-b backend] [-s samples] [-t tests] [-p packets] [-i interval]\n", argv[0]);
                                fprintf(stderr, "  -b: poll backend (default: %d)\n", g_backend);
                                fprintf(stderr, "  -s: sample count (default: %d)\n", g_nsamples);
                                fprintf(stderr, "  -t: number of concurrent tests (default: %d)\n", g_ntests);
                                fprintf(stderr, "  -p: number of packets for each test (default: %d)\n", g_npackets);
                                fprintf(stderr, "  -i: packet interval in floating seconds (default: %f)\n", g_pinterval);
                                return 0;
                        default:
                                fprintf(stderr, "unknown param: %c\n", c);
                                return -1;
                }
        }

        fprintf(stderr, "backend : %d\n", g_backend);
        fprintf(stderr, "samples : %d\n", g_nsamples);
        fprintf(stderr, "tests   : %d\n", g_ntests);
        fprintf(stderr, "packets : %d\n", g_npackets);
        fprintf(stderr, "interval: %f\n", g_pinterval);

        g_pipes = malloc(sizeof(int[2]) * g_ntests);
        if (g_pipes == NULL) {
                return -1;
        }

        for (i = 0; i < g_ntests; i++) {
#if 0
                rc = pipe(&g_pipes[i * 2]);
#else
                rc = socketpair(AF_UNIX, SOCK_STREAM, 0, &g_pipes[i * 2]);
#endif
                if (rc != 0) {
                        fprintf(stderr, "can not create pair: %d\n", i);
                        return -1;
                }
        }

        g_senders = malloc(sizeof(struct sender) * g_ntests);
        if (g_senders == NULL) {
                return -1;
        }
        g_receivers = malloc(sizeof(struct receiver) * g_ntests);
        if (g_receivers == NULL) {
                return -1;
        }

        if (g_backend >= 0) {
                fprintf(stderr, "testing poll: %d ... ", g_backend);

                rc = test_poll(g_backend);
                if (rc != 0) {
                        fprintf(stderr, "fail\n");
                        return -1;
                } else {
                        fprintf(stderr, "success\n");
                }
        } else {
                for (i = 0; i < sizeof(g_polls) / sizeof(g_polls[0]); i++) {
                        fprintf(stderr, "testing poll: %d ... ", g_polls[i]);

                        rc = test_poll(g_polls[i]);
                        if (rc != 0) {
                                fprintf(stderr, "fail\n");
                                return -1;
                        } else {
                                fprintf(stderr, "success\n");
                        }
                }
        }

        for (i = 0; i < g_ntests; i++) {
                close(g_pipes[i * 2]);
                close(g_pipes[i * 2 + 1]);
        }
        free(g_pipes);
        free(g_senders);
        free(g_receivers);
        return 0;
}
