
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <getopt.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <event2/event.h>
#include <event2/thread.h>

static int g_backend;
static unsigned int g_nsamples;
static unsigned int g_ntests;
static unsigned int g_npackets;
static double g_pinterval;

struct sender {
        int fd;
        unsigned int npackets;
        struct event *event;
};

struct receiver {
        int fd;
        struct event *event;
        unsigned int npackets;
};

static int *g_pipes;
static struct sender *g_senders;
static struct receiver *g_receivers;
static unsigned int g_active_senders;
static unsigned int g_active_receivers;

static void receiver_io_onevent (evutil_socket_t fd, short events, void *context)
{
        int rc;
        char ch;
        struct receiver *receiver = context;
        (void) fd;
        if (events & EV_READ) {
                rc = read(receiver->fd, &ch, 1);
                if (rc != 1) {
                        return;
                }
                receiver->npackets += 1;
                if (receiver->npackets >= g_npackets) {
                        rc = event_del(receiver->event);
                        if (rc != 0) {
                                return;
                        }
                        g_active_receivers -= 1;
                }
        }
}

static void sender_timer_onevent (evutil_socket_t fd, short events, void *context)
{
        int rc;
        struct sender *sender = context;
        (void) fd;
        if (events & EV_TIMEOUT) {
                rc = write(sender->fd, "e", 1);
                if (rc != 1) {
                        return;
                }
                sender->npackets += 1;
                if (sender->npackets >= g_npackets) {
                        rc = event_del(sender->event);
                        if (rc != 0) {
                                return;
                        }
                        g_active_senders -= 1;
                }
        }
}

static int test_poll (unsigned int poll)
{
        int rc;
        unsigned int i;
        unsigned int j;

        struct event *io;

        struct event *timer;
        struct timeval timer_timeval;

        struct event_base *event_base;

        (void) poll;

        event_base = NULL;
        evthread_use_pthreads();

        for (j = 0; j < g_nsamples; j++) {
                event_base = event_base_new();
                if (event_base == NULL) {
                        goto bail;
                }
                for (i = 0; i < g_ntests; i++) {
                        g_receivers[i].fd       = g_pipes[i * 2 + 0];
                        g_receivers[i].npackets = 0;

                        io = event_new(event_base, g_receivers[i].fd, EV_READ | EV_PERSIST, receiver_io_onevent, &g_receivers[i]);
                        if (io == NULL) {
                                goto bail;
                        }
                        g_receivers[i].event = io;

                        rc = event_add(io, NULL);
                        if (rc != 0) {
                                event_free(io);
                                goto bail;
                        }

                        g_senders[i].fd       = g_pipes[i * 2 + 1];
                        g_senders[i].npackets = 0;

                        timer = event_new(event_base, -1, EV_PERSIST, sender_timer_onevent, &g_senders[i]);
                        if (timer == NULL) {
                                goto bail;
                        }
                        g_senders[i].event = timer;

                        timer_timeval.tv_sec = (long long) g_pinterval;
                        timer_timeval.tv_usec = (long long) ((g_pinterval - timer_timeval.tv_sec) * 1e6);
                        rc = event_add(timer, &timer_timeval);
                        if (rc != 0) {
                                event_free(io);
                                goto bail;
                        }
                }
                rc = event_base_loop(event_base, EVLOOP_ONCE | EVLOOP_NONBLOCK);
                if (rc < 0) {
                        goto bail;
                }

                g_active_senders   = g_ntests;
                g_active_receivers = g_ntests;

                while (1) {
                        rc = event_base_loop(event_base, EVLOOP_ONCE);
                        if (rc < 0) {
                                goto bail;
                        }
                        if (g_active_senders == 0 &&
                            g_active_receivers == 0) {
                                break;
                        }
                }

                event_base_free(event_base);
        }

        return 0;
bail:   if (event_base != NULL) {
                event_base_free(event_base);
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
        g_ntests    = 10;
        g_npackets  = 10;
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

        rc = test_poll(0);
        if (rc != 0) {
                return -1;
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
