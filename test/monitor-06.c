
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "medusa/event.h"
#include "medusa/time.h"
#include "medusa/io.h"
#include "medusa/monitor.h"

static const unsigned int g_polls[] = {
        medusa_monitor_poll_default,
#if defined(__LINUX__)
        medusa_monitor_poll_epoll,
#endif
#if defined(__APPLE__)
        medusa_monitor_poll_kqueue,
#endif
        medusa_monitor_poll_poll,
//        medusa_monitor_poll_select
};

static void io_activated_callback (struct medusa_io *io, unsigned int events, void *context)
{
        int rc;
        if (io == NULL) {
                fprintf(stderr, "io is invalid\n");
                goto bail;
        }
        if (events == 0) {
                fprintf(stderr, "events is invalid\n");
                goto bail;
        }
        if (context == 0) {
                fprintf(stderr, "context is invalid\n");
                goto bail;
        }
        fprintf(stderr, "callback:\n");
        fprintf(stderr, "  io     : %p\n", io);
        fprintf(stderr, "  fd     : %d\n", medusa_io_get_fd(io));
        fprintf(stderr, "  events : 0x%08x\n", events);
        if (events & medusa_event_out) {
                char value;
                int *write_length = (int *) context;
                value = rand();
                rc = write(medusa_io_get_fd(io), &value, sizeof(value));
                if (rc != sizeof(value)) {
                        if (errno != EAGAIN &&
                            errno != EWOULDBLOCK) {
                                fprintf(stderr, "can not write\n");
                                goto bail;
                        }
                } else {
                        *write_length -= 1;
                }
        } else if (events & medusa_event_in) {
                char value;
                int *read_length = (int *) context;
                rc = read(medusa_io_get_fd(io), &value, sizeof(value));
                if (rc != sizeof(value)) {
                        if (errno != EAGAIN &&
                            errno != EWOULDBLOCK) {
                                fprintf(stderr, "can not read\n");
                                goto bail;
                        }
                } else {
                        *read_length += 1;
                }
        }
        return;
bail:   return;
}

static int test_poll (unsigned int poll)
{
        int rc;
        int sv[2];

        int length;
        int write_length;
        int write_finished;
        int read_length;

        struct medusa_monitor *monitor;
        struct medusa_monitor_init_options options;

        struct medusa_io *io[2];

        monitor = NULL;
        sv[0] = -1;
        sv[1] = -1;
        io[0] = NULL;
        io[1] = NULL;

        length = rand() % 10000;
        write_length = length;
        write_finished = 0;
        read_length = 0;

        memset(&options, 0, sizeof(struct medusa_monitor_init_options));
        options.poll.type = poll;

        monitor = medusa_monitor_create(&options);
        if (monitor == NULL) {
                fprintf(stderr, "can not create monitor\n");
                goto bail;
        }

        rc = socketpair(AF_LOCAL, SOCK_STREAM, 0, sv);
        if (rc != 0) {
                fprintf(stderr, "can not create socket pair\n");
                goto bail;
        }

        fprintf(stderr, "pair: %d, %d\n", sv[0], sv[1]);

        io[0] = medusa_io_create();
        if (io[0] == NULL) {
                fprintf(stderr, "can not create io\n");
                goto bail;
        }
        rc = medusa_io_set_fd(io[0], sv[0]);
        rc = medusa_io_set_events(io[0], medusa_event_out);
        rc = medusa_io_set_activated_callback(io[0], io_activated_callback, &write_length);
        rc = medusa_io_set_enabled(io[0], 1);
        rc = medusa_monitor_add(monitor, (struct medusa_subject *) io[0]);
        if (rc != 0) {
                fprintf(stderr, "can not setup io[0]\n");
                goto bail;
        }
        fprintf(stderr, "  io: %p\n", io[0]);

        io[1] = medusa_io_create();
        if (io[1] == NULL) {
                fprintf(stderr, "can not create io\n");
                goto bail;
        }
        rc = medusa_io_set_fd(io[1], sv[1]);
        rc = medusa_io_set_events(io[1], medusa_event_in);
        rc = medusa_io_set_activated_callback(io[1], io_activated_callback, &read_length);
        rc = medusa_io_set_enabled(io[1], 1);
        rc = medusa_monitor_add(monitor, (struct medusa_subject *) io[1]);
        if (rc != 0) {
                fprintf(stderr, "can not setup io[1]\n");
                goto bail;
        }
        fprintf(stderr, "  io: %p\n", io[1]);

        while (1) {
                fprintf(stderr, "running monitor\n");
                rc = medusa_monitor_run(monitor, medusa_monitor_run_once);
                if (rc != 0) {
                        fprintf(stderr, "can not run monitor\n");
                        goto bail;
                }
                fprintf(stderr, "loop:\n");
                fprintf(stderr, "  write_length: %d\n", write_length);
                if (write_length == 0 &&
                    write_finished == 0) {
                        fprintf(stderr, "    disable writer\n");
                        rc = medusa_io_set_enabled(io[0], 0);
                        if (rc != 0) {
                                fprintf(stderr, "can not setup io\n");
                                goto bail;
                        }
                        write_finished = 1;
                }
                fprintf(stderr, "  read_length: %d\n", read_length);
                if (read_length == length) {
                        break;
                }
        }

        if (write_length != 0) {
                fprintf(stderr, "can not write, write_length: %d\n", write_length);
                goto bail;
        }
        if (read_length != length) {
                fprintf(stderr, "can not read\n");
                goto bail;
        }

        fprintf(stderr, "finish\n");

        close(sv[0]);
        close(sv[1]);
        medusa_monitor_destroy(monitor);
        return 0;
bail:   if (monitor != NULL) {
                medusa_monitor_destroy(monitor);
        }
        if (sv[0] >= 0) {
                close(sv[0]);
        }
        if (sv[1] >= 0) {
                close(sv[1]);
        }
        return 01;
}

static void alarm_handler (int sig)
{
        (void) sig;
        abort();
}

int main (int argc, char *argv[])
{
        int rc;
        unsigned int i;

        (void) argc;
        (void) argv;

        srand(time(NULL));
        signal(SIGALRM, alarm_handler);

        for (i = 0; i < sizeof(g_polls) / sizeof(g_polls[0]); i++) {
                alarm(5);
                fprintf(stderr, "testing poll: %d\n", g_polls[i]);
                rc = test_poll(g_polls[i]);
                if (rc != 0) {
                        fprintf(stderr, "poll: %d test failed\n", g_polls[i]);
                        return -1;
                }
        }

        return 0;
}
