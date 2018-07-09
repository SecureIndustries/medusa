
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
#include "medusa/subject.h"
#include "medusa/monitor.h"

static const unsigned int g_backends[] = {
        medusa_monitor_backend_default,
#if defined(__LINUX__)
        medusa_monitor_backend_epoll,
#endif
#if defined(__APPLE__)
        medusa_monitor_backend_kqueue,
#endif
//        medusa_monitor_backend_poll,
//        medusa_monitor_backend_select
};

static int subject_callback (void *context, struct medusa_monitor *monitor, struct medusa_subject *subject, unsigned int events)
{
        int rc;
        if (context == NULL) {
                fprintf(stderr, "context is invalid\n");
                goto bail;
        }
        if (monitor == NULL) {
                fprintf(stderr, "monitor is invalid\n");
                goto bail;
        }
        if (subject == NULL) {
                fprintf(stderr, "subject is invalid\n");
                goto bail;
        }
        if (events == 0) {
                fprintf(stderr, "events is invalid\n");
                goto bail;
        }
        fprintf(stderr, "callback:\n");
        fprintf(stderr, "  subject: %p\n", subject);
        fprintf(stderr, "  fd     : %d\n", medusa_subject_io_get_fd(subject));
        fprintf(stderr, "  events : 0x%08x\n", events);
        if (events & medusa_event_out) {
                char value;
                int *write_length = context;
                value = rand();
                rc = write(medusa_subject_io_get_fd(subject), &value, sizeof(value));
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
                int *read_length = context;
                rc = read(medusa_subject_io_get_fd(subject), &value, sizeof(value));
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
        return 0;
bail:   return -1;
}

static int test_backend (unsigned int backend)
{
        int rc;
        int sv[2];

        int length;
        int write_length;
        int write_finished;
        int read_length;

        struct medusa_monitor *monitor;
        struct medusa_monitor_init_options options;

        struct medusa_subject *subject[2];

        monitor = NULL;
        sv[0] = -1;
        sv[1] = -1;
        subject[0] = NULL;
        subject[1] = NULL;

        length = rand() % 1000;
        length = 1;
        write_length = length;
        write_finished = 0;
        read_length = 0;

        memset(&options, 0, sizeof(struct medusa_monitor_init_options));
        options.backend.type = backend;

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

        subject[0] = medusa_subject_create_io(sv[0], subject_callback, &write_length);
        if (subject[0] == NULL) {
                fprintf(stderr, "can not create subject\n");
                goto bail;
        }
        fprintf(stderr, "  subject: %p\n", subject[0]);
        rc = medusa_monitor_add(monitor, subject[0], medusa_event_out);
        if (rc != 0) {
                fprintf(stderr, "can not add subject\n");
                goto bail;
        }

        subject[1] = medusa_subject_create_io(sv[1], subject_callback, &read_length);
        if (subject[1] == NULL) {
                fprintf(stderr, "can not create subject\n");
                goto bail;
        }
        fprintf(stderr, "  subject: %p\n", subject[1]);
        rc = medusa_monitor_add(monitor, subject[1], medusa_event_in);
        if (rc != 0) {
                fprintf(stderr, "can not add subject\n");
                goto bail;
        }

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
                        fprintf(stderr, "    deleting writer\n");
                        rc = medusa_monitor_del(monitor, subject[0]);
                        if (rc != 0) {
                                fprintf(stderr, "can not del subject\n");
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

        medusa_subject_destroy(subject[0]);
        medusa_subject_destroy(subject[1]);
        medusa_monitor_destroy(monitor);
        return 0;
bail:   if (monitor != NULL) {
                medusa_monitor_destroy(monitor);
        }
        if (subject[0] != NULL) {
                medusa_subject_destroy(subject[0]);
        }
        if (subject[1] != NULL) {
                medusa_subject_destroy(subject[1]);
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

        for (i = 0; i < sizeof(g_backends) / sizeof(g_backends[0]); i++) {
                alarm(5);
                fprintf(stderr, "testing backend: %d\n", g_backends[i]);
                rc = test_backend(g_backends[i]);
                if (rc != 0) {
                        fprintf(stderr, "backend: %d test failed\n", g_backends[i]);
                        return -1;
                }
        }

        return 0;
}
