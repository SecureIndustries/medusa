
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

#include "medusa/error.h"
#include "medusa/http.h"
#include "medusa/http-server.h"
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

static int http_server_callback_stat (struct medusa_http_server *server, void *cookie, const char *path, struct medusa_http_stat *stat)
{
        (void) server;
        (void) cookie;
        (void) path;
        (void) stat;
        return 0;
}

static void * http_server_callback_open (struct medusa_http_server *server, void *cookie, const char *path, unsigned int mode)
{
        (void) server;
        (void) cookie;
        (void) path;
        (void) mode;
        return NULL;
}

static int http_server_callback_read (struct medusa_http_server *server, void *cookie, void *handle, void *buffer, int length)
{
        (void) server;
        (void) cookie;
        (void) handle;
        (void) buffer;
        (void) length;
        return 0;
}

static int http_server_callback_write (struct medusa_http_server *server, void *cookie, void *handle, const void *buffer, int length)
{
        (void) server;
        (void) cookie;
        (void) handle;
        (void) buffer;
        (void) length;
        return 0;
}

static long long http_server_callback_seek (struct medusa_http_server *server, void *cookie, void *handle, long long offset, unsigned int whence)
{
        (void) server;
        (void) cookie;
        (void) handle;
        (void) offset;
        (void) whence;
        return 0;
}

static int http_server_callback_close (struct medusa_http_server *server, void *cookie, void *handle)
{
        (void) server;
        (void) cookie;
        (void) handle;
        return 0;
}

static int test_poll (unsigned int poll)
{
        int rc;

        struct medusa_monitor *monitor;
        struct medusa_monitor_init_options monitor_options;

        struct medusa_http_server *http_server;
        struct medusa_http_server_init_options http_server_options;
        struct medusa_http_server_callback http_server_callback;

        monitor = NULL;

        rc = medusa_monitor_init_options_default(&monitor_options);
        if (rc < 0) {
                fprintf(stderr, "medusa_monitor_init_options_default failed\n");
                goto bail;
        }
        monitor_options.poll.type = poll;

        monitor = medusa_monitor_create(&monitor_options);
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                fprintf(stderr, "medusa_monitor_init_options_default failed\n");
                goto bail;
        }

        rc = medusa_http_server_init_options_default(&http_server_options);
        if (rc < 0) {
                fprintf(stderr, "medusa_http_server_init_options_default failed\n");
                goto bail;
        }
        http_server_options.port = 12345;

        http_server = medusa_http_server_create_with_options(monitor, &http_server_options);
        if (MEDUSA_IS_ERR_OR_NULL(http_server)) {
                fprintf(stderr, "medusa_http_server_create_with_options failed\n");
                goto bail;
        }
        rc = medusa_http_server_set_enabled(http_server, 1);
        if (rc < 0) {
                fprintf(stderr, "medusa_http_server_set_enabled failed\n");
                goto bail;
        }
        http_server_callback.stat = http_server_callback_stat;
        http_server_callback.open = http_server_callback_open;
        http_server_callback.read = http_server_callback_read;
        http_server_callback.write = http_server_callback_write;
        http_server_callback.seek = http_server_callback_seek;
        http_server_callback.close = http_server_callback_close;
        rc = medusa_http_server_add_path(http_server, NULL, &http_server_callback, NULL);
        if (rc < 0) {
                fprintf(stderr, "medusa_http_server_add_path failed\n");
                goto bail;
        }
        rc = medusa_http_server_del_path(http_server, NULL);
        if (rc < 0) {
                fprintf(stderr, "medusa_http_server_del_path failed\n");
                goto bail;
        }

        medusa_monitor_destroy(monitor);
        return 0;
bail:   if (!MEDUSA_IS_ERR_OR_NULL(monitor)) {
                medusa_monitor_destroy(monitor);
        }
        return -1;
}

static void sigalarm_handler (int sig)
{
        (void) sig;
        abort();
}

static void sigint_handler (int sig)
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
        signal(SIGALRM, sigalarm_handler);
        signal(SIGINT, sigint_handler);

        for (i = 0; i < sizeof(g_polls) / sizeof(g_polls[0]); i++) {
                alarm(5);
                fprintf(stderr, "testing poll: %d\n", g_polls[i]);

                rc = test_poll(g_polls[i]);
                if (rc != 0) {
                        fprintf(stderr, "test_poll failed\n");
                        return -1;
                }
        }
        return 0;
}
