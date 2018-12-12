
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>

#include "error.h"
#include "pool.h"
#include "queue.h"
#include "buffer.h"
#include "subject-struct.h"
#include "io.h"
#include "io-private.h"
#include "timer.h"
#include "timer-private.h"
#include "http-request.h"
#include "http-request-private.h"
#include "http-request-struct.h"
#include "monitor-private.h"

#define MIN(a, b)                               (((a) < (b)) ? (a) : (b))

#define MEDUSA_HTTP_REQUEST_USE_POOL               1

#define MEDUSA_HTTP_REQUEST_STATE_MASK             0xff
#define MEDUSA_HTTP_REQUEST_STATE_SHIFT            0x18

#if defined(MEDUSA_HTTP_REQUEST_USE_POOL) && (MEDUSA_HTTP_REQUEST_USE_POOL == 1)
static struct medusa_pool *g_pool;
#endif

static inline unsigned int http_request_get_state (const struct medusa_http_request *http_request)
{
        return http_request->state;
}

static inline int http_request_set_state (struct medusa_http_request *http_request, unsigned int state)
{
        http_request->state = state;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_http_request_init_options_default (struct medusa_http_request_init_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_http_request_init_options));
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_http_request_init_unlocked (struct medusa_http_request *http_request, struct medusa_monitor *monitor, int (*onevent) (struct medusa_http_request *http_request, unsigned int events, void *context, ...), void *context)
{
        int rc;
        struct medusa_http_request_init_options options;
        rc = medusa_http_request_init_options_default(&options);
        if (rc < 0) {
                return rc;
        }
        options.monitor = monitor;
        options.onevent = onevent;
        options.context = context;
        return medusa_http_request_init_with_options_unlocked(http_request, &options);
}

__attribute__ ((visibility ("default"))) int medusa_http_request_init (struct medusa_http_request *http_request, struct medusa_monitor *monitor, int (*onevent) (struct medusa_http_request *http_request, unsigned int events, void *context, ...), void *context)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(http_request)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return -EINVAL;
        }
        medusa_monitor_lock(monitor);
        rc = medusa_http_request_init_unlocked(http_request, monitor, onevent, context);
        medusa_monitor_unlock(monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_http_request_init_with_options_unlocked (struct medusa_http_request *http_request, const struct medusa_http_request_init_options *options)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(http_request)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                return -EINVAL;
        }
        memset(http_request, 0, sizeof(struct medusa_http_request));
        medusa_subject_set_type(&http_request->subject, MEDUSA_SUBJECT_TYPE_HTTP_REQUEST);
        http_request->subject.monitor = NULL;
        http_request_set_state(http_request, MEDUSA_HTTP_REQUEST_STATE_DISCONNECTED);
        http_request->onevent = options->onevent;
        http_request->context = options->context;
        rc = medusa_monitor_add_unlocked(options->monitor, &http_request->subject);
        if (rc < 0) {
                return rc;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_http_request_init_with_options (struct medusa_http_request *http_request, const struct medusa_http_request_init_options *options)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(http_request)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return -EINVAL;
        }
        medusa_monitor_lock(options->monitor);
        rc = medusa_http_request_init_with_options_unlocked(http_request, options);
        medusa_monitor_unlock(options->monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void medusa_http_request_uninit_unlocked (struct medusa_http_request *http_request)
{
        if (MEDUSA_IS_ERR_OR_NULL(http_request)) {
                return;
        }
        if (http_request->subject.monitor != NULL) {
                medusa_monitor_del_unlocked(&http_request->subject);
        } else {
                medusa_http_request_onevent_unlocked(http_request, MEDUSA_HTTP_REQUEST_EVENT_DESTROY);
        }
}

__attribute__ ((visibility ("default"))) void medusa_http_request_uninit (struct medusa_http_request *http_request)
{
        if (MEDUSA_IS_ERR_OR_NULL(http_request)) {
                return;
        }
        medusa_monitor_lock(http_request->subject.monitor);
        medusa_http_request_uninit_unlocked(http_request);
        medusa_monitor_unlock(http_request->subject.monitor);
}

__attribute__ ((visibility ("default"))) struct medusa_http_request * medusa_http_request_create_unlocked (struct medusa_monitor *monitor, int (*onevent) (struct medusa_http_request *http_request, unsigned int events, void *context, ...), void *context)
{
        int rc;
        struct medusa_http_request_init_options options;
        rc = medusa_http_request_init_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.monitor = monitor;
        options.onevent = onevent;
        options.context = context;
        return medusa_http_request_create_with_options_unlocked(&options);
}

__attribute__ ((visibility ("default"))) struct medusa_http_request * medusa_http_request_create (struct medusa_monitor *monitor, int (*onevent) (struct medusa_http_request *http_request, unsigned int events, void *context, ...), void *context)
{
        struct medusa_http_request *rc;
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(monitor);
        rc = medusa_http_request_create_unlocked(monitor, onevent, context);
        medusa_monitor_unlock(monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_http_request * medusa_http_request_create_with_options_unlocked (const struct medusa_http_request_init_options *options)
{
        int rc;
        struct medusa_http_request *http_request;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
#if defined(MEDUSA_HTTP_REQUEST_USE_POOL) && (MEDUSA_HTTP_REQUEST_USE_POOL == 1)
        http_request = medusa_pool_malloc(g_pool);
#else
        http_request = malloc(sizeof(struct medusa_http_request));
#endif
        if (MEDUSA_IS_ERR_OR_NULL(http_request)) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(http_request, 0, sizeof(struct medusa_http_request));
        rc = medusa_http_request_init_with_options_unlocked(http_request, options);
        if (rc < 0) {
                medusa_http_request_destroy_unlocked(http_request);
                return MEDUSA_ERR_PTR(rc);
        }
        http_request->subject.flags |= MEDUSA_SUBJECT_FLAG_ALLOC;
        return http_request;
}

__attribute__ ((visibility ("default"))) struct medusa_http_request * medusa_http_request_create_with_options (const struct medusa_http_request_init_options *options)
{
        struct medusa_http_request *rc;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(options->monitor);
        rc = medusa_http_request_create_with_options_unlocked(options);
        medusa_monitor_unlock(options->monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void medusa_http_request_destroy_unlocked (struct medusa_http_request *http_request)
{
        if (MEDUSA_IS_ERR_OR_NULL(http_request)) {
                return;
        }
        medusa_http_request_uninit_unlocked(http_request);
}

__attribute__ ((visibility ("default"))) void medusa_http_request_destroy (struct medusa_http_request *http_request)
{
        if (MEDUSA_IS_ERR_OR_NULL(http_request)) {
                return;
        }
        medusa_monitor_lock(http_request->subject.monitor);
        medusa_http_request_destroy_unlocked(http_request);
        medusa_monitor_unlock(http_request->subject.monitor);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_http_request_get_state_unlocked (const struct medusa_http_request *http_request)
{
        if (MEDUSA_IS_ERR_OR_NULL(http_request)) {
                return MEDUSA_HTTP_REQUEST_STATE_UNKNWON;
        }
        return http_request_get_state(http_request);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_http_request_get_state (const struct medusa_http_request *http_request)
{
        unsigned int rc;
        if (MEDUSA_IS_ERR_OR_NULL(http_request)) {
                return MEDUSA_HTTP_REQUEST_STATE_UNKNWON;
        }
        medusa_monitor_lock(http_request->subject.monitor);
        rc = medusa_http_request_get_state_unlocked(http_request);
        medusa_monitor_unlock(http_request->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_http_request_set_connect_timeout_unlocked (struct medusa_http_request *http_request, double timeout)
{
        if (MEDUSA_IS_ERR_OR_NULL(http_request)) {
                return -EINVAL;
        }
        (void) timeout;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_http_request_set_connect_timeout (struct medusa_http_request *http_request, double timeout)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(http_request)) {
                return -EINVAL;
        }
        medusa_monitor_lock(http_request->subject.monitor);
        rc = medusa_http_request_set_connect_timeout_unlocked(http_request, timeout);
        medusa_monitor_unlock(http_request->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) double medusa_http_request_get_connect_timeout_unlocked (const struct medusa_http_request *http_request)
{
        if (MEDUSA_IS_ERR_OR_NULL(http_request)) {
                return -EINVAL;
        }
        return -EIO;
}

__attribute__ ((visibility ("default"))) double medusa_http_request_get_connect_timeout (const struct medusa_http_request *http_request)
{
        double rc;
        if (MEDUSA_IS_ERR_OR_NULL(http_request)) {
                return -EINVAL;
        }
        medusa_monitor_lock(http_request->subject.monitor);
        rc = medusa_http_request_get_connect_timeout(http_request);
        medusa_monitor_unlock(http_request->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_http_request_set_read_timeout_unlocked (struct medusa_http_request *http_request, double timeout)
{
        if (MEDUSA_IS_ERR_OR_NULL(http_request)) {
                return -EINVAL;
        }
        (void) timeout;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_http_request_set_read_timeout (struct medusa_http_request *http_request, double timeout)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(http_request)) {
                return -EINVAL;
        }
        medusa_monitor_lock(http_request->subject.monitor);
        rc = medusa_http_request_set_read_timeout_unlocked(http_request, timeout);
        medusa_monitor_unlock(http_request->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) double medusa_http_request_get_read_timeout_unlocked (const struct medusa_http_request *http_request)
{
        if (MEDUSA_IS_ERR_OR_NULL(http_request)) {
                return -EINVAL;
        }
        return -EIO;
}

__attribute__ ((visibility ("default"))) double medusa_http_request_get_read_timeout (const struct medusa_http_request *http_request)
{
        double rc;
        if (MEDUSA_IS_ERR_OR_NULL(http_request)) {
                return -EINVAL;
        }
        medusa_monitor_lock(http_request->subject.monitor);
        rc = medusa_http_request_get_read_timeout(http_request);
        medusa_monitor_unlock(http_request->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_http_request_onevent_unlocked (struct medusa_http_request *http_request, unsigned int events)
{
        int ret;
        struct medusa_monitor *monitor;
        ret = 0;
        monitor = http_request->subject.monitor;
        if (http_request->onevent != NULL) {
                medusa_monitor_unlock(monitor);
                ret = http_request->onevent(http_request, events, http_request->context);
                medusa_monitor_lock(monitor);
        }
        if (events & MEDUSA_HTTP_REQUEST_EVENT_DESTROY) {
                if (http_request->subject.flags & MEDUSA_SUBJECT_FLAG_ALLOC) {
#if defined(MEDUSA_HTTP_REQUEST_USE_POOL) && (MEDUSA_HTTP_REQUEST_USE_POOL == 1)
                        medusa_pool_free(http_request);
#else
                        free(http_request);
#endif
                } else {
                        memset(http_request, 0, sizeof(struct medusa_http_request));
                }
        }
        return ret;
}

__attribute__ ((visibility ("default"))) int medusa_http_request_onevent (struct medusa_http_request *http_request, unsigned int events)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(http_request)) {
                return -EINVAL;
        }
        medusa_monitor_lock(http_request->subject.monitor);
        rc = medusa_http_request_onevent_unlocked(http_request, events);
        medusa_monitor_unlock(http_request->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_http_request_get_monitor_unlocked (struct medusa_http_request *http_request)
{
        if (MEDUSA_IS_ERR_OR_NULL(http_request)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return http_request->subject.monitor;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_http_request_get_monitor (struct medusa_http_request *http_request)
{
        struct medusa_monitor *rc;
        if (MEDUSA_IS_ERR_OR_NULL(http_request)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(http_request->subject.monitor);
        rc = medusa_http_request_get_monitor_unlocked(http_request);
        medusa_monitor_unlock(http_request->subject.monitor);
        return rc;
}

__attribute__ ((constructor)) static void http_request_constructor (void)
{
#if defined(MEDUSA_HTTP_REQUEST_USE_POOL) && (MEDUSA_HTTP_REQUEST_USE_POOL == 1)
        g_pool = medusa_pool_create("medusa-http_request", sizeof(struct medusa_http_request), 0, 0, MEDUSA_POOL_FLAG_DEFAULT | MEDUSA_POOL_FLAG_THREAD_SAFE, NULL, NULL, NULL);
#endif
}

__attribute__ ((destructor)) static void http_request_destructor (void)
{
#if defined(MEDUSA_HTTP_REQUEST_USE_POOL) && (MEDUSA_HTTP_REQUEST_USE_POOL == 1)
        if (g_pool != NULL) {
                medusa_pool_destroy(g_pool);
        }
#endif
}
