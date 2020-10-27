
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/uio.h>
#include <sys/ioctl.h>

#include "../3rdparty/http-parser/http_parser.h"

#include "error.h"
#include "pool.h"
#include "base64.h"
#include "sha1.h"
#include "queue.h"
#include "subject-struct.h"
#include "buffer.h"
#include "tcpsocket.h"
#include "tcpsocket-private.h"
#include "httpserver.h"
#include "httpserver-private.h"
#include "httpserver-struct.h"
#include "monitor-private.h"

#if defined(__GNUC__) && __GNUC__ >= 7
        #define FALL_THROUGH __attribute__ ((fallthrough))
#else
        #define FALL_THROUGH ((void)0)
#endif /* __GNUC__ >= 7 */

#define MEDUSA_HTTPSERVER_USE_POOL         1

#if defined(MEDUSA_HTTPSERVER_USE_POOL) && (MEDUSA_HTTPSERVER_USE_POOL == 1)
static struct medusa_pool *g_pool_httpserver;
static struct medusa_pool *g_pool_httpserver_client;
#endif

#define WS_FRAGMENT_FIN                 0x80

#define WS_NONBLOCK                     0x02

#define WS_OPCODE_CONTINUE              0x00
#define WS_OPCODE_TEXT                  0x01
#define WS_OPCODE_BINARY                0x02
#define WS_OPCODE_CLOSE                 0x08
#define WS_OPCODE_PING                  0x09
#define WS_OPCODE_PONG                  0x0a

#define WS_CLOSE_NORMAL                 1000
#define WS_CLOSE_GOING_AWAY             1001
#define WS_CLOSE_PROTOCOL_ERROR         1002
#define WS_CLOSE_NOT_ALLOWED            1003
#define WS_CLOSE_RESERVED               1004
#define WS_CLOSE_NO_CODE                1005
#define WS_CLOSE_DIRTY                  1006
#define WS_CLOSE_WRONG_TYPE             1007
#define WS_CLOSE_POLICY_VIOLATION       1008
#define WS_CLOSE_MESSAGE_TOO_BIG        1009
#define WS_CLOSE_UNEXPECTED_ERROR       1011

enum {
        MEDUSA_HTTPSERVER_FLAG_NONE                = (1 << 0),
        MEDUSA_HTTPSERVER_FLAG_ENABLED             = (1 << 1)
#define MEDUSA_HTTPSERVER_FLAG_NONE                MEDUSA_HTTPSERVER_FLAG_NONE
#define MEDUSA_HTTPSERVER_FLAG_ENABLED             MEDUSA_HTTPSERVER_FLAG_ENABLED
};

static inline void httpserver_set_flag (struct medusa_httpserver *httpserver, unsigned int flag)
{
        httpserver->flags = flag;
}

static inline void httpserver_add_flag (struct medusa_httpserver *httpserver, unsigned int flag)
{
        httpserver->flags |= flag;
}

static inline void httpserver_del_flag (struct medusa_httpserver *httpserver, unsigned int flag)
{
        httpserver->flags &= ~flag;
}

static inline int httpserver_has_flag (const struct medusa_httpserver *httpserver, unsigned int flag)
{
        return !!(httpserver->flags & flag);
}

static inline int httpserver_set_state (struct medusa_httpserver *httpserver, unsigned int state)
{
        if (state == MEDUSA_HTTPSERVER_STATE_STOPPED) {
                if (!MEDUSA_IS_ERR_OR_NULL(httpserver->tcpsocket)) {
                        medusa_tcpsocket_destroy_unlocked(httpserver->tcpsocket);
                        httpserver->tcpsocket = NULL;
                }
        }
        httpserver->state = state;
        return 0;
}

static unsigned int httpserver_protocol_to_tcpsocket_protocol (unsigned int protocol)
{
        switch (protocol) {
                case MEDUSA_HTTPSERVER_PROTOCOL_IPV4:      return MEDUSA_TCPSOCKET_PROTOCOL_IPV4;
                case MEDUSA_HTTPSERVER_PROTOCOL_IPV6:      return MEDUSA_TCPSOCKET_PROTOCOL_IPV6;
        }
        return MEDUSA_TCPSOCKET_PROTOCOL_ANY;
}

static int httpserver_tcpsocket_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, void *param)
{
        int rc;
        int error;
        struct medusa_monitor *monitor;
        struct medusa_httpserver *httpserver = (struct medusa_httpserver *) context;

        (void) param;

        if (events & MEDUSA_TCPSOCKET_EVENT_DESTROY) {
                return 0;
        }

        monitor = medusa_tcpsocket_get_monitor(tcpsocket);
        medusa_monitor_lock(monitor);

        if (events & MEDUSA_TCPSOCKET_EVENT_BINDING) {
                rc = httpserver_set_state(httpserver, MEDUSA_HTTPSERVER_STATE_BINDING);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
                rc = medusa_httpserver_onevent_unlocked(httpserver, MEDUSA_HTTPSERVER_EVENT_BINDING, NULL);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_BOUND) {
                rc = httpserver_set_state(httpserver, MEDUSA_HTTPSERVER_STATE_BOUND);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
                rc = medusa_httpserver_onevent_unlocked(httpserver, MEDUSA_HTTPSERVER_EVENT_BOUND, NULL);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_LISTENING) {
                rc = httpserver_set_state(httpserver, MEDUSA_HTTPSERVER_STATE_LISTENING);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
                rc = medusa_httpserver_onevent_unlocked(httpserver, MEDUSA_HTTPSERVER_EVENT_LISTENING, NULL);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_CONNECTION) {
                rc = medusa_httpserver_onevent_unlocked(httpserver, MEDUSA_HTTPSERVER_EVENT_CONNECTION, NULL);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
        }

        medusa_monitor_unlock(monitor);
        return 0;
bail:   medusa_monitor_unlock(monitor);
        return error;
}

static int httpserver_init_with_options_unlocked (struct medusa_httpserver *httpserver, const struct medusa_httpserver_init_options *options)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
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
        memset(httpserver, 0, sizeof(struct medusa_httpserver));
        TAILQ_INIT(&httpserver->clients);
        medusa_subject_set_type(&httpserver->subject, MEDUSA_SUBJECT_TYPE_HTTPSERVER);
        httpserver->subject.monitor = NULL;
        httpserver_set_state(httpserver, MEDUSA_HTTPSERVER_STATE_STOPPED);
        httpserver_set_flag(httpserver, MEDUSA_HTTPSERVER_FLAG_NONE);
        httpserver->onevent = options->onevent;
        httpserver->context = options->context;
        rc = medusa_monitor_add_unlocked(options->monitor, &httpserver->subject);
        if (rc < 0) {
                return rc;
        }
        return 0;
}

static void httpserver_uninit_unlocked (struct medusa_httpserver *httpserver)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return;
        }
        if (httpserver->subject.monitor != NULL) {
                medusa_monitor_del_unlocked(&httpserver->subject);
        } else {
                medusa_httpserver_onevent_unlocked(httpserver, MEDUSA_HTTPSERVER_EVENT_DESTROY, NULL);
        }
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_init_options_default (struct medusa_httpserver_init_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_httpserver_init_options));
        options->protocol   = MEDUSA_HTTPSERVER_PROTOCOL_ANY;
        options->address    = NULL;
        options->port       = 0;
        return 0;
}

__attribute__ ((visibility ("default"))) struct medusa_httpserver * medusa_httpserver_create_unlocked (struct medusa_monitor *monitor, unsigned int protocol, const char *address, unsigned short port, int (*onevent) (struct medusa_httpserver *httpserver, unsigned int events, void *context, void *param), void *context)
{
        int rc;
        struct medusa_httpserver_init_options options;
        rc = medusa_httpserver_init_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.monitor  = monitor;
        options.protocol = protocol;
        options.address  = address;
        options.port     = port;
        options.onevent  = onevent;
        options.context  = context;
        return medusa_httpserver_create_with_options_unlocked(&options);
}

__attribute__ ((visibility ("default"))) struct medusa_httpserver * medusa_httpserver_create (struct medusa_monitor *monitor, unsigned int protocol, const char *address, unsigned short port, int (*onevent) (struct medusa_httpserver *httpserver, unsigned int events, void *context, void *param), void *context)
{
        struct medusa_httpserver *rc;
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(monitor);
        rc = medusa_httpserver_create_unlocked(monitor, protocol, address, port, onevent, context);
        medusa_monitor_unlock(monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_httpserver * medusa_httpserver_create_with_options_unlocked (const struct medusa_httpserver_init_options *options)
{
        int rc;
        int error;
        struct medusa_httpserver *httpserver;

        httpserver = NULL;

        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                error = -EINVAL;
                goto bail;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                error = -EINVAL;
                goto bail;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                error = -EINVAL;
                goto bail;
        }

#if defined(MEDUSA_HTTPSERVER_USE_POOL) && (MEDUSA_HTTPSERVER_USE_POOL == 1)
        httpserver = medusa_pool_malloc(g_pool_httpserver);
#else
        httpserver = malloc(sizeof(struct medusa_httpserver));
#endif
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                error = -ENOMEM;
                goto bail;
        }
        memset(httpserver, 0, sizeof(struct medusa_httpserver));
        rc = httpserver_init_with_options_unlocked(httpserver, options);
        if (rc < 0) {
                error = rc;
                goto bail;
        }

        if (options->address != NULL) {
                httpserver->address = strdup(options->address);
                if (httpserver->address == NULL) {
                        error = -ENOMEM;
                        goto bail;
                }
        }
        httpserver->port     = options->port;
        httpserver->protocol = options->protocol;
        if (options->enabled != 0) {
                rc = medusa_httpserver_set_enabled_unlocked(httpserver, options->enabled);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
        }
        if (options->started != 0) {
                rc = medusa_httpserver_set_started_unlocked(httpserver, options->started);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
        }

        return httpserver;
bail:   if (!MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                medusa_httpserver_destroy_unlocked(httpserver);
        }
        return MEDUSA_ERR_PTR(error);
}

__attribute__ ((visibility ("default"))) struct medusa_httpserver * medusa_httpserver_create_with_options (const struct medusa_httpserver_init_options *options)
{
        struct medusa_httpserver *rc;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(options->monitor);
        rc = medusa_httpserver_create_with_options_unlocked(options);
        medusa_monitor_unlock(options->monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void medusa_httpserver_destroy_unlocked (struct medusa_httpserver *httpserver)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return;
        }
        httpserver_uninit_unlocked(httpserver);
}

__attribute__ ((visibility ("default"))) void medusa_httpserver_destroy (struct medusa_httpserver *httpserver)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return;
        }
        medusa_monitor_lock(httpserver->subject.monitor);
        medusa_httpserver_destroy_unlocked(httpserver);
        medusa_monitor_unlock(httpserver->subject.monitor);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_httpserver_get_state_unlocked (const struct medusa_httpserver *httpserver)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return MEDUSA_HTTPSERVER_STATE_UNKNOWN;
        }
        return httpserver->state;
}

__attribute__ ((visibility ("default"))) unsigned int medusa_httpserver_get_state (const struct medusa_httpserver *httpserver)
{
        unsigned int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return MEDUSA_HTTPSERVER_STATE_UNKNOWN;
        }
        medusa_monitor_lock(httpserver->subject.monitor);
        rc = medusa_httpserver_get_state_unlocked(httpserver);
        medusa_monitor_unlock(httpserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_set_enabled_unlocked (struct medusa_httpserver *httpserver, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return -EINVAL;
        }
        if (httpserver_has_flag(httpserver, MEDUSA_HTTPSERVER_FLAG_ENABLED) == !!enabled) {
                return 0;
        }
        if (enabled) {
                httpserver_add_flag(httpserver, MEDUSA_HTTPSERVER_FLAG_ENABLED);
        } else {
                httpserver_del_flag(httpserver, MEDUSA_HTTPSERVER_FLAG_ENABLED);
        }
        if (!MEDUSA_IS_ERR_OR_NULL(httpserver->tcpsocket)) {
                rc = medusa_tcpsocket_set_enabled_unlocked(httpserver->tcpsocket, enabled);
                if (rc < 0) {
                        return rc;
                }
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_set_enabled (struct medusa_httpserver *httpserver, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return -EINVAL;
        }
        medusa_monitor_lock(httpserver->subject.monitor);
        rc = medusa_httpserver_set_enabled_unlocked(httpserver, enabled);
        medusa_monitor_unlock(httpserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_get_enabled_unlocked (const struct medusa_httpserver *httpserver)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return -EINVAL;
        }
        return httpserver_has_flag(httpserver, MEDUSA_HTTPSERVER_FLAG_ENABLED);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_get_enabled (const struct medusa_httpserver *httpserver)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return -EINVAL;
        }
        medusa_monitor_lock(httpserver->subject.monitor);
        rc = medusa_httpserver_get_enabled_unlocked(httpserver);
        medusa_monitor_unlock(httpserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_pause_unlocked (struct medusa_httpserver *httpserver)
{
        return medusa_httpserver_set_enabled_unlocked(httpserver, 0);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_pause (struct medusa_httpserver *httpserver)
{
        return medusa_httpserver_set_enabled(httpserver, 0);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_resume_unlocked (struct medusa_httpserver *httpserver)
{
        return medusa_httpserver_set_enabled_unlocked(httpserver, 1);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_resume (struct medusa_httpserver *httpserver)
{
        return medusa_httpserver_set_enabled(httpserver, 1);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_set_started_unlocked (struct medusa_httpserver *httpserver, int started)
{
        int rc;
        int error;
        struct medusa_tcpsocket_bind_options medusa_tcpsocket_bind_options;

        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return -EINVAL;
        }

        if (started) {
                if (httpserver->state != MEDUSA_HTTPSERVER_STATE_STOPPED) {
                        error = -EALREADY;
                        goto bail;
                }
                if (!MEDUSA_IS_ERR_OR_NULL(httpserver->tcpsocket)) {
                        error = EIO;
                        goto bail;
                }
                rc = medusa_tcpsocket_bind_options_default(&medusa_tcpsocket_bind_options);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
                medusa_tcpsocket_bind_options.protocol    = httpserver_protocol_to_tcpsocket_protocol(httpserver->protocol);
                medusa_tcpsocket_bind_options.address     = httpserver->address;
                medusa_tcpsocket_bind_options.port        = httpserver->port;
                medusa_tcpsocket_bind_options.buffered    = 1;
                medusa_tcpsocket_bind_options.nodelay     = 1;
                medusa_tcpsocket_bind_options.nonblocking = 1;
                medusa_tcpsocket_bind_options.reuseaddr   = 1;
                medusa_tcpsocket_bind_options.reuseport   = 0;
                medusa_tcpsocket_bind_options.enabled     = 1;
                medusa_tcpsocket_bind_options.monitor     = httpserver->subject.monitor;
                medusa_tcpsocket_bind_options.context     = httpserver;
                medusa_tcpsocket_bind_options.onevent     = httpserver_tcpsocket_onevent;
                httpserver->tcpsocket = medusa_tcpsocket_bind_with_options_unlocked(&medusa_tcpsocket_bind_options);
                if (MEDUSA_IS_ERR_OR_NULL(httpserver->tcpsocket)) {
                        error =  MEDUSA_PTR_ERR(httpserver->tcpsocket);
                        goto bail;
                }
                httpserver_set_state(httpserver, MEDUSA_HTTPSERVER_STATE_STARTED);
                medusa_httpserver_onevent_unlocked(httpserver, MEDUSA_HTTPSERVER_EVENT_STARTED, NULL);
        } else {
                if (httpserver->state == MEDUSA_HTTPSERVER_STATE_STOPPED) {
                        return -EALREADY;
                }
                if (MEDUSA_IS_ERR_OR_NULL(httpserver->tcpsocket)) {
                        return -EIO;
                }
                medusa_tcpsocket_destroy_unlocked(httpserver->tcpsocket);
                httpserver->tcpsocket = NULL;
                httpserver_set_state(httpserver, MEDUSA_HTTPSERVER_STATE_STOPPED);
                medusa_httpserver_onevent_unlocked(httpserver, MEDUSA_HTTPSERVER_EVENT_STOPPED, NULL);
        }
        return 0;
bail:   return error;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_set_started (struct medusa_httpserver *httpserver, int started)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return -EINVAL;
        }
        medusa_monitor_lock(httpserver->subject.monitor);
        rc = medusa_httpserver_set_started_unlocked(httpserver, started);
        medusa_monitor_unlock(httpserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_get_started_unlocked (const struct medusa_httpserver *httpserver)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return -EINVAL;
        }
        return httpserver_has_flag(httpserver, MEDUSA_HTTPSERVER_FLAG_ENABLED);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_get_started (const struct medusa_httpserver *httpserver)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return -EINVAL;
        }
        medusa_monitor_lock(httpserver->subject.monitor);
        rc = medusa_httpserver_get_started_unlocked(httpserver);
        medusa_monitor_unlock(httpserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_start_unlocked (struct medusa_httpserver *httpserver)
{
        return medusa_httpserver_set_started_unlocked(httpserver, 1);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_start (struct medusa_httpserver *httpserver)
{
        return medusa_httpserver_set_started(httpserver, 1);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_stop_unlocked (struct medusa_httpserver *httpserver)
{
        return medusa_httpserver_set_started_unlocked(httpserver, 0);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_stop (struct medusa_httpserver *httpserver)
{
        return medusa_httpserver_set_started(httpserver, 0);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_set_context_unlocked (struct medusa_httpserver *httpserver, void *context)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return -EINVAL;
        }
        httpserver->context = context;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_set_context (struct medusa_httpserver *httpserver, void *context)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return -EINVAL;
        }
        medusa_monitor_lock(httpserver->subject.monitor);
        rc = medusa_httpserver_set_context_unlocked(httpserver, context);
        medusa_monitor_unlock(httpserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void * medusa_httpserver_get_context_unlocked (struct medusa_httpserver *httpserver)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return httpserver->context;
}

__attribute__ ((visibility ("default"))) void * medusa_httpserver_get_context (struct medusa_httpserver *httpserver)
{
        void *rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(httpserver->subject.monitor);
        rc = medusa_httpserver_get_context_unlocked(httpserver);
        medusa_monitor_unlock(httpserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_set_userdata_unlocked (struct medusa_httpserver *httpserver, void *userdata)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return -EINVAL;
        }
        httpserver->userdata = userdata;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_set_userdata (struct medusa_httpserver *httpserver, void *userdata)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return -EINVAL;
        }
        medusa_monitor_lock(httpserver->subject.monitor);
        rc = medusa_httpserver_set_userdata_unlocked(httpserver, userdata);
        medusa_monitor_unlock(httpserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void * medusa_httpserver_get_userdata_unlocked (struct medusa_httpserver *httpserver)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return httpserver->userdata;
}

__attribute__ ((visibility ("default"))) void * medusa_httpserver_get_userdata (struct medusa_httpserver *httpserver)
{
        void *rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(httpserver->subject.monitor);
        rc = medusa_httpserver_get_userdata_unlocked(httpserver);
        medusa_monitor_unlock(httpserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_set_userdata_ptr_unlocked (struct medusa_httpserver *httpserver, void *userdata)
{
        return medusa_httpserver_set_userdata_unlocked(httpserver, userdata);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_set_userdata_ptr (struct medusa_httpserver *httpserver, void *userdata)
{
        return medusa_httpserver_set_userdata(httpserver, userdata);
}

__attribute__ ((visibility ("default"))) void * medusa_httpserver_get_userdata_ptr_unlocked (struct medusa_httpserver *httpserver)
{
        return medusa_httpserver_get_userdata_unlocked(httpserver);
}

__attribute__ ((visibility ("default"))) void * medusa_httpserver_get_userdata_ptr (struct medusa_httpserver *httpserver)
{
        return medusa_httpserver_get_userdata(httpserver);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_set_userdata_int_unlocked (struct medusa_httpserver *httpserver, int userdata)
{
        return medusa_httpserver_set_userdata_unlocked(httpserver, (void *) (intptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_set_userdata_int (struct medusa_httpserver *httpserver, int userdata)
{
        return medusa_httpserver_set_userdata(httpserver, (void *) (intptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_get_userdata_int_unlocked (struct medusa_httpserver *httpserver)
{
        return (int) (intptr_t) medusa_httpserver_get_userdata_unlocked(httpserver);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_get_userdata_int (struct medusa_httpserver *httpserver)
{
        return (int) (intptr_t) medusa_httpserver_get_userdata(httpserver);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_set_userdata_uint_unlocked (struct medusa_httpserver *httpserver, unsigned int userdata)
{
        return medusa_httpserver_set_userdata_unlocked(httpserver, (void *) (uintptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_set_userdata_uint (struct medusa_httpserver *httpserver, unsigned int userdata)
{
        return medusa_httpserver_set_userdata(httpserver, (void *) (uintptr_t) userdata);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_httpserver_get_userdata_uint_unlocked (struct medusa_httpserver *httpserver)
{
        return (unsigned int) (intptr_t) medusa_httpserver_get_userdata_unlocked(httpserver);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_httpserver_get_userdata_uint (struct medusa_httpserver *httpserver)
{
        return (unsigned int) (uintptr_t) medusa_httpserver_get_userdata(httpserver);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_onevent_unlocked (struct medusa_httpserver *httpserver, unsigned int events, void *param)
{
        int ret;
        struct medusa_monitor *monitor;
        ret = 0;
        monitor = httpserver->subject.monitor;
        if (httpserver->onevent != NULL) {
                if ((medusa_subject_is_active(&httpserver->subject)) ||
                    (events & MEDUSA_HTTPSERVER_EVENT_DESTROY)) {
                        medusa_monitor_unlock(monitor);
                        ret = httpserver->onevent(httpserver, events, httpserver->context, param);
                        medusa_monitor_lock(monitor);
                }
        }
        if (events & MEDUSA_HTTPSERVER_EVENT_DESTROY) {
                struct medusa_httpserver_client *httpserver_client;
                struct medusa_httpserver_client *nhttpserver_client;
                TAILQ_FOREACH_SAFE(httpserver_client, &httpserver->clients, list, nhttpserver_client) {
                        TAILQ_REMOVE(&httpserver->clients, httpserver_client, list);
                        httpserver_client->httpserver = NULL;
                        medusa_httpserver_client_destroy_unlocked(httpserver_client);
                }
                if (httpserver->address != NULL) {
                        free(httpserver->address);
                }
                if (!MEDUSA_IS_ERR_OR_NULL(httpserver->tcpsocket)) {
                        medusa_tcpsocket_destroy_unlocked(httpserver->tcpsocket);
                        httpserver->tcpsocket = NULL;
                }
#if defined(MEDUSA_HTTPSERVER_USE_POOL) && (MEDUSA_HTTPSERVER_USE_POOL == 1)
                medusa_pool_free(httpserver);
#else
                free(httpserver);
#endif
        }
        return ret;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_onevent (struct medusa_httpserver *httpserver, unsigned int events, void *param)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return -EINVAL;
        }
        medusa_monitor_lock(httpserver->subject.monitor);
        rc = medusa_httpserver_onevent_unlocked(httpserver, events, param);
        medusa_monitor_unlock(httpserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_httpserver_get_monitor_unlocked (struct medusa_httpserver *httpserver)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return httpserver->subject.monitor;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_httpserver_get_monitor (struct medusa_httpserver *httpserver)
{
        struct medusa_monitor *rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(httpserver->subject.monitor);
        rc = medusa_httpserver_get_monitor_unlocked(httpserver);
        medusa_monitor_unlock(httpserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) const char * medusa_httpserver_event_string (unsigned int events)
{
        if (events == MEDUSA_HTTPSERVER_EVENT_STARTED)             return "MEDUSA_HTTPSERVER_EVENT_STARTED";
        if (events == MEDUSA_HTTPSERVER_EVENT_STOPPED)             return "MEDUSA_HTTPSERVER_EVENT_STOPPED";
        if (events == MEDUSA_HTTPSERVER_EVENT_BINDING)             return "MEDUSA_HTTPSERVER_EVENT_BINDING";
        if (events == MEDUSA_HTTPSERVER_EVENT_BOUND)               return "MEDUSA_HTTPSERVER_EVENT_BOUND";
        if (events == MEDUSA_HTTPSERVER_EVENT_LISTENING)           return "MEDUSA_HTTPSERVER_EVENT_LISTENING";
        if (events == MEDUSA_HTTPSERVER_EVENT_CONNECTION)          return "MEDUSA_HTTPSERVER_EVENT_CONNECTION";
        if (events == MEDUSA_HTTPSERVER_EVENT_ERROR)               return "MEDUSA_HTTPSERVER_EVENT_ERROR";
        if (events == MEDUSA_HTTPSERVER_EVENT_DESTROY)             return "MEDUSA_HTTPSERVER_EVENT_DESTROY";
        return "MEDUSA_HTTPSERVER_EVENT_UNKNOWN";
}

__attribute__ ((visibility ("default"))) const char * medusa_httpserver_state_string (unsigned int state)
{
        if (state == MEDUSA_HTTPSERVER_STATE_UNKNOWN)              return "MEDUSA_HTTPSERVER_STATE_UNKNOWN";
        if (state == MEDUSA_HTTPSERVER_STATE_STARTED)              return "MEDUSA_HTTPSERVER_STATE_STARTED";
        if (state == MEDUSA_HTTPSERVER_STATE_STOPPED)              return "MEDUSA_HTTPSERVER_STATE_STOPPED";
        if (state == MEDUSA_HTTPSERVER_STATE_BINDING)              return "MEDUSA_HTTPSERVER_STATE_BINDING";
        if (state == MEDUSA_HTTPSERVER_STATE_BOUND)                return "MEDUSA_HTTPSERVER_STATE_BOUND";
        if (state == MEDUSA_HTTPSERVER_STATE_LISTENING)            return "MEDUSA_HTTPSERVER_STATE_LISTENING";
        if (state == MEDUSA_HTTPSERVER_STATE_ERROR)                return "MEDUSA_HTTPSERVER_STATE_ERROR";
        return "MEDUSA_HTTPSERVER_STATE_UNKNOWN";
}

enum {
        MEDUSA_HTTPSERVER_CLIENT_FLAG_NONE         = (1 <<  0),
        MEDUSA_HTTPSERVER_CLIENT_FLAG_ENABLED      = (1 <<  1)
#define MEDUSA_HTTPSERVER_CLIENT_FLAG_NONE         MEDUSA_HTTPSERVER_CLIENT_FLAG_NONE
#define MEDUSA_HTTPSERVER_CLIENT_FLAG_ENABLED      MEDUSA_HTTPSERVER_CLIENT_FLAG_ENABLED
};

enum {
        MEDUSA_HTTPSERVER_CLIENT_FRAME_STATE_START         = 0,
        MEDUSA_HTTPSERVER_CLIENT_FRAME_STATE_HEADER        = 1,
        MEDUSA_HTTPSERVER_CLIENT_FRAME_STATE_PAYLOAD       = 2,
        MEDUSA_HTTPSERVER_CLIENT_FRAME_STATE_FINISH        = 3
#define MEDUSA_HTTPSERVER_CLIENT_FRAME_STATE_START         MEDUSA_HTTPSERVER_CLIENT_FRAME_STATE_START
#define MEDUSA_HTTPSERVER_CLIENT_FRAME_STATE_HEADER        MEDUSA_HTTPSERVER_CLIENT_FRAME_STATE_HEADER
#define MEDUSA_HTTPSERVER_CLIENT_FRAME_STATE_PAYLOAD       MEDUSA_HTTPSERVER_CLIENT_FRAME_STATE_PAYLOAD
#define MEDUSA_HTTPSERVER_CLIENT_FRAME_STATE_FINISH        MEDUSA_HTTPSERVER_CLIENT_FRAME_STATE_FINISH
};

static inline void httpserver_client_set_flag (struct medusa_httpserver_client *httpserver_client, unsigned int flag)
{
        httpserver_client->flags = flag;
}

static inline void httpserver_client_add_flag (struct medusa_httpserver_client *httpserver_client, unsigned int flag)
{
        httpserver_client->flags |= flag;
}

static inline void httpserver_client_del_flag (struct medusa_httpserver_client *httpserver_client, unsigned int flag)
{
        httpserver_client->flags &= ~flag;
}

static inline int httpserver_client_has_flag (const struct medusa_httpserver_client *httpserver_client, unsigned int flag)
{
        return !!(httpserver_client->flags & flag);
}

static inline int httpserver_client_set_state (struct medusa_httpserver_client *httpserver_client, unsigned int state)
{
        httpserver_client->error = 0;
        if (state == MEDUSA_HTTPSERVER_CLIENT_STATE_DISCONNECTED) {
                if (!MEDUSA_IS_ERR_OR_NULL(httpserver_client->tcpsocket)) {
                        medusa_tcpsocket_destroy_unlocked(httpserver_client->tcpsocket);
                        httpserver_client->tcpsocket = NULL;
                }
        }
        httpserver_client->state = state;
        return 0;
}

TAILQ_HEAD(medusa_httpserver_client_request_headers_list, medusa_httpserver_client_request_header);
struct medusa_httpserver_client_request_header {
        TAILQ_ENTRY(medusa_httpserver_client_request_header) list;
        char *key;
        char *value;
};

struct medusa_httpserver_client_request_headers {
        int64_t count;
        struct medusa_httpserver_client_request_headers_list list;
};

struct medusa_httpserver_client_request_body {
        int64_t length;
        void *value;
};

struct medusa_httpserver_client_request {
        char *method;
        char *url;
        struct medusa_httpserver_client_request_headers headers;
        struct medusa_httpserver_client_request_body body;
};

static int medusa_httpserver_client_request_header_set_key (struct medusa_httpserver_client_request_header *header, const char *key, int64_t length)
{
        if (header == NULL) {
                return -EINVAL;
        }
        if (key == NULL) {
                return -EINVAL;
        }
        if (length <= 0) {
                return -EINVAL;
        }
        header->key = strndup(key, length);
        if (header->key == NULL) {
                return -ENOMEM;
        }
        return 0;
}

static int medusa_httpserver_client_request_header_set_value (struct medusa_httpserver_client_request_header *header, const char *value, int64_t length)
{
        if (header == NULL) {
                return -EINVAL;
        }
        if (value == NULL) {
                return -EINVAL;
        }
        if (length <= 0) {
                return -EINVAL;
        }
        header->value = strndup(value, length);
        if (header->value == NULL) {
                return -ENOMEM;
        }
        return 0;
}

static void medusa_httpserver_client_request_header_destroy (struct medusa_httpserver_client_request_header *header)
{
        if (header == NULL) {
                return;
        }
        if (header->key != NULL) {
                free(header->key);
        }
        if (header->value != NULL) {
                free(header->value);
        }
        free(header);
}

static struct medusa_httpserver_client_request_header * medusa_httpserver_client_request_header_create (void)
{
        struct medusa_httpserver_client_request_header *header;
        header = malloc(sizeof(struct medusa_httpserver_client_request_header));
        if (header == NULL) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(header, 0, sizeof(struct medusa_httpserver_client_request_header));
        return header;
}

static void medusa_httpserver_client_request_body_uninit (struct medusa_httpserver_client_request_body *body)
{
        body->length = 0;
        if (body->value != NULL) {
                free(body->value);
        }
}

static void medusa_httpserver_client_request_body_init (struct medusa_httpserver_client_request_body *body)
{
        memset(body, 0, sizeof(struct medusa_httpserver_client_request_body));
        body->length = 0;
}

static void medusa_httpserver_client_request_headers_uninit (struct medusa_httpserver_client_request_headers *headers)
{
        struct medusa_httpserver_client_request_header *header;
        struct medusa_httpserver_client_request_header *nheader;
        TAILQ_FOREACH_SAFE(header, &headers->list, list, nheader) {
                TAILQ_REMOVE(&headers->list, header, list);
                medusa_httpserver_client_request_header_destroy(header);
        }
        headers->count = 0;
}

static void medusa_httpserver_client_request_headers_init (struct medusa_httpserver_client_request_headers *headers)
{
        memset(headers, 0, sizeof(struct medusa_httpserver_client_request_headers));
        headers->count = 0;
        TAILQ_INIT(&headers->list);
}

static int medusa_httpserver_client_request_set_method (struct medusa_httpserver_client_request *request, const char *method)
{
        if (request == NULL) {
                return -EINVAL;
        }
        if (request->method != NULL) {
                free(request->method);
                request->method = NULL;
        }
        if (method != NULL) {
                request->method = strdup(method);
                if (request->method == NULL) {
                        return -ENOMEM;
                }
        }
        return 0;
}

static int medusa_httpserver_client_request_set_url (struct medusa_httpserver_client_request *request, const char *url, int length)
{
        if (request == NULL) {
                return -EINVAL;
        }
        if (request->url != NULL) {
                free(request->url);
                request->url = NULL;
        }
        if (length > 0) {
                request->url = strndup(url, length);
                if (request->url == NULL) {
                        return -ENOMEM;
                }
        }
        return 0;
}

static void medusa_httpserver_client_request_destroy (struct medusa_httpserver_client_request *request)
{
        if (request == NULL) {
                return;
        }
        if (request->method != NULL) {
                free(request->method);
        }
        if (request->url != NULL) {
                free(request->url);
        }
        medusa_httpserver_client_request_body_uninit(&request->body);
        medusa_httpserver_client_request_headers_uninit(&request->headers);
        free(request);
}

static struct medusa_httpserver_client_request * medusa_httpserver_client_request_create (void)
{
        struct medusa_httpserver_client_request *request;
        request = malloc(sizeof(struct medusa_httpserver_client_request));
        if (request == NULL) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(request, 0, sizeof(struct medusa_httpserver_client_request));
        medusa_httpserver_client_request_headers_init(&request->headers);
        medusa_httpserver_client_request_body_init(&request->body);
        return request;
}

static int httpserver_client_httpparser_on_message_begin (http_parser *http_parser)
{
        struct medusa_httpserver_client *httpserver_client = http_parser->data;
        if (!MEDUSA_IS_ERR_OR_NULL(httpserver_client->request)) {
             medusa_httpserver_client_request_destroy(httpserver_client->request);
             httpserver_client->request = NULL;
        }
        httpserver_client->request = medusa_httpserver_client_request_create();
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client->request)) {
                return MEDUSA_PTR_ERR(httpserver_client->request);
        }
        return 0;
}

static int httpserver_client_httpparser_on_url (http_parser *http_parser, const char *at, size_t length)
{
        int rc;
        struct medusa_httpserver_client *httpserver_client = http_parser->data;
        rc = medusa_httpserver_client_request_set_method(httpserver_client->request, http_method_str(http_parser->method));
        if (rc < 0) {
                return rc;
        }
        rc = medusa_httpserver_client_request_set_url(httpserver_client->request, at, length);
        if (rc < 0) {
                return rc;
        }
        return 0;
}

static int httpserver_client_httpparser_on_status (http_parser *http_parser, const char *at, size_t length)
{
        struct medusa_httpserver_client *httpserver_client = http_parser->data;
        (void) httpserver_client;
        (void) at;
        (void) length;
        return 0;
}

static int httpserver_client_httpparser_on_header_field (http_parser *http_parser, const char *at, size_t length)
{
         int rc;
        struct medusa_httpserver_client_request_header *header;
        struct medusa_httpserver_client *httpserver_client = http_parser->data;
        header = medusa_httpserver_client_request_header_create();
        if (MEDUSA_IS_ERR_OR_NULL(header)) {
                return MEDUSA_PTR_ERR(header);
        }
        rc = medusa_httpserver_client_request_header_set_key(header, at, length);
        if (rc < 0) {
                medusa_httpserver_client_request_header_destroy(header);
                return rc;
        }
        TAILQ_INSERT_TAIL(&httpserver_client->request->headers.list, header, list);
        httpserver_client->request->headers.count += 1;
        return 0;
}

static int httpserver_client_httpparser_on_header_value (http_parser *http_parser, const char *at, size_t length)
{
        int rc;
        struct medusa_httpserver_client_request_header *header;
        struct medusa_httpserver_client *httpserver_client = http_parser->data;
        header = TAILQ_LAST(&httpserver_client->request->headers.list, medusa_httpserver_client_request_headers_list);
        if (MEDUSA_IS_ERR_OR_NULL(header)) {
                return MEDUSA_PTR_ERR(header);
        }
        rc = medusa_httpserver_client_request_header_set_value(header, at, length);
        if (rc < 0) {
                return rc;
        }
        return 0;
}

static int httpserver_client_httpparser_on_headers_complete (http_parser *http_parser)
{
        struct medusa_httpserver_client *httpserver_client = http_parser->data;
        (void) httpserver_client;
        return 0;
}

static int httpserver_client_httpparser_on_body (http_parser *http_parser, const char *at, size_t length)
{
        void *tmp;
        struct medusa_httpserver_client *httpserver_client = http_parser->data;
        tmp = realloc(httpserver_client->request->body.value, httpserver_client->request->body.length + length + 1);
        if (tmp == NULL) {
                tmp = malloc(httpserver_client->request->body.length + length + 1);
                if (tmp == NULL) {
                        return -ENOMEM;
                }
                memcpy(tmp, httpserver_client->request->body.value, httpserver_client->request->body.length);
                free(httpserver_client->request->body.value);
                httpserver_client->request->body.value = tmp;
        } else {
                httpserver_client->request->body.value = tmp;
        }
        memcpy(httpserver_client->request->body.value +  httpserver_client->request->body.length, at, length);
        httpserver_client->request->body.length += length;
        ((char *) httpserver_client->request->body.value)[httpserver_client->request->body.length] = '\0';
        return 0;
}

static int httpserver_client_httpparser_on_message_complete (http_parser *http_parser)
{
        int rc;
        struct medusa_httpserver_client_event_request_received httpserver_client_event_request_received;
        struct medusa_httpserver_client *httpserver_client = http_parser->data;
        rc = httpserver_client_set_state(httpserver_client, MEDUSA_HTTPSERVER_CLIENT_STATE_REQUEST_RECEIVED);
        if (rc < 0) {
                return rc;
        }
        httpserver_client_event_request_received.request = httpserver_client->request;
        rc = medusa_httpserver_client_onevent_unlocked(httpserver_client, MEDUSA_HTTPSERVER_CLIENT_EVENT_REQUEST_RECEIVED, &httpserver_client_event_request_received);
        if (rc < 0) {
                return rc;
        }
        return 0;
}

static int httpserver_client_httpparser_on_chunk_header (http_parser *http_parser)
{
        struct medusa_httpserver_client *httpserver_client = http_parser->data;
        (void) httpserver_client;
        return 0;
}

static int httpserver_client_httpparser_on_chunk_complete (http_parser *http_parser)
{
        struct medusa_httpserver_client *httpserver_client = http_parser->data;
        (void) httpserver_client;
        return 0;
}

static int httpserver_client_tcpsocket_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, void *param)
{
        int rc;
        int error;
        struct medusa_monitor *monitor;
        struct medusa_httpserver_client *httpserver_client = (struct medusa_httpserver_client *) context;

        if (events & MEDUSA_TCPSOCKET_EVENT_DESTROY) {
                return 0;
        }

        monitor = medusa_tcpsocket_get_monitor(tcpsocket);
        medusa_monitor_lock(monitor);

        if (events & MEDUSA_TCPSOCKET_EVENT_CONNECTED) {
                httpserver_client_set_state(httpserver_client, MEDUSA_HTTPSERVER_CLIENT_STATE_CONNECTED);
                rc = medusa_httpserver_client_onevent_unlocked(httpserver_client, MEDUSA_HTTPSERVER_CLIENT_EVENT_CONNECTED, NULL);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
                http_parser_settings_init(&httpserver_client->http_parser_settings);
                httpserver_client->http_parser_settings.on_message_begin      = httpserver_client_httpparser_on_message_begin;
                httpserver_client->http_parser_settings.on_url                = httpserver_client_httpparser_on_url;
                httpserver_client->http_parser_settings.on_status             = httpserver_client_httpparser_on_status;
                httpserver_client->http_parser_settings.on_header_field       = httpserver_client_httpparser_on_header_field;
                httpserver_client->http_parser_settings.on_header_value       = httpserver_client_httpparser_on_header_value;
                httpserver_client->http_parser_settings.on_headers_complete   = httpserver_client_httpparser_on_headers_complete;
                httpserver_client->http_parser_settings.on_body               = httpserver_client_httpparser_on_body;
                httpserver_client->http_parser_settings.on_message_complete   = httpserver_client_httpparser_on_message_complete;
                httpserver_client->http_parser_settings.on_chunk_header       = httpserver_client_httpparser_on_chunk_header;
                httpserver_client->http_parser_settings.on_chunk_complete     = httpserver_client_httpparser_on_chunk_complete;
                http_parser_init(&httpserver_client->http_parser, HTTP_REQUEST);
                httpserver_client->http_parser.data = httpserver_client;
        } else if (events & MEDUSA_TCPSOCKET_EVENT_BUFFERED_READ) {
                if (httpserver_client->state == MEDUSA_HTTPSERVER_CLIENT_STATE_CONNECTED) {
                        rc = httpserver_client_set_state(httpserver_client, MEDUSA_HTTPSERVER_CLIENT_STATE_REQUEST_RECEIVING);
                        if (rc < 0) {
                                error = rc;
                                goto bail;
                        }
                        rc = medusa_httpserver_client_onevent_unlocked(httpserver_client, MEDUSA_HTTPSERVER_CLIENT_EVENT_REQUEST_RECEIVING, NULL);
                        if (rc < 0) {
                                error = rc;
                                goto bail;
                        }
                }
                if (httpserver_client->state == MEDUSA_HTTPSERVER_CLIENT_STATE_REQUEST_RECEIVING) {
                        int64_t siovecs;
                        int64_t niovecs;
                        int64_t iiovecs;
                        struct iovec iovecs[1];

                        size_t nparsed;
                        size_t tparsed;
                        int64_t clength;

                        siovecs = sizeof(iovecs) / sizeof(iovecs[0]);
                        niovecs = medusa_buffer_peekv(medusa_tcpsocket_get_read_buffer_unlocked(tcpsocket), 0, -1, iovecs, siovecs);
                        if (niovecs < 0) {
                                error = niovecs;
                                goto bail;
                        }

                        tparsed = 0;
                        for (iiovecs = 0; iiovecs < niovecs; iiovecs++) {
                                nparsed = http_parser_execute(&httpserver_client->http_parser, &httpserver_client->http_parser_settings, iovecs[iiovecs].iov_base, iovecs[iiovecs].iov_len);
                                if (httpserver_client->http_parser.http_errno != 0) {
                                        error = -EIO;
                                        goto bail;
                                }
                                tparsed += nparsed;
                                if (nparsed != iovecs[iiovecs].iov_len) {
                                        break;
                                }
                        }
                        clength = medusa_buffer_choke(medusa_tcpsocket_get_read_buffer_unlocked(tcpsocket), 0, tparsed);
                        if (clength != (int64_t) tparsed) {
                                error = -EIO;
                                goto bail;
                        }
                }
                if (httpserver_client->state == MEDUSA_HTTPSERVER_CLIENT_STATE_REQUEST_RECEIVED) {
                }
        } else if (events & MEDUSA_TCPSOCKET_EVENT_BUFFERED_READ_TIMEOUT) {
                rc = medusa_httpserver_client_onevent_unlocked(httpserver_client, MEDUSA_HTTPSERVER_CLIENT_EVENT_REQUEST_RECEIVE_TIMEOUT, NULL);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
        } else if (events & MEDUSA_TCPSOCKET_EVENT_BUFFERED_WRITE) {
                struct medusa_tcpsocket_event_buffered_write *medusa_tcpsocket_event_buffered_write = (struct medusa_tcpsocket_event_buffered_write *) param;
                struct medusa_httpserver_client_event_buffered_write medusa_httpserver_client_event_buffered_write;
                medusa_httpserver_client_event_buffered_write.length    = medusa_tcpsocket_event_buffered_write->length;
                medusa_httpserver_client_event_buffered_write.remaining = medusa_tcpsocket_event_buffered_write->remaining;
                rc = medusa_httpserver_client_onevent_unlocked(httpserver_client, MEDUSA_HTTPSERVER_CLIENT_EVENT_BUFFERED_WRITE, &medusa_httpserver_client_event_buffered_write);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
        } else if (events & MEDUSA_TCPSOCKET_EVENT_BUFFERED_WRITE_FINISHED) {
                rc = medusa_httpserver_client_onevent_unlocked(httpserver_client, MEDUSA_HTTPSERVER_CLIENT_EVENT_BUFFERED_WRITE_FINISHED, NULL);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
        } else if (events & MEDUSA_TCPSOCKET_EVENT_DISCONNECTED) {
                rc = httpserver_client_set_state(httpserver_client, MEDUSA_HTTPSERVER_CLIENT_STATE_DISCONNECTED);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
                rc = medusa_httpserver_client_onevent_unlocked(httpserver_client, MEDUSA_HTTPSERVER_CLIENT_EVENT_DISCONNECTED, NULL);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
                medusa_httpserver_client_destroy_unlocked(httpserver_client);
        } else if (events & MEDUSA_TCPSOCKET_EVENT_ERROR) {
        } else {
                error = -EIO;
                goto bail;
        }

        medusa_monitor_unlock(monitor);
        return 0;
bail:   httpserver_client_set_state(httpserver_client, MEDUSA_HTTPSERVER_CLIENT_STATE_ERROR);
        httpserver_client->error = -error;
        medusa_httpserver_client_onevent_unlocked(httpserver_client, MEDUSA_HTTPSERVER_CLIENT_EVENT_ERROR, NULL);
        medusa_monitor_unlock(monitor);
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_accept_options_default (struct medusa_httpserver_accept_options *options)
{
        if (options == NULL) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_httpserver_accept_options));
        return 0;
}

__attribute__ ((visibility ("default"))) struct medusa_httpserver_client * medusa_httpserver_accept_unlocked (struct medusa_httpserver *httpserver, int (*onevent) (struct medusa_httpserver_client *httpserver_client, unsigned int events, void *context, void *param), void *context)
{
        int rc;
        struct medusa_httpserver_accept_options options;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        rc = medusa_httpserver_accept_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.enabled  = medusa_httpserver_get_enabled_unlocked(httpserver);
        options.onevent  = onevent;
        options.context  = context;
        return medusa_httpserver_accept_with_options_unlocked(httpserver, &options);
}

__attribute__ ((visibility ("default"))) struct medusa_httpserver_client * medusa_httpserver_accept (struct medusa_httpserver *httpserver, int (*onevent) (struct medusa_httpserver_client *httpserver_client, unsigned int events, void *context, void *param), void *context)
{
        struct medusa_httpserver_client *rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(httpserver->subject.monitor);
        rc = medusa_httpserver_accept_unlocked(httpserver, onevent, context);
        medusa_monitor_unlock(httpserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_httpserver_client * medusa_httpserver_accept_with_options_unlocked (struct medusa_httpserver *httpserver, struct medusa_httpserver_accept_options *options)
{
        int rc;
        int error;

        struct medusa_tcpsocket *accepted;
        struct medusa_tcpsocket_accept_options medusa_tcpsocket_accept_options;

        struct medusa_httpserver_client *httpserver_client;

        httpserver_client = NULL;

        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }

#if defined(MEDUSA_HTTPSERVER_USE_POOL) && (MEDUSA_HTTPSERVER_USE_POOL == 1)
        httpserver_client = medusa_pool_malloc(g_pool_httpserver_client);
#else
        httpserver_client = malloc(sizeof(struct medusa_httpserver_client));
#endif
        if (httpserver_client == NULL) {
                error = -ENOMEM;
                goto bail;
        }
        memset(httpserver_client, 0, sizeof(struct medusa_httpserver_client));
        medusa_subject_set_type(&httpserver_client->subject, MEDUSA_SUBJECT_TYPE_HTTPSERVER_CLIENT);
        httpserver_client->subject.monitor = NULL;
        httpserver_client_set_state(httpserver_client, MEDUSA_HTTPSERVER_CLIENT_STATE_DISCONNECTED);
        httpserver_client_set_flag(httpserver_client, MEDUSA_HTTPSERVER_CLIENT_FLAG_NONE);
        httpserver_client->onevent = options->onevent;
        httpserver_client->context = options->context;
        rc = medusa_monitor_add_unlocked(httpserver->subject.monitor, &httpserver_client->subject);
        if (rc < 0) {
                error = rc;
                goto bail;
        }

        rc = medusa_httpserver_client_set_enabled_unlocked(httpserver_client, options->enabled);
        if (rc < 0) {
                error = rc;
                goto bail;
        }

        rc = medusa_tcpsocket_accept_options_default(&medusa_tcpsocket_accept_options);
        if (rc < 0) {
                error = rc;
                goto bail;
        }
        medusa_tcpsocket_accept_options.buffered    = 1;
        medusa_tcpsocket_accept_options.nodelay     = 1;
        medusa_tcpsocket_accept_options.nonblocking = 1;
        medusa_tcpsocket_accept_options.enabled     = options->enabled;
        medusa_tcpsocket_accept_options.onevent     = httpserver_client_tcpsocket_onevent;
        medusa_tcpsocket_accept_options.context     = httpserver_client;
        accepted = medusa_tcpsocket_accept_with_options_unlocked(httpserver->tcpsocket, &medusa_tcpsocket_accept_options);
        if (MEDUSA_IS_ERR_OR_NULL(accepted)) {
                error = MEDUSA_PTR_ERR(accepted);
                goto bail;
        }

        httpserver_client->tcpsocket  = accepted;
        httpserver_client->httpserver = httpserver;
        TAILQ_INSERT_TAIL(&httpserver->clients, httpserver_client, list);

        return httpserver_client;
bail:   if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return MEDUSA_ERR_PTR(error);
        }
        httpserver_client_set_state(httpserver_client, MEDUSA_HTTPSERVER_CLIENT_STATE_ERROR);
        httpserver_client->error = -error;
        medusa_httpserver_client_onevent_unlocked(httpserver_client, MEDUSA_HTTPSERVER_CLIENT_EVENT_ERROR, NULL);
        return httpserver_client;

}

__attribute__ ((visibility ("default"))) struct medusa_httpserver_client * medusa_httpserver_accept_with_options (struct medusa_httpserver *httpserver, struct medusa_httpserver_accept_options *options)
{
        struct medusa_httpserver_client *rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(httpserver->subject.monitor);
        rc = medusa_httpserver_accept_with_options_unlocked(httpserver, options);
        medusa_monitor_unlock(httpserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void medusa_httpserver_client_destroy_unlocked (struct medusa_httpserver_client *httpserver_client)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return;
        }
        if (httpserver_client->subject.monitor != NULL) {
                medusa_monitor_del_unlocked(&httpserver_client->subject);
        } else {
                medusa_httpserver_client_onevent_unlocked(httpserver_client, MEDUSA_HTTPSERVER_CLIENT_EVENT_DESTROY, NULL);
        }
}

__attribute__ ((visibility ("default"))) void medusa_httpserver_client_destroy (struct medusa_httpserver_client *httpserver_client)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return;
        }
        medusa_monitor_lock(httpserver_client->subject.monitor);
        medusa_httpserver_client_destroy_unlocked(httpserver_client);
        medusa_monitor_unlock(httpserver_client->subject.monitor);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_httpserver_client_get_state_unlocked (const struct medusa_httpserver_client *httpserver_client)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return MEDUSA_HTTPSERVER_STATE_UNKNOWN;
        }
        return httpserver_client->state;
}

__attribute__ ((visibility ("default"))) unsigned int medusa_httpserver_client_get_state (const struct medusa_httpserver_client *httpserver_client)
{
        unsigned int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return MEDUSA_HTTPSERVER_STATE_UNKNOWN;
        }
        medusa_monitor_lock(httpserver_client->subject.monitor);
        rc = medusa_httpserver_client_get_state_unlocked(httpserver_client);
        medusa_monitor_unlock(httpserver_client->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_set_enabled_unlocked (struct medusa_httpserver_client *httpserver_client, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        if (httpserver_client_has_flag(httpserver_client, MEDUSA_HTTPSERVER_CLIENT_FLAG_ENABLED) == !!enabled) {
                return 0;
        }
        if (enabled) {
                httpserver_client_add_flag(httpserver_client, MEDUSA_HTTPSERVER_CLIENT_FLAG_ENABLED);
        } else {
                httpserver_client_del_flag(httpserver_client, MEDUSA_HTTPSERVER_CLIENT_FLAG_ENABLED);
        }
        if (!MEDUSA_IS_ERR_OR_NULL(httpserver_client->tcpsocket)) {
                rc = medusa_tcpsocket_set_enabled_unlocked(httpserver_client->tcpsocket, enabled);
                if (rc < 0) {
                        return rc;
                }
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_set_enabled (struct medusa_httpserver_client *httpserver_client, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        medusa_monitor_lock(httpserver_client->subject.monitor);
        rc = medusa_httpserver_client_set_enabled_unlocked(httpserver_client, enabled);
        medusa_monitor_unlock(httpserver_client->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_get_enabled_unlocked (const struct medusa_httpserver_client *httpserver_client)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        return httpserver_client_has_flag(httpserver_client, MEDUSA_HTTPSERVER_CLIENT_FLAG_ENABLED);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_get_enabled (const struct medusa_httpserver_client *httpserver_client)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        medusa_monitor_lock(httpserver_client->subject.monitor);
        rc = medusa_httpserver_client_get_enabled_unlocked(httpserver_client);
        medusa_monitor_unlock(httpserver_client->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_set_read_timeout_unlocked (struct medusa_httpserver_client *httpserver_client, double timeout)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client->tcpsocket)) {
                return -EIO;
        }
        return medusa_tcpsocket_set_read_timeout_unlocked(httpserver_client->tcpsocket, timeout);        
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_set_read_timeout (struct medusa_httpserver_client *httpserver_client, double timeout)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        medusa_monitor_lock(httpserver_client->subject.monitor);
        rc = medusa_httpserver_client_set_read_timeout_unlocked(httpserver_client, timeout);
        medusa_monitor_unlock(httpserver_client->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) double medusa_httpserver_client_get_read_timeout_unlocked (const struct medusa_httpserver_client *httpserver_client)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client->tcpsocket)) {
                return -EIO;
        }
        return medusa_tcpsocket_get_read_timeout_unlocked(httpserver_client->tcpsocket);        
}

__attribute__ ((visibility ("default"))) double medusa_httpserver_client_get_read_timeout (const struct medusa_httpserver_client *httpserver_client)
{
        double rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        medusa_monitor_lock(httpserver_client->subject.monitor);
        rc = medusa_httpserver_client_get_read_timeout_unlocked(httpserver_client);
        medusa_monitor_unlock(httpserver_client->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) const struct medusa_httpserver_client_request * medusa_httprequest_client_get_request (const struct medusa_httpserver_client *httpserver_client)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return httpserver_client->request;
}

__attribute__ ((visibility ("default"))) const char * medusa_httpserver_client_request_get_method (const struct medusa_httpserver_client_request *request)
{
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return request->method;
}

__attribute__ ((visibility ("default"))) const char * medusa_httpserver_client_request_get_path (const struct medusa_httpserver_client_request *request)
{
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return request->url;
}

__attribute__ ((visibility ("default"))) const struct medusa_httpserver_client_request_headers * medusa_httpserver_client_request_get_headers (const struct medusa_httpserver_client_request *request)
{
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return &request->headers;
}

__attribute__ ((visibility ("default"))) int64_t medusa_httpserver_client_request_headers_get_count (const struct medusa_httpserver_client_request_headers *headers)
{
        if (MEDUSA_IS_ERR_OR_NULL(headers)) {
                return -EINVAL;
        }
        return headers->count;
}

__attribute__ ((visibility ("default"))) const struct medusa_httpserver_client_request_header * medusa_httpserver_client_request_headers_get_first (const struct medusa_httpserver_client_request_headers *headers)
{
        if (MEDUSA_IS_ERR_OR_NULL(headers)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return TAILQ_FIRST(&headers->list);
}

__attribute__ ((visibility ("default"))) const char * medusa_httpserver_client_request_header_get_key (const struct medusa_httpserver_client_request_header *header)
{
        if (MEDUSA_IS_ERR_OR_NULL(header)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return header->key;
}

__attribute__ ((visibility ("default"))) const char * medusa_httpserver_client_request_header_get_value (const struct medusa_httpserver_client_request_header *header)
{
        if (MEDUSA_IS_ERR_OR_NULL(header)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return header->value;
}

__attribute__ ((visibility ("default"))) const struct medusa_httpserver_client_request_header * medusa_httpserver_client_request_header_get_next (const struct medusa_httpserver_client_request_header *header)
{
        if (MEDUSA_IS_ERR_OR_NULL(header)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return TAILQ_NEXT(header, list);
}

__attribute__ ((visibility ("default"))) const struct medusa_httpserver_client_request_body * medusa_httpserver_client_request_get_body (const struct medusa_httpserver_client_request *request)
{
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return &request->body;
}

__attribute__ ((visibility ("default"))) int64_t medusa_httpserver_client_request_body_get_length (const struct medusa_httpserver_client_request_body *body)
{
        if (MEDUSA_IS_ERR_OR_NULL(body)) {
                return -EINVAL;
        }
        return body->length;
}

__attribute__ ((visibility ("default"))) const void * medusa_httpserver_client_request_body_get_value (const struct medusa_httpserver_client_request_body *body)
{
        if (MEDUSA_IS_ERR_OR_NULL(body)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return body->value;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_reply_send_start_unlocked (struct medusa_httpserver_client *httpserver_client)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_reply_send_start (struct medusa_httpserver_client *httpserver_client)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        medusa_monitor_lock(httpserver_client->subject.monitor);
        rc = medusa_httpserver_client_reply_send_start_unlocked(httpserver_client);
        medusa_monitor_unlock(httpserver_client->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_reply_send_status_unlocked (struct medusa_httpserver_client *httpserver_client, int code, const char *reason, ...)
{
        int rc;
        va_list va;
        va_start(va, reason);
        rc = medusa_httpserver_client_reply_send_vstatus_unlocked(httpserver_client, code, reason, va);
        va_end(va);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_reply_send_status (struct medusa_httpserver_client *httpserver_client, int code, const char *reason, ...)
{
        int rc;
        va_list va;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        va_start(va, reason);
        rc = medusa_httpserver_client_reply_send_vstatus(httpserver_client, code, reason, va);
        va_end(va);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_reply_send_vstatus_unlocked (struct medusa_httpserver_client *httpserver_client, int code, const char *reason, va_list va)
{
        int rc;
        struct medusa_buffer *buffer;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        buffer = medusa_tcpsocket_get_write_buffer_unlocked(httpserver_client->tcpsocket);
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        rc  = medusa_buffer_printf(buffer, "HTTP/1.0 %d ", code);
        if (rc < 0) {
                return rc;
        }
        if (reason == NULL) {
                rc  = medusa_buffer_printf(buffer, "%d", code);
                if (rc < 0) {
                        return rc;
                }
        } else {
                rc = medusa_buffer_vprintf(buffer, reason, va);
                if (rc < 0) {
                        return rc;
                }
        }
        rc = medusa_buffer_printf(buffer, "\r\n");
        if (rc < 0) {
                return rc;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_reply_send_vstatus (struct medusa_httpserver_client *httpserver_client, int code, const char *reason, va_list va)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        medusa_monitor_lock(httpserver_client->subject.monitor);
        rc = medusa_httpserver_client_reply_send_vstatus_unlocked(httpserver_client, code, reason, va);
        medusa_monitor_unlock(httpserver_client->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_reply_send_header_unlocked (struct medusa_httpserver_client *httpserver_client, const char *key, const char *value, ...)
{
        int64_t rc;
        va_list va;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(key)) {
                return -EINVAL;
        }
        va_start(va, value);
        rc = medusa_httpserver_client_reply_send_vheader_unlocked(httpserver_client, key, value, va);
        va_end(va);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_reply_send_header (struct medusa_httpserver_client *httpserver_client, const char *key, const char *value, ...)
{
        int64_t rc;
        va_list va;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        va_start(va, value);
        rc = medusa_httpserver_client_reply_send_vheader(httpserver_client, key, value, va);
        va_end(va);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_reply_send_vheader_unlocked (struct medusa_httpserver_client *httpserver_client, const char *key, const char *value, va_list va)
{
        int rc;
        struct medusa_buffer *buffer;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        buffer = medusa_tcpsocket_get_write_buffer_unlocked(httpserver_client->tcpsocket);
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        if (key == NULL) {
                rc = medusa_buffer_printf(buffer, "\r\n");
                if (rc < 0) {
                        return rc;
                }
        } else {
                rc  = medusa_buffer_printf(buffer, "%s:", key);
                if (rc < 0) {
                        return rc;
                }
                if (value != NULL) {
                        rc = medusa_buffer_vprintf(buffer, value, va);
                        if (rc < 0) {
                                return rc;
                        }
                }
        }
        rc = medusa_buffer_printf(buffer, "\r\n");
        if (rc < 0) {
                return rc;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_reply_send_vheader (struct medusa_httpserver_client *httpserver_client, const char *key, const char *value, va_list va)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        medusa_monitor_lock(httpserver_client->subject.monitor);
        rc = medusa_httpserver_client_reply_send_vheader_unlocked(httpserver_client, key, value, va);
        medusa_monitor_unlock(httpserver_client->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_reply_send_body_unlocked (struct medusa_httpserver_client *httpserver_client, const void *body, int length)
{
        int rc;
        struct medusa_buffer *buffer;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(body)) {
                return -EINVAL;
        }
        buffer = medusa_tcpsocket_get_write_buffer_unlocked(httpserver_client->tcpsocket);
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        rc  = medusa_buffer_write(buffer, body, length);
        if (rc < 0) {
                return rc;
        }
        rc = medusa_buffer_printf(buffer, "\r\n");
        if (rc < 0) {
                return rc;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_reply_send_body (struct medusa_httpserver_client *httpserver_client, const void *body, int length)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        medusa_monitor_lock(httpserver_client->subject.monitor);
        rc = medusa_httpserver_client_reply_send_body_unlocked(httpserver_client, body, length);
        medusa_monitor_unlock(httpserver_client->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_reply_send_bodyf_unlocked (struct medusa_httpserver_client *httpserver_client, const char *body, ...)
{
        int rc;
        va_list va;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        va_start(va, body);
        rc = medusa_httpserver_client_reply_send_vbody_unlocked(httpserver_client, body, va);
        va_end(va);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_reply_send_bodyf (struct medusa_httpserver_client *httpserver_client, const char *body, ...)
{
        int rc;
        va_list va;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        va_start(va, body);
        rc = medusa_httpserver_client_reply_send_vbody(httpserver_client, body, va);
        va_end(va);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_reply_send_vbody_unlocked (struct medusa_httpserver_client *httpserver_client, const char *body, va_list va)
{
        int rc;
        struct medusa_buffer *buffer;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(body)) {
                return -EINVAL;
        }
        buffer = medusa_tcpsocket_get_write_buffer_unlocked(httpserver_client->tcpsocket);
        if (MEDUSA_IS_ERR_OR_NULL(buffer)) {
                return -EINVAL;
        }
        rc  = medusa_buffer_vprintf(buffer, body, va);
        if (rc < 0) {
                return rc;
        }
        rc = medusa_buffer_printf(buffer, "\r\n");
        if (rc < 0) {
                return rc;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_reply_send_vbody (struct medusa_httpserver_client *httpserver_client, const char *body, va_list va)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        medusa_monitor_lock(httpserver_client->subject.monitor);
        rc = medusa_httpserver_client_reply_send_vbody_unlocked(httpserver_client, body, va);
        medusa_monitor_unlock(httpserver_client->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_reply_send_finish_unlocked (struct medusa_httpserver_client *httpserver_client)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_reply_send_finish (struct medusa_httpserver_client *httpserver_client)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        medusa_monitor_lock(httpserver_client->subject.monitor);
        rc = medusa_httpserver_client_reply_send_finish_unlocked(httpserver_client);
        medusa_monitor_unlock(httpserver_client->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_set_context_unlocked (struct medusa_httpserver_client *httpserver_client, void *context)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        httpserver_client->context = context;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_set_context (struct medusa_httpserver_client *httpserver_client, void *context)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        medusa_monitor_lock(httpserver_client->subject.monitor);
        rc = medusa_httpserver_client_set_context_unlocked(httpserver_client, context);
        medusa_monitor_unlock(httpserver_client->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void * medusa_httpserver_client_get_context_unlocked (struct medusa_httpserver_client *httpserver_client)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return httpserver_client->context;
}

__attribute__ ((visibility ("default"))) void * medusa_httpserver_client_get_context (struct medusa_httpserver_client *httpserver_client)
{
        void *rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(httpserver_client->subject.monitor);
        rc = medusa_httpserver_client_get_context_unlocked(httpserver_client);
        medusa_monitor_unlock(httpserver_client->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_set_userdata_unlocked (struct medusa_httpserver_client *httpserver_client, void *userdata)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        httpserver_client->userdata = userdata;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_set_userdata (struct medusa_httpserver_client *httpserver_client, void *userdata)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        medusa_monitor_lock(httpserver_client->subject.monitor);
        rc = medusa_httpserver_client_set_userdata_unlocked(httpserver_client, userdata);
        medusa_monitor_unlock(httpserver_client->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void * medusa_httpserver_client_get_userdata_unlocked (struct medusa_httpserver_client *httpserver_client)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return httpserver_client->userdata;
}

__attribute__ ((visibility ("default"))) void * medusa_httpserver_client_get_userdata (struct medusa_httpserver_client *httpserver_client)
{
        void *rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(httpserver_client->subject.monitor);
        rc = medusa_httpserver_client_get_userdata_unlocked(httpserver_client);
        medusa_monitor_unlock(httpserver_client->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_set_userdata_ptr_unlocked (struct medusa_httpserver_client *httpserver_client, void *userdata)
{
        return medusa_httpserver_client_set_userdata_unlocked(httpserver_client, userdata);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_set_userdata_ptr (struct medusa_httpserver_client *httpserver_client, void *userdata)
{
        return medusa_httpserver_client_set_userdata(httpserver_client, userdata);
}

__attribute__ ((visibility ("default"))) void * medusa_httpserver_client_get_userdata_ptr_unlocked (struct medusa_httpserver_client *httpserver_client)
{
        return medusa_httpserver_client_get_userdata_unlocked(httpserver_client);
}

__attribute__ ((visibility ("default"))) void * medusa_httpserver_client_get_userdata_ptr (struct medusa_httpserver_client *httpserver_client)
{
        return medusa_httpserver_client_get_userdata(httpserver_client);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_set_userdata_int_unlocked (struct medusa_httpserver_client *httpserver_client, int userdata)
{
        return medusa_httpserver_client_set_userdata_unlocked(httpserver_client, (void *) (intptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_set_userdata_int (struct medusa_httpserver_client *httpserver_client, int userdata)
{
        return medusa_httpserver_client_set_userdata(httpserver_client, (void *) (intptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_get_userdata_int_unlocked (struct medusa_httpserver_client *httpserver_client)
{
        return (int) (intptr_t) medusa_httpserver_client_get_userdata_unlocked(httpserver_client);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_get_userdata_int (struct medusa_httpserver_client *httpserver_client)
{
        return (int) (intptr_t) medusa_httpserver_client_get_userdata(httpserver_client);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_set_userdata_uint_unlocked (struct medusa_httpserver_client *httpserver_client, unsigned int userdata)
{
        return medusa_httpserver_client_set_userdata_unlocked(httpserver_client, (void *) (uintptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_set_userdata_uint (struct medusa_httpserver_client *httpserver_client, unsigned int userdata)
{
        return medusa_httpserver_client_set_userdata(httpserver_client, (void *) (uintptr_t) userdata);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_httpserver_client_get_userdata_uint_unlocked (struct medusa_httpserver_client *httpserver_client)
{
        return (unsigned int) (intptr_t) medusa_httpserver_client_get_userdata_unlocked(httpserver_client);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_httpserver_client_get_userdata_uint (struct medusa_httpserver_client *httpserver_client)
{
        return (unsigned int) (uintptr_t) medusa_httpserver_client_get_userdata(httpserver_client);
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_onevent_unlocked (struct medusa_httpserver_client *httpserver_client, unsigned int events, void *param)
{
        int ret;
        struct medusa_monitor *monitor;
        ret = 0;
        monitor = httpserver_client->subject.monitor;
        if (httpserver_client->onevent != NULL) {
                if ((medusa_subject_is_active(&httpserver_client->subject)) ||
                    (events & MEDUSA_HTTPSERVER_CLIENT_EVENT_DESTROY)) {
                        medusa_monitor_unlock(monitor);
                        ret = httpserver_client->onevent(httpserver_client, events, httpserver_client->context, param);
                        medusa_monitor_lock(monitor);
                }
        }
        if (events & MEDUSA_HTTPSERVER_CLIENT_EVENT_DESTROY) {
                if (httpserver_client->request != NULL) {
                        medusa_httpserver_client_request_destroy(httpserver_client->request);
                        httpserver_client->request = NULL;
                }
                if (!MEDUSA_IS_ERR_OR_NULL(httpserver_client->tcpsocket)) {
                        medusa_tcpsocket_destroy_unlocked(httpserver_client->tcpsocket);
                        httpserver_client->tcpsocket = NULL;       
                }
                if (httpserver_client->httpserver != NULL) {
                        TAILQ_REMOVE(&httpserver_client->httpserver->clients, httpserver_client, list);
                        httpserver_client->httpserver = NULL;
                }
#if defined(MEDUSA_HTTPSERVER_USE_POOL) && (MEDUSA_HTTPSERVER_USE_POOL == 1)
                medusa_pool_free(httpserver_client);
#else
                free(httpserver_client);
#endif
        }
        return ret;
}

__attribute__ ((visibility ("default"))) int medusa_httpserver_client_onevent (struct medusa_httpserver_client *httpserver_client, unsigned int events, void *param)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return -EINVAL;
        }
        medusa_monitor_lock(httpserver_client->subject.monitor);
        rc = medusa_httpserver_client_onevent_unlocked(httpserver_client, events, param);
        medusa_monitor_unlock(httpserver_client->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_httpserver_client_get_monitor_unlocked (struct medusa_httpserver_client *httpserver_client)
{
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return httpserver_client->subject.monitor;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_httpserver_client_get_monitor (struct medusa_httpserver_client *httpserver_client)
{
        struct medusa_monitor *rc;
        if (MEDUSA_IS_ERR_OR_NULL(httpserver_client)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(httpserver_client->subject.monitor);
        rc = medusa_httpserver_client_get_monitor_unlocked(httpserver_client);
        medusa_monitor_unlock(httpserver_client->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) const char * medusa_httpserver_client_event_string (unsigned int events)
{
        if (events == MEDUSA_HTTPSERVER_CLIENT_EVENT_ERROR)                        return "MEDUSA_HTTPSERVER_CLIENT_EVENT_ERROR";
        if (events == MEDUSA_HTTPSERVER_CLIENT_EVENT_CONNECTED)                    return "MEDUSA_HTTPSERVER_CLIENT_EVENT_CONNECTED";
        if (events == MEDUSA_HTTPSERVER_CLIENT_EVENT_REQUEST_RECEIVING)            return "MEDUSA_HTTPSERVER_CLIENT_EVENT_REQUEST_RECEIVING";
        if (events == MEDUSA_HTTPSERVER_CLIENT_EVENT_REQUEST_RECEIVED)             return "MEDUSA_HTTPSERVER_CLIENT_EVENT_REQUEST_RECEIVED";
        if (events == MEDUSA_HTTPSERVER_CLIENT_EVENT_REQUEST_RECEIVE_TIMEOUT)      return "MEDUSA_HTTPSERVER_CLIENT_EVENT_REQUEST_RECEIVE_TIMEOUT";
        if (events == MEDUSA_HTTPSERVER_CLIENT_EVENT_BUFFERED_WRITE)               return "MEDUSA_HTTPSERVER_CLIENT_EVENT_BUFFERED_WRITE";
        if (events == MEDUSA_HTTPSERVER_CLIENT_EVENT_BUFFERED_WRITE_FINISHED)      return "MEDUSA_HTTPSERVER_CLIENT_EVENT_BUFFERED_WRITE_FINISHED";
        if (events == MEDUSA_HTTPSERVER_CLIENT_EVENT_DISCONNECTED)                 return "MEDUSA_HTTPSERVER_CLIENT_EVENT_DISCONNECTED";
        if (events == MEDUSA_HTTPSERVER_CLIENT_EVENT_DESTROY)                      return "MEDUSA_HTTPSERVER_CLIENT_EVENT_DESTROY";
        return "MEDUSA_HTTPSERVER_CLIENT_EVENT_UNKNOWN";
}

__attribute__ ((visibility ("default"))) const char * medusa_httpserver_client_state_string (unsigned int state)
{
        if (state == MEDUSA_HTTPSERVER_CLIENT_STATE_UNKNOWN)               return "MEDUSA_HTTPSERVER_CLIENT_STATE_UNKNOWN";
        if (state == MEDUSA_HTTPSERVER_CLIENT_STATE_CONNECTED)             return "MEDUSA_HTTPSERVER_CLIENT_STATE_CONNECTED";
        if (state == MEDUSA_HTTPSERVER_CLIENT_STATE_REQUEST_RECEIVING)     return "MEDUSA_HTTPSERVER_CLIENT_STATE_REQUEST_RECEIVING";
        if (state == MEDUSA_HTTPSERVER_CLIENT_STATE_REQUEST_RECEIVED)      return "MEDUSA_HTTPSERVER_CLIENT_STATE_REQUEST_RECEIVED";
        if (state == MEDUSA_HTTPSERVER_CLIENT_STATE_DISCONNECTED)          return "MEDUSA_HTTPSERVER_CLIENT_STATE_DISCONNECTED";
        if (state == MEDUSA_HTTPSERVER_CLIENT_STATE_ERROR)                 return "MEDUSA_HTTPSERVER_CLIENT_STATE_ERROR";
        return "MEDUSA_HTTPSERVER_CLIENT_STATE_UNKNOWN";
}

__attribute__ ((constructor)) static void httpserver_constructor (void)
{
#if defined(MEDUSA_HTTPSERVER_USE_POOL) && (MEDUSA_HTTPSERVER_USE_POOL == 1)
        g_pool_httpserver = medusa_pool_create("medusa-httpserver", sizeof(struct medusa_httpserver), 0, 0, MEDUSA_POOL_FLAG_DEFAULT | MEDUSA_POOL_FLAG_THREAD_SAFE, NULL, NULL, NULL);
        g_pool_httpserver_client = medusa_pool_create("medusa-httpserver-client", sizeof(struct medusa_httpserver_client), 0, 0, MEDUSA_POOL_FLAG_DEFAULT | MEDUSA_POOL_FLAG_THREAD_SAFE, NULL, NULL, NULL);
#endif
}

__attribute__ ((destructor)) static void httpserver_destructor (void)
{
#if defined(MEDUSA_HTTPSERVER_USE_POOL) && (MEDUSA_HTTPSERVER_USE_POOL == 1)
        if (g_pool_httpserver_client != NULL) {
                medusa_pool_destroy(g_pool_httpserver_client);
        }
        if (g_pool_httpserver != NULL) {
                medusa_pool_destroy(g_pool_httpserver);
        }
#endif
}
