
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
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
#include "websocketserver.h"
#include "websocketserver-private.h"
#include "websocketserver-struct.h"
#include "monitor-private.h"

#define MEDUSA_WEBSOCKETSERVER_USE_POOL         1

#if defined(MEDUSA_WEBSOCKETSERVER_USE_POOL) && (MEDUSA_WEBSOCKETSERVER_USE_POOL == 1)
static struct medusa_pool *g_pool_websocketserver;
static struct medusa_pool *g_pool_websocketserver_client;
#endif

enum {
        MEDUSA_WEBSOCKETSERVER_FLAG_NONE                = (1 << 0),
        MEDUSA_WEBSOCKETSERVER_FLAG_ENABLED             = (1 << 1)
#define MEDUSA_WEBSOCKETSERVER_FLAG_NONE                MEDUSA_WEBSOCKETSERVER_FLAG_NONE
#define MEDUSA_WEBSOCKETSERVER_FLAG_ENABLED             MEDUSA_WEBSOCKETSERVER_FLAG_ENABLED
};

static inline void websocketserver_set_flag (struct medusa_websocketserver *websocketserver, unsigned int flag)
{
        websocketserver->flags = flag;
}

static inline void websocketserver_add_flag (struct medusa_websocketserver *websocketserver, unsigned int flag)
{
        websocketserver->flags |= flag;
}

static inline void websocketserver_del_flag (struct medusa_websocketserver *websocketserver, unsigned int flag)
{
        websocketserver->flags &= ~flag;
}

static inline int websocketserver_has_flag (const struct medusa_websocketserver *websocketserver, unsigned int flag)
{
        return !!(websocketserver->flags & flag);
}

static inline int websocketserver_set_state (struct medusa_websocketserver *websocketserver, unsigned int state)
{
        if (state == MEDUSA_WEBSOCKETSERVER_STATE_STOPPED) {
                if (!MEDUSA_IS_ERR_OR_NULL(websocketserver->tcpsocket)) {
                        medusa_tcpsocket_destroy_unlocked(websocketserver->tcpsocket);
                        websocketserver->tcpsocket = NULL;
                }
        }
        websocketserver->state = state;
        return 0;
}

static unsigned int websocketserver_protocol_to_tcpsocket_protocol (unsigned int protocol)
{
        switch (protocol) {
                case MEDUSA_WEBSOCKETSERVER_PROTOCOL_IPV4:      return MEDUSA_TCPSOCKET_PROTOCOL_IPV4;
                case MEDUSA_WEBSOCKETSERVER_PROTOCOL_IPV6:      return MEDUSA_TCPSOCKET_PROTOCOL_IPV6;
        }
        return MEDUSA_TCPSOCKET_PROTOCOL_ANY;
}

static int websocketserver_tcpsocket_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, void *param)
{
        int rc;
        int error;
        struct medusa_monitor *monitor;
        struct medusa_websocketserver *websocketserver = (struct medusa_websocketserver *) context;

        (void) param;

        fprintf(stderr, "websocketserver.tcpsocket.events: 0x%08x, %s\n", events, medusa_tcpsocket_event_string(events));

        if (events & MEDUSA_TCPSOCKET_EVENT_DESTROY) {
                return 0;
        }

        monitor = medusa_tcpsocket_get_monitor(tcpsocket);
        medusa_monitor_lock(monitor);

        if (events & MEDUSA_TCPSOCKET_EVENT_BINDING) {
                rc = websocketserver_set_state(websocketserver, MEDUSA_WEBSOCKETSERVER_STATE_BINDING);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
                rc = medusa_websocketserver_onevent_unlocked(websocketserver, MEDUSA_WEBSOCKETSERVER_EVENT_BINDING, NULL);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_BOUND) {
                rc = websocketserver_set_state(websocketserver, MEDUSA_WEBSOCKETSERVER_STATE_BOUND);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
                rc = medusa_websocketserver_onevent_unlocked(websocketserver, MEDUSA_WEBSOCKETSERVER_EVENT_BOUND, NULL);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_LISTENING) {
                rc = websocketserver_set_state(websocketserver, MEDUSA_WEBSOCKETSERVER_STATE_LISTENING);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
                rc = medusa_websocketserver_onevent_unlocked(websocketserver, MEDUSA_WEBSOCKETSERVER_EVENT_LISTENING, NULL);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
        }
        if (events & MEDUSA_TCPSOCKET_EVENT_CONNECTION) {
                rc = medusa_websocketserver_onevent_unlocked(websocketserver, MEDUSA_WEBSOCKETSERVER_EVENT_CONNECTION, NULL);
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

static int websocketserver_init_with_options_unlocked (struct medusa_websocketserver *websocketserver, const struct medusa_websocketserver_init_options *options)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
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
        memset(websocketserver, 0, sizeof(struct medusa_websocketserver));
        TAILQ_INIT(&websocketserver->clients);
        medusa_subject_set_type(&websocketserver->subject, MEDUSA_SUBJECT_TYPE_WEBSOCKETSERVER);
        websocketserver->subject.monitor = NULL;
        websocketserver_set_state(websocketserver, MEDUSA_WEBSOCKETSERVER_STATE_STOPPED);
        websocketserver_set_flag(websocketserver, MEDUSA_WEBSOCKETSERVER_FLAG_NONE);
        websocketserver->onevent = options->onevent;
        websocketserver->context = options->context;
        rc = medusa_monitor_add_unlocked(options->monitor, &websocketserver->subject);
        if (rc < 0) {
                return rc;
        }
        return 0;
}

static void websocketserver_uninit_unlocked (struct medusa_websocketserver *websocketserver)
{
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return;
        }
        if (websocketserver->subject.monitor != NULL) {
                medusa_monitor_del_unlocked(&websocketserver->subject);
        } else {
                medusa_websocketserver_onevent_unlocked(websocketserver, MEDUSA_WEBSOCKETSERVER_EVENT_DESTROY, NULL);
        }
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_init_options_default (struct medusa_websocketserver_init_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_websocketserver_init_options));
        options->protocol   = MEDUSA_WEBSOCKETSERVER_PROTOCOL_ANY;
        options->address    = NULL;
        options->port       = 0;
        options->servername = NULL;
        return 0;
}

__attribute__ ((visibility ("default"))) struct medusa_websocketserver * medusa_websocketserver_create_unlocked (struct medusa_monitor *monitor, unsigned int protocol, const char *address, unsigned short port, int (*onevent) (struct medusa_websocketserver *websocketserver, unsigned int events, void *context, void *param), void *context)
{
        int rc;
        struct medusa_websocketserver_init_options options;
        rc = medusa_websocketserver_init_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.monitor  = monitor;
        options.protocol = protocol;
        options.address  = address;
        options.port     = port;
        options.onevent  = onevent;
        options.context  = context;
        return medusa_websocketserver_create_with_options_unlocked(&options);
}

__attribute__ ((visibility ("default"))) struct medusa_websocketserver * medusa_websocketserver_create (struct medusa_monitor *monitor, unsigned int protocol, const char *address, unsigned short port, int (*onevent) (struct medusa_websocketserver *websocketserver, unsigned int events, void *context, void *param), void *context)
{
        struct medusa_websocketserver *rc;
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(monitor);
        rc = medusa_websocketserver_create_unlocked(monitor, protocol, address, port, onevent, context);
        medusa_monitor_unlock(monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_websocketserver * medusa_websocketserver_create_with_options_unlocked (const struct medusa_websocketserver_init_options *options)
{
        int rc;
        int error;
        struct medusa_websocketserver *websocketserver;

        websocketserver = NULL;

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

#if defined(MEDUSA_WEBSOCKETSERVER_USE_POOL) && (MEDUSA_WEBSOCKETSERVER_USE_POOL == 1)
        websocketserver = medusa_pool_malloc(g_pool_websocketserver);
#else
        websocketserver = malloc(sizeof(struct medusa_websocketserver));
#endif
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                error = -ENOMEM;
                goto bail;
        }
        memset(websocketserver, 0, sizeof(struct medusa_websocketserver));
        rc = websocketserver_init_with_options_unlocked(websocketserver, options);
        if (rc < 0) {
                error = rc;
                goto bail;
        }

        if (options->address != NULL) {
                websocketserver->address = strdup(options->address);
                if (websocketserver->address == NULL) {
                error = -ENOMEM;
                goto bail;
                }
        }
        if (options->servername != NULL) {
                websocketserver->servername = strdup(options->servername);
                if (websocketserver->servername == NULL) {
                        error = -ENOMEM;
                        goto bail;
                }
        }
        websocketserver->port     = options->port;
        websocketserver->protocol = options->protocol;
        rc = medusa_websocketserver_set_enabled_unlocked(websocketserver, options->enabled);
        if (rc < 0) {
                error = rc;
                goto bail;
        }
        rc = medusa_websocketserver_set_started_unlocked(websocketserver, options->started);
        if (rc < 0) {
                error = rc;
                goto bail;
        }

        return websocketserver;
bail:   if (!MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                medusa_websocketserver_destroy_unlocked(websocketserver);
        }
        return MEDUSA_ERR_PTR(error);
}

__attribute__ ((visibility ("default"))) struct medusa_websocketserver * medusa_websocketserver_create_with_options (const struct medusa_websocketserver_init_options *options)
{
        struct medusa_websocketserver *rc;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(options->monitor);
        rc = medusa_websocketserver_create_with_options_unlocked(options);
        medusa_monitor_unlock(options->monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void medusa_websocketserver_destroy_unlocked (struct medusa_websocketserver *websocketserver)
{
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return;
        }
        websocketserver_uninit_unlocked(websocketserver);
}

__attribute__ ((visibility ("default"))) void medusa_websocketserver_destroy (struct medusa_websocketserver *websocketserver)
{
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return;
        }
        medusa_monitor_lock(websocketserver->subject.monitor);
        medusa_websocketserver_destroy_unlocked(websocketserver);
        medusa_monitor_unlock(websocketserver->subject.monitor);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_websocketserver_get_state_unlocked (const struct medusa_websocketserver *websocketserver)
{
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return MEDUSA_WEBSOCKETSERVER_STATE_UNKNOWN;
        }
        return websocketserver->state;
}

__attribute__ ((visibility ("default"))) unsigned int medusa_websocketserver_get_state (const struct medusa_websocketserver *websocketserver)
{
        unsigned int rc;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return MEDUSA_WEBSOCKETSERVER_STATE_UNKNOWN;
        }
        medusa_monitor_lock(websocketserver->subject.monitor);
        rc = medusa_websocketserver_get_state_unlocked(websocketserver);
        medusa_monitor_unlock(websocketserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_set_enabled_unlocked (struct medusa_websocketserver *websocketserver, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return -EINVAL;
        }
        if (websocketserver_has_flag(websocketserver, MEDUSA_WEBSOCKETSERVER_FLAG_ENABLED) == !!enabled) {
                return 0;
        }
        if (enabled) {
                websocketserver_add_flag(websocketserver, MEDUSA_WEBSOCKETSERVER_FLAG_ENABLED);
        } else {
                websocketserver_del_flag(websocketserver, MEDUSA_WEBSOCKETSERVER_FLAG_ENABLED);
        }
        if (!MEDUSA_IS_ERR_OR_NULL(websocketserver->tcpsocket)) {
                rc = medusa_tcpsocket_set_enabled_unlocked(websocketserver->tcpsocket, enabled);
                if (rc < 0) {
                        return rc;
                }
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_set_enabled (struct medusa_websocketserver *websocketserver, int enabled)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return -EINVAL;
        }
        medusa_monitor_lock(websocketserver->subject.monitor);
        rc = medusa_websocketserver_set_enabled_unlocked(websocketserver, enabled);
        medusa_monitor_unlock(websocketserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_get_enabled_unlocked (const struct medusa_websocketserver *websocketserver)
{
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return -EINVAL;
        }
        return websocketserver_has_flag(websocketserver, MEDUSA_WEBSOCKETSERVER_FLAG_ENABLED);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_get_enabled (const struct medusa_websocketserver *websocketserver)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return -EINVAL;
        }
        medusa_monitor_lock(websocketserver->subject.monitor);
        rc = medusa_websocketserver_get_enabled_unlocked(websocketserver);
        medusa_monitor_unlock(websocketserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_pause_unlocked (struct medusa_websocketserver *websocketserver)
{
        return medusa_websocketserver_set_enabled_unlocked(websocketserver, 0);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_pause (struct medusa_websocketserver *websocketserver)
{
        return medusa_websocketserver_set_enabled(websocketserver, 0);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_resume_unlocked (struct medusa_websocketserver *websocketserver)
{
        return medusa_websocketserver_set_enabled_unlocked(websocketserver, 1);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_resume (struct medusa_websocketserver *websocketserver)
{
        return medusa_websocketserver_set_enabled(websocketserver, 1);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_set_started_unlocked (struct medusa_websocketserver *websocketserver, int started)
{
        int rc;
        int error;
        struct medusa_tcpsocket_bind_options medusa_tcpsocket_bind_options;

        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return -EINVAL;
        }

        if (started) {
                if (websocketserver->state != MEDUSA_WEBSOCKETSERVER_STATE_STOPPED) {
                        error = -EALREADY;
                        goto bail;
                }
                if (!MEDUSA_IS_ERR_OR_NULL(websocketserver->tcpsocket)) {
                        error = EIO;
                        goto bail;
                }
                rc = medusa_tcpsocket_bind_options_default(&medusa_tcpsocket_bind_options);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
                medusa_tcpsocket_bind_options.protocol    = websocketserver_protocol_to_tcpsocket_protocol(websocketserver->protocol);
                medusa_tcpsocket_bind_options.address     = websocketserver->address;
                medusa_tcpsocket_bind_options.port        = websocketserver->port;
                medusa_tcpsocket_bind_options.buffered    = 1;
                medusa_tcpsocket_bind_options.nodelay     = 1;
                medusa_tcpsocket_bind_options.nonblocking = 1;
                medusa_tcpsocket_bind_options.reuseaddr   = 1;
                medusa_tcpsocket_bind_options.reuseport   = 0;
                medusa_tcpsocket_bind_options.enabled     = 1;
                medusa_tcpsocket_bind_options.monitor     = websocketserver->subject.monitor;
                medusa_tcpsocket_bind_options.context     = websocketserver;
                medusa_tcpsocket_bind_options.onevent     = websocketserver_tcpsocket_onevent;
                websocketserver->tcpsocket = medusa_tcpsocket_bind_with_options_unlocked(&medusa_tcpsocket_bind_options);
                if (MEDUSA_IS_ERR_OR_NULL(websocketserver->tcpsocket)) {
                        error =  MEDUSA_PTR_ERR(websocketserver->tcpsocket);
                        goto bail;
                }
                websocketserver_set_state(websocketserver, MEDUSA_WEBSOCKETSERVER_STATE_STARTED);
                medusa_websocketserver_onevent_unlocked(websocketserver, MEDUSA_WEBSOCKETSERVER_EVENT_STARTED, NULL);
        } else {
                if (websocketserver->state == MEDUSA_WEBSOCKETSERVER_STATE_STOPPED) {
                        return -EALREADY;
                }
                if (MEDUSA_IS_ERR_OR_NULL(websocketserver->tcpsocket)) {
                        return -EIO;
                }
                medusa_tcpsocket_destroy_unlocked(websocketserver->tcpsocket);
                websocketserver->tcpsocket = NULL;
                websocketserver_set_state(websocketserver, MEDUSA_WEBSOCKETSERVER_STATE_STOPPED);
                medusa_websocketserver_onevent_unlocked(websocketserver, MEDUSA_WEBSOCKETSERVER_EVENT_STOPPED, NULL);
        }
        return 0;
bail:   return error;
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_set_started (struct medusa_websocketserver *websocketserver, int started)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return -EINVAL;
        }
        medusa_monitor_lock(websocketserver->subject.monitor);
        rc = medusa_websocketserver_set_started_unlocked(websocketserver, started);
        medusa_monitor_unlock(websocketserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_get_started_unlocked (const struct medusa_websocketserver *websocketserver)
{
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return -EINVAL;
        }
        return websocketserver_has_flag(websocketserver, MEDUSA_WEBSOCKETSERVER_FLAG_ENABLED);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_get_started (const struct medusa_websocketserver *websocketserver)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return -EINVAL;
        }
        medusa_monitor_lock(websocketserver->subject.monitor);
        rc = medusa_websocketserver_get_started_unlocked(websocketserver);
        medusa_monitor_unlock(websocketserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_start_unlocked (struct medusa_websocketserver *websocketserver)
{
        return medusa_websocketserver_set_started_unlocked(websocketserver, 1);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_start (struct medusa_websocketserver *websocketserver)
{
        return medusa_websocketserver_set_started(websocketserver, 1);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_stop_unlocked (struct medusa_websocketserver *websocketserver)
{
        return medusa_websocketserver_set_started_unlocked(websocketserver, 0);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_stop (struct medusa_websocketserver *websocketserver)
{
        return medusa_websocketserver_set_started(websocketserver, 0);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_set_context_unlocked (struct medusa_websocketserver *websocketserver, void *context)
{
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return -EINVAL;
        }
        websocketserver->context = context;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_set_context (struct medusa_websocketserver *websocketserver, void *context)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return -EINVAL;
        }
        medusa_monitor_lock(websocketserver->subject.monitor);
        rc = medusa_websocketserver_set_context_unlocked(websocketserver, context);
        medusa_monitor_unlock(websocketserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void * medusa_websocketserver_get_context_unlocked (struct medusa_websocketserver *websocketserver)
{
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return websocketserver->context;
}

__attribute__ ((visibility ("default"))) void * medusa_websocketserver_get_context (struct medusa_websocketserver *websocketserver)
{
        void *rc;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(websocketserver->subject.monitor);
        rc = medusa_websocketserver_get_context_unlocked(websocketserver);
        medusa_monitor_unlock(websocketserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_set_userdata_unlocked (struct medusa_websocketserver *websocketserver, void *userdata)
{
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return -EINVAL;
        }
        websocketserver->userdata = userdata;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_set_userdata (struct medusa_websocketserver *websocketserver, void *userdata)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return -EINVAL;
        }
        medusa_monitor_lock(websocketserver->subject.monitor);
        rc = medusa_websocketserver_set_userdata_unlocked(websocketserver, userdata);
        medusa_monitor_unlock(websocketserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void * medusa_websocketserver_get_userdata_unlocked (struct medusa_websocketserver *websocketserver)
{
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return websocketserver->userdata;
}

__attribute__ ((visibility ("default"))) void * medusa_websocketserver_get_userdata (struct medusa_websocketserver *websocketserver)
{
        void *rc;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(websocketserver->subject.monitor);
        rc = medusa_websocketserver_get_userdata_unlocked(websocketserver);
        medusa_monitor_unlock(websocketserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_set_userdata_ptr_unlocked (struct medusa_websocketserver *websocketserver, void *userdata)
{
        return medusa_websocketserver_set_userdata_unlocked(websocketserver, userdata);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_set_userdata_ptr (struct medusa_websocketserver *websocketserver, void *userdata)
{
        return medusa_websocketserver_set_userdata(websocketserver, userdata);
}

__attribute__ ((visibility ("default"))) void * medusa_websocketserver_get_userdata_ptr_unlocked (struct medusa_websocketserver *websocketserver)
{
        return medusa_websocketserver_get_userdata_unlocked(websocketserver);
}

__attribute__ ((visibility ("default"))) void * medusa_websocketserver_get_userdata_ptr (struct medusa_websocketserver *websocketserver)
{
        return medusa_websocketserver_get_userdata(websocketserver);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_set_userdata_int_unlocked (struct medusa_websocketserver *websocketserver, int userdata)
{
        return medusa_websocketserver_set_userdata_unlocked(websocketserver, (void *) (intptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_set_userdata_int (struct medusa_websocketserver *websocketserver, int userdata)
{
        return medusa_websocketserver_set_userdata(websocketserver, (void *) (intptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_get_userdata_int_unlocked (struct medusa_websocketserver *websocketserver)
{
        return (int) (intptr_t) medusa_websocketserver_get_userdata_unlocked(websocketserver);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_get_userdata_int (struct medusa_websocketserver *websocketserver)
{
        return (int) (intptr_t) medusa_websocketserver_get_userdata(websocketserver);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_set_userdata_uint_unlocked (struct medusa_websocketserver *websocketserver, unsigned int userdata)
{
        return medusa_websocketserver_set_userdata_unlocked(websocketserver, (void *) (uintptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_set_userdata_uint (struct medusa_websocketserver *websocketserver, unsigned int userdata)
{
        return medusa_websocketserver_set_userdata(websocketserver, (void *) (uintptr_t) userdata);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_websocketserver_get_userdata_uint_unlocked (struct medusa_websocketserver *websocketserver)
{
        return (unsigned int) (intptr_t) medusa_websocketserver_get_userdata_unlocked(websocketserver);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_websocketserver_get_userdata_uint (struct medusa_websocketserver *websocketserver)
{
        return (unsigned int) (uintptr_t) medusa_websocketserver_get_userdata(websocketserver);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_onevent_unlocked (struct medusa_websocketserver *websocketserver, unsigned int events, void *param)
{
        int ret;
        struct medusa_monitor *monitor;
        ret = 0;
        monitor = websocketserver->subject.monitor;
        if (websocketserver->onevent != NULL) {
                if ((medusa_subject_is_active(&websocketserver->subject)) ||
                    (events & MEDUSA_WEBSOCKETSERVER_EVENT_DESTROY)) {
                        medusa_monitor_unlock(monitor);
                        ret = websocketserver->onevent(websocketserver, events, websocketserver->context, param);
                        medusa_monitor_lock(monitor);
                }
        }
        if (events & MEDUSA_WEBSOCKETSERVER_EVENT_DESTROY) {
                struct medusa_websocketserver_client *websocketserver_client;
                struct medusa_websocketserver_client *nwebsocketserver_client;
                TAILQ_FOREACH_SAFE(websocketserver_client, &websocketserver->clients, list, nwebsocketserver_client) {
                        TAILQ_REMOVE(&websocketserver->clients, websocketserver_client, list);
                        websocketserver_client->websocketserver = NULL;
                        medusa_websocketserver_client_destroy_unlocked(websocketserver_client);
                }
                if (websocketserver->address != NULL) {
                        free(websocketserver->address);
                }
                if (websocketserver->servername != NULL) {
                        free(websocketserver->servername);
                }
                if (!MEDUSA_IS_ERR_OR_NULL(websocketserver->tcpsocket)) {
                        medusa_tcpsocket_destroy_unlocked(websocketserver->tcpsocket);
                        websocketserver->tcpsocket = NULL;
                }
#if defined(MEDUSA_WEBSOCKETSERVER_USE_POOL) && (MEDUSA_WEBSOCKETSERVER_USE_POOL == 1)
                medusa_pool_free(websocketserver);
#else
                free(websocketserver);
#endif
        }
        return ret;
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_onevent (struct medusa_websocketserver *websocketserver, unsigned int events, void *param)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return -EINVAL;
        }
        medusa_monitor_lock(websocketserver->subject.monitor);
        rc = medusa_websocketserver_onevent_unlocked(websocketserver, events, param);
        medusa_monitor_unlock(websocketserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_websocketserver_get_monitor_unlocked (struct medusa_websocketserver *websocketserver)
{
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return websocketserver->subject.monitor;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_websocketserver_get_monitor (struct medusa_websocketserver *websocketserver)
{
        struct medusa_monitor *rc;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(websocketserver->subject.monitor);
        rc = medusa_websocketserver_get_monitor_unlocked(websocketserver);
        medusa_monitor_unlock(websocketserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) const char * medusa_websocketserver_event_string (unsigned int events)
{
        if (events == MEDUSA_WEBSOCKETSERVER_EVENT_STARTED)             return "MEDUSA_WEBSOCKETSERVER_EVENT_STARTED";
        if (events == MEDUSA_WEBSOCKETSERVER_EVENT_STOPPED)             return "MEDUSA_WEBSOCKETSERVER_EVENT_STOPPED";
        if (events == MEDUSA_WEBSOCKETSERVER_EVENT_BINDING)             return "MEDUSA_WEBSOCKETSERVER_EVENT_BINDING";
        if (events == MEDUSA_WEBSOCKETSERVER_EVENT_BOUND)               return "MEDUSA_WEBSOCKETSERVER_EVENT_BOUND";
        if (events == MEDUSA_WEBSOCKETSERVER_EVENT_LISTENING)           return "MEDUSA_WEBSOCKETSERVER_EVENT_LISTENING";
        if (events == MEDUSA_WEBSOCKETSERVER_EVENT_CONNECTION)          return "MEDUSA_WEBSOCKETSERVER_EVENT_CONNECTION";
        if (events == MEDUSA_WEBSOCKETSERVER_EVENT_ERROR)               return "MEDUSA_WEBSOCKETSERVER_EVENT_ERROR";
        if (events == MEDUSA_WEBSOCKETSERVER_EVENT_DESTROY)             return "MEDUSA_WEBSOCKETSERVER_EVENT_DESTROY";
        return "MEDUSA_WEBSOCKETSERVER_EVENT_UNKNOWN";
}

__attribute__ ((visibility ("default"))) const char * medusa_websocketserver_state_string (unsigned int state)
{
        if (state == MEDUSA_WEBSOCKETSERVER_STATE_UNKNOWN)              return "MEDUSA_WEBSOCKETSERVER_STATE_UNKNOWN";
        if (state == MEDUSA_WEBSOCKETSERVER_STATE_STARTED)              return "MEDUSA_WEBSOCKETSERVER_STATE_STARTED";
        if (state == MEDUSA_WEBSOCKETSERVER_STATE_STOPPED)              return "MEDUSA_WEBSOCKETSERVER_STATE_STOPPED";
        if (state == MEDUSA_WEBSOCKETSERVER_STATE_BINDING)              return "MEDUSA_WEBSOCKETSERVER_STATE_BINDING";
        if (state == MEDUSA_WEBSOCKETSERVER_STATE_BOUND)                return "MEDUSA_WEBSOCKETSERVER_STATE_BOUND";
        if (state == MEDUSA_WEBSOCKETSERVER_STATE_LISTENING)            return "MEDUSA_WEBSOCKETSERVER_STATE_LISTENING";
        if (state == MEDUSA_WEBSOCKETSERVER_STATE_ERROR)                return "MEDUSA_WEBSOCKETSERVER_STATE_ERROR";
        return "MEDUSA_WEBSOCKETSERVER_STATE_UNKNOWN";
}

enum {
        MEDUSA_WEBSOCKETSERVER_CLIENT_FLAG_NONE         = (1 <<  0),
        MEDUSA_WEBSOCKETSERVER_CLIENT_FLAG_ENABLED      = (1 <<  1)
#define MEDUSA_WEBSOCKETSERVER_CLIENT_FLAG_NONE         MEDUSA_WEBSOCKETSERVER_CLIENT_FLAG_NONE
#define MEDUSA_WEBSOCKETSERVER_CLIENT_FLAG_ENABLED      MEDUSA_WEBSOCKETSERVER_CLIENT_FLAG_ENABLED
};

static inline void websocketserver_client_set_flag (struct medusa_websocketserver_client *websocketserver_client, unsigned int flag)
{
        websocketserver_client->flags = flag;
}

static inline void websocketserver_client_add_flag (struct medusa_websocketserver_client *websocketserver_client, unsigned int flag)
{
        websocketserver_client->flags |= flag;
}

static inline void websocketserver_client_del_flag (struct medusa_websocketserver_client *websocketserver_client, unsigned int flag)
{
        websocketserver_client->flags &= ~flag;
}

static inline int websocketserver_client_has_flag (const struct medusa_websocketserver_client *websocketserver_client, unsigned int flag)
{
        return !!(websocketserver_client->flags & flag);
}

static inline int websocketserver_client_set_state (struct medusa_websocketserver_client *websocketserver_client, unsigned int state)
{
        websocketserver_client->error = 0;
        if (state == MEDUSA_WEBSOCKETSERVER_CLIENT_STATE_DISCONNECTED) {
                if (!MEDUSA_IS_ERR_OR_NULL(websocketserver_client->tcpsocket)) {
                        medusa_tcpsocket_destroy_unlocked(websocketserver_client->tcpsocket);
                        websocketserver_client->tcpsocket = NULL;
                }
        }
        websocketserver_client->state = state;
        return 0;
}

static int websocketserver_client_httpparser_on_message_begin (http_parser *http_parser)
{
        struct medusa_websocketserver_client *websocketserver_client = http_parser->data;
        (void) websocketserver_client;
        fprintf(stderr, "websocketserver-client.httpparser @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        return 0;
}

static int websocketserver_client_httpparser_on_url (http_parser *http_parser, const char *at, size_t length)
{
        struct medusa_websocketserver_client *websocketserver_client = http_parser->data;
        (void) websocketserver_client;
        (void) at;
        (void) length;
        fprintf(stderr, "websocketserver-client.httpparser @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        return 0;
}

static int websocketserver_client_httpparser_on_status (http_parser *http_parser, const char *at, size_t length)
{
        struct medusa_websocketserver_client *websocketserver_client = http_parser->data;
        (void) websocketserver_client;
        (void) at;
        (void) length;
        fprintf(stderr, "websocketserver-client.httpparser @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        return 0;
}

static int websocketserver_client_httpparser_on_header_field (http_parser *http_parser, const char *at, size_t length)
{
        struct medusa_websocketserver_client *websocketserver_client = http_parser->data;
        if (websocketserver_client->http_parser_header_field != NULL) {
                free(websocketserver_client->http_parser_header_field);
                websocketserver_client->http_parser_header_field = NULL;
        }
        websocketserver_client->http_parser_header_field = strndup(at, length);
        if (websocketserver_client->http_parser_header_field == NULL) {
                return -ENOMEM;
        }
        return 0;
}

static int websocketserver_client_httpparser_on_header_value (http_parser *http_parser, const char *at, size_t length)
{
        int rc;
        struct medusa_websocketserver_client_event_request_header websocketserver_client_event_request_header;

        struct medusa_websocketserver_client *websocketserver_client = http_parser->data;

        if (websocketserver_client->http_parser_header_value != NULL) {
                free(websocketserver_client->http_parser_header_value);
                websocketserver_client->http_parser_header_value = NULL;
        }
        websocketserver_client->http_parser_header_value = strndup(at, length);
        if (websocketserver_client->http_parser_header_value == NULL) {
                return -ENOMEM;
        }

        fprintf(stderr, "websocketserver-client.httpparser header %s: %s @ %s %s:%d\n", websocketserver_client->http_parser_header_field, websocketserver_client->http_parser_header_value, __FUNCTION__, __FILE__, __LINE__);
        
        websocketserver_client_event_request_header.field = websocketserver_client->http_parser_header_field;
        websocketserver_client_event_request_header.value = websocketserver_client->http_parser_header_value;
        rc = medusa_websocketserver_client_onevent_unlocked(websocketserver_client, MEDUSA_WEBSOCKETSERVER_CLIENT_EVENT_REQUEST_HEADER, &websocketserver_client_event_request_header);
        if (rc < 0) {
                return rc;
        }

        if (strcasecmp(websocketserver_client->http_parser_header_field, "Sec-WebSocket-Key") == 0) {
                websocketserver_client->sec_websocket_key = strdup(websocketserver_client->http_parser_header_value);
                if (websocketserver_client->sec_websocket_key == NULL) {
                        return -ENOMEM;
                }
        }

        if (websocketserver_client->http_parser_header_field != NULL) {
                free(websocketserver_client->http_parser_header_field);
                websocketserver_client->http_parser_header_field = NULL;
        }
        if (websocketserver_client->http_parser_header_value != NULL) {
                free(websocketserver_client->http_parser_header_value);
                websocketserver_client->http_parser_header_value = NULL;
        }
        return 0;
}

static int websocketserver_client_httpparser_on_headers_complete (http_parser *http_parser)
{
        struct medusa_websocketserver_client *websocketserver_client = http_parser->data;
        (void) websocketserver_client;
        fprintf(stderr, "websocketserver-client.httpparser @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        return 0;
}

static int websocketserver_client_httpparser_on_body (http_parser *http_parser, const char *at, size_t length)
{
        struct medusa_websocketserver_client *websocketserver_client = http_parser->data;
        (void) websocketserver_client;
        (void) at;
        (void) length;
        fprintf(stderr, "websocketserver-client.httpparser @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        return 0;
}

static int websocketserver_client_httpparser_on_message_complete (http_parser *http_parser)
{
        struct medusa_websocketserver_client *websocketserver_client = http_parser->data;
        (void) websocketserver_client;
        fprintf(stderr, "websocketserver-client.httpparser @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        return 0;
}

static int websocketserver_client_httpparser_on_chunk_header (http_parser *http_parser)
{
        struct medusa_websocketserver_client *websocketserver_client = http_parser->data;
        (void) websocketserver_client;
        fprintf(stderr, "websocketserver-client.httpparser @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        return 0;
}

static int websocketserver_client_httpparser_on_chunk_complete (http_parser *http_parser)
{
        struct medusa_websocketserver_client *websocketserver_client = http_parser->data;
        (void) websocketserver_client;
        fprintf(stderr, "websocketserver-client.httpparser @ %s %s:%d\n", __FUNCTION__, __FILE__, __LINE__);
        return 0;
}

static int websocketserver_client_tcpsocket_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, void *param)
{
        int rc;
        int error;
        struct medusa_monitor *monitor;
        struct medusa_websocketserver_client *websocketserver_client = (struct medusa_websocketserver_client *) context;

        (void) param;

        fprintf(stderr, "websocketserver-client.tcpsocket.events: 0x%08x, %s\n", events, medusa_tcpsocket_event_string(events));
        
        if (events & MEDUSA_TCPSOCKET_EVENT_DESTROY) {
                return 0;
        }

        monitor = medusa_tcpsocket_get_monitor(tcpsocket);
        medusa_monitor_lock(monitor);

        if (events & MEDUSA_TCPSOCKET_EVENT_CONNECTED) {
                websocketserver_client_set_state(websocketserver_client, MEDUSA_WEBSOCKETSERVER_CLIENT_STATE_ACCEPTED);
                rc = medusa_websocketserver_client_onevent_unlocked(websocketserver_client, MEDUSA_WEBSOCKETSERVER_CLIENT_EVENT_ACCEPTED, NULL);
                if (rc < 0) {
                        error = rc;
                        goto bail;
                }
                http_parser_settings_init(&websocketserver_client->http_parser_settings);
                websocketserver_client->http_parser_settings.on_message_begin      = websocketserver_client_httpparser_on_message_begin;
                websocketserver_client->http_parser_settings.on_url                = websocketserver_client_httpparser_on_url;
                websocketserver_client->http_parser_settings.on_status             = websocketserver_client_httpparser_on_status;
                websocketserver_client->http_parser_settings.on_header_field       = websocketserver_client_httpparser_on_header_field;
                websocketserver_client->http_parser_settings.on_header_value       = websocketserver_client_httpparser_on_header_value;
                websocketserver_client->http_parser_settings.on_headers_complete   = websocketserver_client_httpparser_on_headers_complete;
                websocketserver_client->http_parser_settings.on_body               = websocketserver_client_httpparser_on_body;
                websocketserver_client->http_parser_settings.on_message_complete   = websocketserver_client_httpparser_on_message_complete;
                websocketserver_client->http_parser_settings.on_chunk_header       = websocketserver_client_httpparser_on_chunk_header;
                websocketserver_client->http_parser_settings.on_chunk_complete     = websocketserver_client_httpparser_on_chunk_complete;
                http_parser_init(&websocketserver_client->http_parser, HTTP_REQUEST);
                websocketserver_client->http_parser.data = websocketserver_client;
        } else if (events & MEDUSA_TCPSOCKET_EVENT_BUFFERED_READ) {
                if (websocketserver_client->state == MEDUSA_WEBSOCKETSERVER_CLIENT_STATE_ACCEPTED) {
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
                                nparsed = http_parser_execute(&websocketserver_client->http_parser, &websocketserver_client->http_parser_settings, iovecs[iiovecs].iov_base, iovecs[iiovecs].iov_len);
                                if (websocketserver_client->http_parser.http_errno != 0) {
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
                } else {
                        error = -EIO;
                        goto bail;
                }
        } else {
                error = -EIO;
                goto bail;
        }

        medusa_monitor_unlock(monitor);
        return 0;
bail:   websocketserver_client_set_state(websocketserver_client, MEDUSA_WEBSOCKETSERVER_CLIENT_STATE_ERROR);
        websocketserver_client->error = -error;
        medusa_websocketserver_client_onevent_unlocked(websocketserver_client, MEDUSA_WEBSOCKETSERVER_CLIENT_EVENT_ERROR, NULL);
        medusa_monitor_unlock(monitor);
        return error;
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_accept_options_default (struct medusa_websocketserver_accept_options *options)
{
        if (options == NULL) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_websocketserver_accept_options));
        return 0;
}

__attribute__ ((visibility ("default"))) struct medusa_websocketserver_client * medusa_websocketserver_accept_unlocked (struct medusa_websocketserver *websocketserver, int (*onevent) (struct medusa_websocketserver_client *websocketserver_client, unsigned int events, void *context, void *param), void *context)
{
        int rc;
        struct medusa_websocketserver_accept_options options;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        rc = medusa_websocketserver_accept_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.enabled  = medusa_websocketserver_get_enabled_unlocked(websocketserver);
        options.onevent  = onevent;
        options.context  = context;
        return medusa_websocketserver_accept_with_options_unlocked(websocketserver, &options);
}

__attribute__ ((visibility ("default"))) struct medusa_websocketserver_client * medusa_websocketserver_accept (struct medusa_websocketserver *websocketserver, int (*onevent) (struct medusa_websocketserver_client *websocketserver_client, unsigned int events, void *context, void *param), void *context)
{
        struct medusa_websocketserver_client *rc;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(websocketserver->subject.monitor);
        rc = medusa_websocketserver_accept_unlocked(websocketserver, onevent, context);
        medusa_monitor_unlock(websocketserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_websocketserver_client * medusa_websocketserver_accept_with_options_unlocked (struct medusa_websocketserver *websocketserver, struct medusa_websocketserver_accept_options *options)
{
        int rc;
        int error;

        struct medusa_tcpsocket *accepted;
        struct medusa_tcpsocket_accept_options medusa_tcpsocket_accept_options;

        struct medusa_websocketserver_client *websocketserver_client;

        websocketserver_client = NULL;

        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }

#if defined(MEDUSA_WEBSOCKETSERVER_USE_POOL) && (MEDUSA_WEBSOCKETSERVER_USE_POOL == 1)
        websocketserver_client = medusa_pool_malloc(g_pool_websocketserver_client);
#else
        websocketserver_client = malloc(sizeof(struct medusa_websocketserver_client));
#endif
        if (websocketserver_client == NULL) {
                error = -ENOMEM;
                goto bail;
        }
        memset(websocketserver_client, 0, sizeof(struct medusa_websocketserver_client));
        medusa_subject_set_type(&websocketserver_client->subject, MEDUSA_SUBJECT_TYPE_WEBSOCKETSERVER_CLIENT);
        websocketserver_client->subject.monitor = NULL;
        websocketserver_client_set_state(websocketserver_client, MEDUSA_WEBSOCKETSERVER_CLIENT_STATE_DISCONNECTED);
        websocketserver_client_set_flag(websocketserver_client, MEDUSA_WEBSOCKETSERVER_CLIENT_FLAG_ENABLED);
        websocketserver_client->onevent = options->onevent;
        websocketserver_client->context = options->context;
        rc = medusa_monitor_add_unlocked(websocketserver->subject.monitor, &websocketserver_client->subject);
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
        medusa_tcpsocket_accept_options.onevent     = websocketserver_client_tcpsocket_onevent;
        medusa_tcpsocket_accept_options.context     = websocketserver_client;
        accepted = medusa_tcpsocket_accept_with_options_unlocked(websocketserver->tcpsocket, &medusa_tcpsocket_accept_options);
        if (MEDUSA_IS_ERR_OR_NULL(accepted)) {
                error = MEDUSA_PTR_ERR(accepted);
                goto bail;
        }

        websocketserver_client->tcpsocket       = accepted;
        websocketserver_client->websocketserver = websocketserver;
        TAILQ_INSERT_TAIL(&websocketserver->clients, websocketserver_client, list);

        return websocketserver_client;
bail:   if (MEDUSA_IS_ERR_OR_NULL(websocketserver_client)) {
                return MEDUSA_ERR_PTR(error);
        }
        websocketserver_client_set_state(websocketserver_client, MEDUSA_WEBSOCKETSERVER_CLIENT_STATE_ERROR);
        websocketserver_client->error = -error;
        medusa_websocketserver_client_onevent_unlocked(websocketserver_client, MEDUSA_WEBSOCKETSERVER_CLIENT_EVENT_ERROR, NULL);
        return websocketserver_client;

}

__attribute__ ((visibility ("default"))) struct medusa_websocketserver_client * medusa_websocketserver_accept_with_options (struct medusa_websocketserver *websocketserver, struct medusa_websocketserver_accept_options *options)
{
        struct medusa_websocketserver_client *rc;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(websocketserver->subject.monitor);
        rc = medusa_websocketserver_accept_with_options_unlocked(websocketserver, options);
        medusa_monitor_unlock(websocketserver->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void medusa_websocketserver_client_destroy_unlocked (struct medusa_websocketserver_client *websocketserver_client)
{
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver_client)) {
                return;
        }
        if (websocketserver_client->subject.monitor != NULL) {
                medusa_monitor_del_unlocked(&websocketserver_client->subject);
        } else {
                medusa_websocketserver_client_onevent_unlocked(websocketserver_client, MEDUSA_WEBSOCKETSERVER_CLIENT_EVENT_DESTROY, NULL);
        }
}

__attribute__ ((visibility ("default"))) void medusa_websocketserver_client_destroy (struct medusa_websocketserver_client *websocketserver_client)
{
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver_client)) {
                return;
        }
        medusa_monitor_lock(websocketserver_client->subject.monitor);
        medusa_websocketserver_client_destroy_unlocked(websocketserver_client);
        medusa_monitor_unlock(websocketserver_client->subject.monitor);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_websocketserver_client_get_state_unlocked (const struct medusa_websocketserver_client *websocketserver_client)
{
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver_client)) {
                return MEDUSA_WEBSOCKETSERVER_STATE_UNKNOWN;
        }
        return websocketserver_client->state;
}

__attribute__ ((visibility ("default"))) unsigned int medusa_websocketserver_client_get_state (const struct medusa_websocketserver_client *websocketserver_client)
{
        unsigned int rc;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver_client)) {
                return MEDUSA_WEBSOCKETSERVER_STATE_UNKNOWN;
        }
        medusa_monitor_lock(websocketserver_client->subject.monitor);
        rc = medusa_websocketserver_client_get_state_unlocked(websocketserver_client);
        medusa_monitor_unlock(websocketserver_client->subject.monitor);
        return rc;
}
__attribute__ ((visibility ("default"))) int medusa_websocketserver_client_set_context_unlocked (struct medusa_websocketserver_client *websocketserver_client, void *context)
{
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver_client)) {
                return -EINVAL;
        }
        websocketserver_client->context = context;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_client_set_context (struct medusa_websocketserver_client *websocketserver_client, void *context)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver_client)) {
                return -EINVAL;
        }
        medusa_monitor_lock(websocketserver_client->subject.monitor);
        rc = medusa_websocketserver_client_set_context_unlocked(websocketserver_client, context);
        medusa_monitor_unlock(websocketserver_client->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void * medusa_websocketserver_client_get_context_unlocked (struct medusa_websocketserver_client *websocketserver_client)
{
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver_client)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return websocketserver_client->context;
}

__attribute__ ((visibility ("default"))) void * medusa_websocketserver_client_get_context (struct medusa_websocketserver_client *websocketserver_client)
{
        void *rc;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver_client)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(websocketserver_client->subject.monitor);
        rc = medusa_websocketserver_client_get_context_unlocked(websocketserver_client);
        medusa_monitor_unlock(websocketserver_client->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_client_set_userdata_unlocked (struct medusa_websocketserver_client *websocketserver_client, void *userdata)
{
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver_client)) {
                return -EINVAL;
        }
        websocketserver_client->userdata = userdata;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_client_set_userdata (struct medusa_websocketserver_client *websocketserver_client, void *userdata)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver_client)) {
                return -EINVAL;
        }
        medusa_monitor_lock(websocketserver_client->subject.monitor);
        rc = medusa_websocketserver_client_set_userdata_unlocked(websocketserver_client, userdata);
        medusa_monitor_unlock(websocketserver_client->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void * medusa_websocketserver_client_get_userdata_unlocked (struct medusa_websocketserver_client *websocketserver_client)
{
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver_client)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return websocketserver_client->userdata;
}

__attribute__ ((visibility ("default"))) void * medusa_websocketserver_client_get_userdata (struct medusa_websocketserver_client *websocketserver_client)
{
        void *rc;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver_client)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(websocketserver_client->subject.monitor);
        rc = medusa_websocketserver_client_get_userdata_unlocked(websocketserver_client);
        medusa_monitor_unlock(websocketserver_client->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_client_set_userdata_ptr_unlocked (struct medusa_websocketserver_client *websocketserver_client, void *userdata)
{
        return medusa_websocketserver_client_set_userdata_unlocked(websocketserver_client, userdata);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_client_set_userdata_ptr (struct medusa_websocketserver_client *websocketserver_client, void *userdata)
{
        return medusa_websocketserver_client_set_userdata(websocketserver_client, userdata);
}

__attribute__ ((visibility ("default"))) void * medusa_websocketserver_client_get_userdata_ptr_unlocked (struct medusa_websocketserver_client *websocketserver_client)
{
        return medusa_websocketserver_client_get_userdata_unlocked(websocketserver_client);
}

__attribute__ ((visibility ("default"))) void * medusa_websocketserver_client_get_userdata_ptr (struct medusa_websocketserver_client *websocketserver_client)
{
        return medusa_websocketserver_client_get_userdata(websocketserver_client);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_client_set_userdata_int_unlocked (struct medusa_websocketserver_client *websocketserver_client, int userdata)
{
        return medusa_websocketserver_client_set_userdata_unlocked(websocketserver_client, (void *) (intptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_client_set_userdata_int (struct medusa_websocketserver_client *websocketserver_client, int userdata)
{
        return medusa_websocketserver_client_set_userdata(websocketserver_client, (void *) (intptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_client_get_userdata_int_unlocked (struct medusa_websocketserver_client *websocketserver_client)
{
        return (int) (intptr_t) medusa_websocketserver_client_get_userdata_unlocked(websocketserver_client);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_client_get_userdata_int (struct medusa_websocketserver_client *websocketserver_client)
{
        return (int) (intptr_t) medusa_websocketserver_client_get_userdata(websocketserver_client);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_client_set_userdata_uint_unlocked (struct medusa_websocketserver_client *websocketserver_client, unsigned int userdata)
{
        return medusa_websocketserver_client_set_userdata_unlocked(websocketserver_client, (void *) (uintptr_t) userdata);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_client_set_userdata_uint (struct medusa_websocketserver_client *websocketserver_client, unsigned int userdata)
{
        return medusa_websocketserver_client_set_userdata(websocketserver_client, (void *) (uintptr_t) userdata);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_websocketserver_client_get_userdata_uint_unlocked (struct medusa_websocketserver_client *websocketserver_client)
{
        return (unsigned int) (intptr_t) medusa_websocketserver_client_get_userdata_unlocked(websocketserver_client);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_websocketserver_client_get_userdata_uint (struct medusa_websocketserver_client *websocketserver_client)
{
        return (unsigned int) (uintptr_t) medusa_websocketserver_client_get_userdata(websocketserver_client);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_client_onevent_unlocked (struct medusa_websocketserver_client *websocketserver_client, unsigned int events, void *param)
{
        int ret;
        struct medusa_monitor *monitor;
        ret = 0;
        monitor = websocketserver_client->subject.monitor;
        if (websocketserver_client->onevent != NULL) {
                if ((medusa_subject_is_active(&websocketserver_client->subject)) ||
                    (events & MEDUSA_WEBSOCKETSERVER_CLIENT_EVENT_DESTROY)) {
                        medusa_monitor_unlock(monitor);
                        ret = websocketserver_client->onevent(websocketserver_client, events, websocketserver_client->context, param);
                        medusa_monitor_lock(monitor);
                }
        }
        if (events & MEDUSA_WEBSOCKETSERVER_CLIENT_EVENT_DESTROY) {
                if (websocketserver_client->sec_websocket_key != NULL) {
                        free(websocketserver_client->sec_websocket_key);
                        websocketserver_client->sec_websocket_key = NULL;
                }
                if (!MEDUSA_IS_ERR_OR_NULL(websocketserver_client->tcpsocket)) {
                        medusa_tcpsocket_destroy_unlocked(websocketserver_client->tcpsocket);
                        websocketserver_client->tcpsocket = NULL;       
                }
                if (websocketserver_client->websocketserver != NULL) {
                        TAILQ_REMOVE(&websocketserver_client->websocketserver->clients, websocketserver_client, list);
                        websocketserver_client->websocketserver = NULL;
                }
#if defined(MEDUSA_WEBSOCKETSERVER_USE_POOL) && (MEDUSA_WEBSOCKETSERVER_USE_POOL == 1)
                medusa_pool_free(websocketserver_client);
#else
                free(websocketserver_client);
#endif
        }
        return ret;
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_client_onevent (struct medusa_websocketserver_client *websocketserver_client, unsigned int events, void *param)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver_client)) {
                return -EINVAL;
        }
        medusa_monitor_lock(websocketserver_client->subject.monitor);
        rc = medusa_websocketserver_client_onevent_unlocked(websocketserver_client, events, param);
        medusa_monitor_unlock(websocketserver_client->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_websocketserver_client_get_monitor_unlocked (struct medusa_websocketserver_client *websocketserver_client)
{
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver_client)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return websocketserver_client->subject.monitor;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_websocketserver_client_get_monitor (struct medusa_websocketserver_client *websocketserver_client)
{
        struct medusa_monitor *rc;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver_client)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(websocketserver_client->subject.monitor);
        rc = medusa_websocketserver_client_get_monitor_unlocked(websocketserver_client);
        medusa_monitor_unlock(websocketserver_client->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) const char * medusa_websocketserver_client_event_string (unsigned int events)
{
        if (events == MEDUSA_WEBSOCKETSERVER_CLIENT_EVENT_ERROR)                return "MEDUSA_WEBSOCKETSERVER_CLIENT_EVENT_ERROR";
        if (events == MEDUSA_WEBSOCKETSERVER_CLIENT_EVENT_ACCEPTED)             return "MEDUSA_WEBSOCKETSERVER_CLIENT_EVENT_ACCEPTED";
        if (events == MEDUSA_WEBSOCKETSERVER_CLIENT_EVENT_REQUEST_HEADER)       return "MEDUSA_WEBSOCKETSERVER_CLIENT_EVENT_REQUEST_HEADER";
        if (events == MEDUSA_WEBSOCKETSERVER_CLIENT_EVENT_DESTROY)              return "MEDUSA_WEBSOCKETSERVER_CLIENT_EVENT_DESTROY";
        return "MEDUSA_WEBSOCKETSERVER_CLIENT_EVENT_UNKNOWN";
}

__attribute__ ((visibility ("default"))) const char * medusa_websocketserver_client_state_string (unsigned int state)
{
        if (state == MEDUSA_WEBSOCKETSERVER_CLIENT_STATE_UNKNOWN)       return "MEDUSA_WEBSOCKETSERVER_CLIENT_STATE_UNKNOWN";
        if (state == MEDUSA_WEBSOCKETSERVER_CLIENT_STATE_ACCEPTED)      return "MEDUSA_WEBSOCKETSERVER_CLIENT_STATE_ACCEPTED";
        if (state == MEDUSA_WEBSOCKETSERVER_CLIENT_STATE_DISCONNECTED)  return "MEDUSA_WEBSOCKETSERVER_CLIENT_STATE_DISCONNECTED";
        if (state == MEDUSA_WEBSOCKETSERVER_CLIENT_STATE_ERROR)         return "MEDUSA_WEBSOCKETSERVER_CLIENT_STATE_ERROR";
        return "MEDUSA_WEBSOCKETSERVER_CLIENT_STATE_UNKNOWN";
}

__attribute__ ((constructor)) static void websocketserver_constructor (void)
{
#if defined(MEDUSA_WEBSOCKETSERVER_USE_POOL) && (MEDUSA_WEBSOCKETSERVER_USE_POOL == 1)
        g_pool_websocketserver = medusa_pool_create("medusa-websocketserver", sizeof(struct medusa_websocketserver), 0, 0, MEDUSA_POOL_FLAG_DEFAULT | MEDUSA_POOL_FLAG_THREAD_SAFE, NULL, NULL, NULL);
        g_pool_websocketserver_client = medusa_pool_create("medusa-websocketserver-client", sizeof(struct medusa_websocketserver_client), 0, 0, MEDUSA_POOL_FLAG_DEFAULT | MEDUSA_POOL_FLAG_THREAD_SAFE, NULL, NULL, NULL);
#endif
}

__attribute__ ((destructor)) static void websocketserver_destructor (void)
{
#if defined(MEDUSA_WEBSOCKETSERVER_USE_POOL) && (MEDUSA_WEBSOCKETSERVER_USE_POOL == 1)
        if (g_pool_websocketserver_client != NULL) {
                medusa_pool_destroy(g_pool_websocketserver_client);
        }
        if (g_pool_websocketserver != NULL) {
                medusa_pool_destroy(g_pool_websocketserver);
        }
#endif
}
