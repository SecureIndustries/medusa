
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "error.h"
#include "pool.h"
#include "queue.h"
#include "subject-struct.h"
#include "tcpsocket.h"
#include "tcpsocket-private.h"
#include "websocketserver.h"
#include "websocketserver-private.h"
#include "websocketserver-struct.h"
#include "monitor-private.h"

#define MEDUSA_WEBSOCKETSERVER_USE_POOL         1

#if defined(MEDUSA_WEBSOCKETSERVER_USE_POOL) && (MEDUSA_WEBSOCKETSERVER_USE_POOL == 1)
static struct medusa_pool *g_pool;
#endif

static unsigned int websocketserver_protocol_to_tcpsocket_protocol (unsigned int protocol)
{
        switch (protocol) {
                case MEDUSA_WEBSOCKETSERVER_PROTOCOL_IPV4:      return MEDUSA_TCPSOCKET_PROTOCOL_IPV4;
                case MEDUSA_WEBSOCKETSERVER_PROTOCOL_IPV6:      return MEDUSA_TCPSOCKET_PROTOCOL_IPV6;
        }
        return MEDUSA_TCPSOCKET_PROTOCOL_ANY;
}

static inline int websocketserver_set_state (struct medusa_websocketserver *websocketserver, unsigned int state)
{
        if (state == MEDUSA_WEBSOCKETSERVER_STATE_ERROR ||
            state == MEDUSA_WEBSOCKETSERVER_STATE_STOPPED) {
                if (!MEDUSA_IS_ERR_OR_NULL(websocketserver->tcpsocket)) {
                        medusa_tcpsocket_destroy_unlocked(websocketserver->tcpsocket);
                        websocketserver->tcpsocket = NULL;
                }
        }
        websocketserver->state = state;
        return 0;
}

static int accepted_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, void *param)
{
        struct medusa_monitor *monitor;
        struct medusa_websocketserver *websocketserver = (struct medusa_websocketserver *) context;

        (void) websocketserver;
        (void) param;

        fprintf(stderr, "websocketserver.accepted.events: 0x%08x, %s\n", events, medusa_tcpsocket_event_string(events));

        monitor = medusa_tcpsocket_get_monitor(tcpsocket);
        medusa_monitor_lock(monitor);

        if (events & MEDUSA_TCPSOCKET_EVENT_IN) {
                
        }

        medusa_monitor_unlock(monitor);
        return 0;
}

static int tcpsocket_onevent (struct medusa_tcpsocket *tcpsocket, unsigned int events, void *context, void *param)
{
        int rc;
        int error;
        struct medusa_monitor *monitor;
        struct medusa_websocketserver *websocketserver = (struct medusa_websocketserver *) context;

        (void) param;

        fprintf(stderr, "websocketserver.tcpsocket.events: 0x%08x, %s\n", events, medusa_tcpsocket_event_string(events));

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
                struct medusa_tcpsocket *accepted;
                struct medusa_tcpsocket_accept_options medusa_tcpsocket_accept_options;
                struct medusa_websocketserver_client *medusa_websocketserver_client;
                
                medusa_websocketserver_client = malloc(sizeof(struct medusa_websocketserver_client));
                if (medusa_websocketserver_client == NULL) {
                        error = -ENOMEM;
                        goto bail;
                }
                memset(medusa_websocketserver_client, 0, sizeof(struct medusa_websocketserver_client));
                medusa_websocketserver_client->websocketserver = websocketserver;
                TAILQ_INSERT_TAIL(&websocketserver->clients, medusa_websocketserver_client, list);

                rc = medusa_tcpsocket_accept_options_default(&medusa_tcpsocket_accept_options);
                if (rc != 0) {
                        error = rc;
                        goto bail;
                }
                medusa_tcpsocket_accept_options.buffered    = websocketserver->buffered;
                medusa_tcpsocket_accept_options.nodelay     = 1;
                medusa_tcpsocket_accept_options.nonblocking = 1;
                medusa_tcpsocket_accept_options.enabled     = 1;
                medusa_tcpsocket_accept_options.onevent     = accepted_onevent;
                medusa_tcpsocket_accept_options.context     = medusa_websocketserver_client;
                accepted = medusa_tcpsocket_accept_with_options_unlocked(tcpsocket, &medusa_tcpsocket_accept_options);
                if (MEDUSA_IS_ERR_OR_NULL(accepted)) {
                        error = MEDUSA_PTR_ERR(accepted);
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
        struct medusa_websocketserver *websocketserver;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
#if defined(MEDUSA_WEBSOCKETSERVER_USE_POOL) && (MEDUSA_WEBSOCKETSERVER_USE_POOL == 1)
        websocketserver = medusa_pool_malloc(g_pool);
#else
        websocketserver = malloc(sizeof(struct medusa_websocketserver));
#endif
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(websocketserver, 0, sizeof(struct medusa_websocketserver));
        rc = websocketserver_init_with_options_unlocked(websocketserver, options);
        if (rc < 0) {
                medusa_websocketserver_destroy_unlocked(websocketserver);
                return MEDUSA_ERR_PTR(rc);
        }
        if (options->address != NULL) {
                websocketserver->address = strdup(options->address);
                if (websocketserver->address == NULL) {
                        medusa_websocketserver_destroy_unlocked(websocketserver);
                        return MEDUSA_ERR_PTR(-ENOMEM);
                }
        }
        if (options->servername != NULL) {
                websocketserver->servername = strdup(options->servername);
                if (websocketserver->servername == NULL) {
                        medusa_websocketserver_destroy_unlocked(websocketserver);
                        return MEDUSA_ERR_PTR(-ENOMEM);
                }
        }
        websocketserver->port     = options->port;
        websocketserver->protocol = options->protocol;
        websocketserver->buffered = !!options->buffered;
        if (options->enabled) {
                rc = medusa_websocketserver_set_enabled_unlocked(websocketserver, options->enabled);
                if (rc < 0) {
                        medusa_websocketserver_destroy_unlocked(websocketserver);
                        return MEDUSA_ERR_PTR(rc);
                }
        }
        return websocketserver;
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
        int error;
        struct medusa_tcpsocket_bind_options medusa_tcpsocket_bind_options;
        if (MEDUSA_IS_ERR_OR_NULL(websocketserver)) {
                return -EINVAL;
        }
        if (enabled != 0) {
                if (websocketserver->state != MEDUSA_WEBSOCKETSERVER_STATE_STOPPED) {
                        error = EALREADY;
                        goto bail;
                }
                websocketserver_set_state(websocketserver, MEDUSA_WEBSOCKETSERVER_STATE_STARTED);
                medusa_websocketserver_onevent_unlocked(websocketserver, MEDUSA_WEBSOCKETSERVER_EVENT_STARTED, NULL);
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
                medusa_tcpsocket_bind_options.buffered    = websocketserver->buffered;
                medusa_tcpsocket_bind_options.nodelay     = 1;
                medusa_tcpsocket_bind_options.nonblocking = 1;
                medusa_tcpsocket_bind_options.reuseaddr   = 1;
                medusa_tcpsocket_bind_options.reuseport   = 0;
                medusa_tcpsocket_bind_options.enabled     = 1;
                medusa_tcpsocket_bind_options.monitor     = websocketserver->subject.monitor;
                medusa_tcpsocket_bind_options.context     = websocketserver;
                medusa_tcpsocket_bind_options.onevent     = tcpsocket_onevent;
                websocketserver->tcpsocket = medusa_tcpsocket_bind_with_options_unlocked(&medusa_tcpsocket_bind_options);
                if (MEDUSA_IS_ERR_OR_NULL(websocketserver->tcpsocket)) {
                        error =  -MEDUSA_PTR_ERR(websocketserver->tcpsocket);
                        goto bail;
                }
        } else {
                if (websocketserver->state == MEDUSA_WEBSOCKETSERVER_STATE_STOPPED) {
                        error = EALREADY;
                        goto bail;
                }
                if (MEDUSA_IS_ERR_OR_NULL(websocketserver->tcpsocket)) {
                        error = EIO;
                        goto bail;
                }
                medusa_tcpsocket_destroy_unlocked(websocketserver->tcpsocket);
                websocketserver->tcpsocket = NULL;
                websocketserver_set_state(websocketserver, MEDUSA_WEBSOCKETSERVER_STATE_STOPPED);
                medusa_websocketserver_onevent_unlocked(websocketserver, MEDUSA_WEBSOCKETSERVER_EVENT_STOPPED, NULL);
        }
        return 0;
bail:   medusa_websocketserver_onevent_unlocked(websocketserver, MEDUSA_WEBSOCKETSERVER_EVENT_ERROR, NULL);
        websocketserver_set_state(websocketserver, MEDUSA_WEBSOCKETSERVER_STATE_ERROR);
        return -error;
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

__attribute__ ((visibility ("default"))) int medusa_websocketserver_start_unlocked (struct medusa_websocketserver *websocketserver)
{
        return medusa_websocketserver_set_enabled_unlocked(websocketserver, 1);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_start (struct medusa_websocketserver *websocketserver)
{
        return medusa_websocketserver_set_enabled(websocketserver, 1);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_stop_unlocked (struct medusa_websocketserver *websocketserver)
{
        return medusa_websocketserver_set_enabled_unlocked(websocketserver, 0);
}

__attribute__ ((visibility ("default"))) int medusa_websocketserver_stop (struct medusa_websocketserver *websocketserver)
{
        return medusa_websocketserver_set_enabled(websocketserver, 0);
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
                struct medusa_websocketserver_client *client;
                struct medusa_websocketserver_client *nclient;
                TAILQ_FOREACH_SAFE(client, &websocketserver->clients, list, nclient) {
                        TAILQ_REMOVE(&websocketserver->clients, client, list);
                        if (!MEDUSA_IS_ERR_OR_NULL(client->tcpsocket)) {
                                medusa_tcpsocket_destroy_unlocked(client->tcpsocket);
                        }
                        free(client);
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
        if (events == MEDUSA_WEBSOCKETSERVER_EVENT_ERROR)               return "MEDUSA_WEBSOCKETSERVER_EVENT_ERROR";
        if (events == MEDUSA_WEBSOCKETSERVER_EVENT_DESTROY)             return "MEDUSA_WEBSOCKETSERVER_EVENT_DESTROY";
        return "MEDUSA_WEBSOCKETSERVER_EVENT_UNKNOWN";
}

__attribute__ ((visibility ("default"))) const char * medusa_websocketserver_state_string (unsigned int state)
{
        if (state == MEDUSA_WEBSOCKETSERVER_STATE_UNKNOWN)              return "MEDUSA_WEBSOCKETSERVER_STATE_UNKNOWN";
        if (state == MEDUSA_WEBSOCKETSERVER_STATE_ERROR)                return "MEDUSA_WEBSOCKETSERVER_STATE_ERROR";
        if (state == MEDUSA_WEBSOCKETSERVER_STATE_STARTED)              return "MEDUSA_WEBSOCKETSERVER_STATE_STARTED";
        if (state == MEDUSA_WEBSOCKETSERVER_STATE_STOPPED)              return "MEDUSA_WEBSOCKETSERVER_STATE_STOPPED";
        if (state == MEDUSA_WEBSOCKETSERVER_STATE_BINDING)              return "MEDUSA_WEBSOCKETSERVER_STATE_BINDING";
        if (state == MEDUSA_WEBSOCKETSERVER_STATE_BOUND)                return "MEDUSA_WEBSOCKETSERVER_STATE_BOUND";
        if (state == MEDUSA_WEBSOCKETSERVER_STATE_LISTENING)            return "MEDUSA_WEBSOCKETSERVER_STATE_LISTENING";
        return "MEDUSA_WEBSOCKETSERVER_STATE_UNKNOWN";
}

__attribute__ ((constructor)) static void websocketserver_constructor (void)
{
#if defined(MEDUSA_WEBSOCKETSERVER_USE_POOL) && (MEDUSA_WEBSOCKETSERVER_USE_POOL == 1)
        g_pool = medusa_pool_create("medusa-websocketserver", sizeof(struct medusa_websocketserver), 0, 0, MEDUSA_POOL_FLAG_DEFAULT | MEDUSA_POOL_FLAG_THREAD_SAFE, NULL, NULL, NULL);
#endif
}

__attribute__ ((destructor)) static void websocketserver_destructor (void)
{
#if defined(MEDUSA_WEBSOCKETSERVER_USE_POOL) && (MEDUSA_WEBSOCKETSERVER_USE_POOL == 1)
        if (g_pool != NULL) {
                medusa_pool_destroy(g_pool);
        }
#endif
}
