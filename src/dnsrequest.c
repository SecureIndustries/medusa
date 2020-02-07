
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "../3rdparty/SPCDNS/src/dns.h"
#include "../3rdparty/SPCDNS/src/mappings.h"
#include "../3rdparty/SPCDNS/src/output.h"

#include "error.h"
#include "pool.h"
#include "queue.h"
#include "subject-struct.h"
#include "udpsocket.h"
#include "udpsocket-private.h"
#include "dnsrequest.h"
#include "dnsrequest-private.h"
#include "dnsrequest-struct.h"
#include "monitor-private.h"

#define MEDUSA_DNSREQUEST_USE_POOL             1

#if defined(MEDUSA_DNSREQUEST_USE_POOL) && (MEDUSA_DNSREQUEST_USE_POOL == 1)
static struct medusa_pool *g_pool;
#endif

static inline unsigned int dnsrequest_get_state (const struct medusa_dnsrequest *dnsrequest)
{
        return dnsrequest->state;
}

static inline int dnsrequest_set_state (struct medusa_dnsrequest *dnsrequest, unsigned int state)
{
        if (state == MEDUSA_DNSREQUEST_STATE_DISCONNECTED) {
                if (!MEDUSA_IS_ERR_OR_NULL(dnsrequest->udpsocket)) {
                        medusa_udpsocket_destroy_unlocked(dnsrequest->udpsocket);
                        dnsrequest->udpsocket = NULL;
                }
        }
        dnsrequest->state = state;
        return 0;
}

static int dnsrequest_udpsocket_onevent (struct medusa_udpsocket *udpsocket, unsigned int events, void *context, void *param)
{
        int rc;

        struct medusa_monitor *monitor;
        struct medusa_dnsrequest *dnsrequest = (struct medusa_dnsrequest *) context;

        (void) param;

        monitor = medusa_udpsocket_get_monitor(udpsocket);
        medusa_monitor_lock(monitor);

        if (events & MEDUSA_UDPSOCKET_EVENT_RESOLVING) {
                dnsrequest_set_state(dnsrequest, MEDUSA_DNSREQUEST_STATE_RESOLVING);
                rc = medusa_dnsrequest_onevent_unlocked(dnsrequest, MEDUSA_DNSREQUEST_EVENT_RESOLVING, NULL);
                if (rc < 0) {
                        goto bail;
                }
        }
        if (events & MEDUSA_UDPSOCKET_EVENT_RESOLVED) {
                dnsrequest_set_state(dnsrequest, MEDUSA_DNSREQUEST_STATE_RESOLVED);
                rc = medusa_dnsrequest_onevent_unlocked(dnsrequest, MEDUSA_DNSREQUEST_EVENT_RESOLVED, NULL);
                if (rc < 0) {
                        goto bail;
                }
        }
        if (events & MEDUSA_UDPSOCKET_EVENT_CONNECTING) {
                dnsrequest_set_state(dnsrequest, MEDUSA_DNSREQUEST_STATE_CONNECTING);
                rc = medusa_dnsrequest_onevent_unlocked(dnsrequest, MEDUSA_DNSREQUEST_EVENT_CONNECTING, NULL);
                if (rc < 0) {
                        goto bail;
                }
        }
        if (events & MEDUSA_UDPSOCKET_EVENT_CONNECTED) {
                int fd;

                dns_question_t domain;
                dns_query_t    query;
                dns_packet_t   request[DNS_BUFFER_UDP];
                size_t         reqsize;

                dnsrequest_set_state(dnsrequest, MEDUSA_DNSREQUEST_STATE_CONNECTED);
                rc = medusa_dnsrequest_onevent_unlocked(dnsrequest, MEDUSA_DNSREQUEST_EVENT_CONNECTED, NULL);
                if (rc < 0) {
                        goto bail;
                }

                dnsrequest_set_state(dnsrequest, MEDUSA_DNSREQUEST_STATE_REQUESTING);
                rc = medusa_dnsrequest_onevent_unlocked(dnsrequest, MEDUSA_DNSREQUEST_EVENT_REQUESTING, NULL);
                if (rc < 0) {
                        goto bail;
                }

                domain.name  = dnsrequest->name;
                domain.type  = dns_type_value(medusa_dnsrequest_record_type_string(dnsrequest->type) + 30);
                domain.class = CLASS_IN;

                query.id          = rand() & 0xffff;
                query.query       = true;
                query.opcode      = OP_QUERY;
                query.aa          = false;
                query.tc          = false;
                query.rd          = true;
                query.ra          = false;
                query.z           = false;
                query.ad          = false;
                query.cd          = false;
                query.rcode       = RCODE_OKAY;
                query.qdcount     = 1;
                query.questions   = &domain;
                query.ancount     = 0;
                query.answers     = NULL;
                query.nscount     = 0;
                query.nameservers = NULL;
                query.arcount     = 0;
                query.additional  = NULL;

                reqsize = sizeof(request);
                rc      = dns_encode(request, &reqsize, &query);
                if (rc != RCODE_OKAY) {
                        dnsrequest_set_state(dnsrequest, MEDUSA_DNSREQUEST_STATE_DISCONNECTED);
                        rc = medusa_dnsrequest_onevent_unlocked(dnsrequest, MEDUSA_DNSREQUEST_EVENT_ERROR, NULL);
                        if (rc < 0) {
                                goto bail;
                        }
                }

                fd = medusa_udpsocket_get_fd_unlocked(udpsocket);
                if (fd < 0) {
                        dnsrequest_set_state(dnsrequest, MEDUSA_DNSREQUEST_STATE_DISCONNECTED);
                        rc = medusa_dnsrequest_onevent_unlocked(dnsrequest, MEDUSA_DNSREQUEST_EVENT_ERROR, NULL);
                        if (rc < 0) {
                                goto bail;
                        }
                }
                rc = sendto(fd, request, reqsize, MSG_NOSIGNAL, NULL, 0);
                if (rc != (int) reqsize) {
                        dnsrequest_set_state(dnsrequest, MEDUSA_DNSREQUEST_STATE_DISCONNECTED);
                        rc = medusa_dnsrequest_onevent_unlocked(dnsrequest, MEDUSA_DNSREQUEST_EVENT_ERROR, NULL);
                        if (rc < 0) {
                                goto bail;
                        }
                }

                dnsrequest_set_state(dnsrequest, MEDUSA_DNSREQUEST_STATE_REQUESTED);
                rc = medusa_dnsrequest_onevent_unlocked(dnsrequest, MEDUSA_DNSREQUEST_EVENT_REQUESTED, NULL);
                if (rc < 0) {
                        goto bail;
                }
        }
        if (events & MEDUSA_UDPSOCKET_EVENT_IN) {
                int fd;

                dns_packet_t reply[DNS_BUFFER_UDP];
                size_t       replysize;

                dns_decoded_t  bufresult[DNS_DECODEBUF_8K];
                size_t         bufsize;

                replysize = sizeof(reply);

                dnsrequest_set_state(dnsrequest, MEDUSA_DNSREQUEST_STATE_RECEIVING);
                rc = medusa_dnsrequest_onevent_unlocked(dnsrequest, MEDUSA_DNSREQUEST_EVENT_RECEIVING, NULL);
                if (rc < 0) {
                        goto bail;
                }

                fd = medusa_udpsocket_get_fd_unlocked(udpsocket);
                if (fd < 0) {
                        dnsrequest_set_state(dnsrequest, MEDUSA_DNSREQUEST_STATE_DISCONNECTED);
                        rc = medusa_dnsrequest_onevent_unlocked(dnsrequest, MEDUSA_DNSREQUEST_EVENT_ERROR, NULL);
                        if (rc < 0) {
                                goto bail;
                        }
                }
                rc = recvfrom(fd, reply, replysize, MSG_NOSIGNAL, NULL, 0);
                if (rc <= 0) {
                        dnsrequest_set_state(dnsrequest, MEDUSA_DNSREQUEST_STATE_DISCONNECTED);
                        rc = medusa_dnsrequest_onevent_unlocked(dnsrequest, MEDUSA_DNSREQUEST_EVENT_ERROR, NULL);
                        if (rc < 0) {
                                goto bail;
                        }
                }

                bufsize = sizeof(bufresult);
                rc = dns_decode(bufresult, &bufsize, reply, replysize);
                if (rc != RCODE_OKAY) {
                        dnsrequest_set_state(dnsrequest, MEDUSA_DNSREQUEST_STATE_DISCONNECTED);
                        rc = medusa_dnsrequest_onevent_unlocked(dnsrequest, MEDUSA_DNSREQUEST_EVENT_ERROR, NULL);
                        if (rc < 0) {
                                goto bail;
                        }
                }

                dns_print_result((dns_query_t *)bufresult);

                dnsrequest_set_state(dnsrequest, MEDUSA_DNSREQUEST_STATE_RECEIVED);
                rc = medusa_dnsrequest_onevent_unlocked(dnsrequest, MEDUSA_DNSREQUEST_EVENT_RECEIVED, NULL);
                if (rc < 0) {
                        goto bail;
                }

                dnsrequest_set_state(dnsrequest, MEDUSA_DNSREQUEST_STATE_DISCONNECTED);
                rc = medusa_dnsrequest_onevent_unlocked(dnsrequest, MEDUSA_DNSREQUEST_EVENT_DISCONNECTED, NULL);
                if (rc < 0) {
                        goto bail;
                }
        }

        medusa_monitor_unlock(monitor);
        return 0;
bail:   medusa_monitor_unlock(monitor);
        return -EIO;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_init_options_default (struct medusa_dnsrequest_init_options *options)
{
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        memset(options, 0, sizeof(struct medusa_dnsrequest_init_options));
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_init_unlocked (struct medusa_dnsrequest *dnsrequest, struct medusa_monitor *monitor, int (*onevent) (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *context, void *param), void *context)
{
        int rc;
        struct medusa_dnsrequest_init_options options;
        rc = medusa_dnsrequest_init_options_default(&options);
        if (rc < 0) {
                return rc;
        }
        options.monitor = monitor;
        options.onevent = onevent;
        options.context = context;
        return medusa_dnsrequest_init_with_options_unlocked(dnsrequest, &options);
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_init (struct medusa_dnsrequest *dnsrequest, struct medusa_monitor *monitor, int (*onevent) (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *context, void *param), void *context)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return -EINVAL;
        }
        medusa_monitor_lock(monitor);
        rc = medusa_dnsrequest_init_unlocked(dnsrequest, monitor, onevent, context);
        medusa_monitor_unlock(monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_init_with_options_unlocked (struct medusa_dnsrequest *dnsrequest, const struct medusa_dnsrequest_init_options *options)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
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
        memset(dnsrequest, 0, sizeof(struct medusa_dnsrequest));
        medusa_subject_set_type(&dnsrequest->subject, MEDUSA_SUBJECT_TYPE_DNSREQUEST);
        dnsrequest->subject.monitor = NULL;
        dnsrequest_set_state(dnsrequest, MEDUSA_DNSREQUEST_STATE_DISCONNECTED);
        dnsrequest->onevent = options->onevent;
        dnsrequest->context = options->context;
        dnsrequest->connect_timeout = -1;
        dnsrequest->read_timeout    = -1;
        if (options->nameserver != NULL) {
                dnsrequest->nameserver = strdup(options->nameserver);
                if (dnsrequest->nameserver == NULL) {
                        return -ENOMEM;
                }
        }
        if (options->name != NULL) {
                dnsrequest->name = strdup(options->name);
                if (dnsrequest->name == NULL) {
                        return -ENOMEM;
                }
        }
        dnsrequest->type = options->type;
        rc = medusa_monitor_add_unlocked(options->monitor, &dnsrequest->subject);
        if (rc < 0) {
                return rc;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_init_with_options (struct medusa_dnsrequest *dnsrequest, const struct medusa_dnsrequest_init_options *options)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return -EINVAL;
        }
        medusa_monitor_lock(options->monitor);
        rc = medusa_dnsrequest_init_with_options_unlocked(dnsrequest, options);
        medusa_monitor_unlock(options->monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void medusa_dnsrequest_uninit_unlocked (struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return;
        }
        if (dnsrequest->subject.monitor != NULL) {
                medusa_monitor_del_unlocked(&dnsrequest->subject);
        } else {
                medusa_dnsrequest_onevent_unlocked(dnsrequest, MEDUSA_DNSREQUEST_EVENT_DESTROY, NULL);
        }
}

__attribute__ ((visibility ("default"))) void medusa_dnsrequest_uninit (struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        medusa_dnsrequest_uninit_unlocked(dnsrequest);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
}

__attribute__ ((visibility ("default"))) struct medusa_dnsrequest * medusa_dnsrequest_create_lookup_unlocked (struct medusa_monitor *monitor, const char *nameserver, unsigned int type, const char *name, int (*onevent) (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *context, void *param), void *context)
{
        int rc;
        struct medusa_dnsrequest *dnsrequest;

        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (nameserver == NULL) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (name == NULL) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (onevent == NULL) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }

        dnsrequest = medusa_dnsrequest_create_unlocked(monitor, onevent, context);
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return dnsrequest;
        }
        rc = medusa_dnsrequest_set_nameserver_unlocked(dnsrequest, nameserver);
        if (rc != 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        rc = medusa_dnsrequest_set_type_unlocked(dnsrequest, type);
        if (rc != 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        rc = medusa_dnsrequest_set_name_unlocked(dnsrequest, name);
        if (rc != 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        rc = medusa_dnsrequest_lookup_unlocked(dnsrequest);
        if (rc != 0) {
                return MEDUSA_ERR_PTR(rc);
        }

        return dnsrequest;
}

__attribute__ ((visibility ("default"))) struct medusa_dnsrequest * medusa_dnsrequest_create_lookup (struct medusa_monitor *monitor, const char *nameserver, unsigned int type, const char *name, int (*onevent) (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *context, void *param), void *context)
{
        struct medusa_dnsrequest *rc;
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(monitor);
        rc = medusa_dnsrequest_create_lookup_unlocked(monitor, nameserver, type, name, onevent, context);
        medusa_monitor_unlock(monitor);
        return rc;
}


__attribute__ ((visibility ("default"))) struct medusa_dnsrequest * medusa_dnsrequest_create_unlocked (struct medusa_monitor *monitor, int (*onevent) (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *context, void *param), void *context)
{
        int rc;
        struct medusa_dnsrequest_init_options options;
        rc = medusa_dnsrequest_init_options_default(&options);
        if (rc < 0) {
                return MEDUSA_ERR_PTR(rc);
        }
        options.monitor = monitor;
        options.onevent = onevent;
        options.context = context;
        return medusa_dnsrequest_create_with_options_unlocked(&options);
}

__attribute__ ((visibility ("default"))) struct medusa_dnsrequest * medusa_dnsrequest_create (struct medusa_monitor *monitor, int (*onevent) (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *context, void *param), void *context)
{
        struct medusa_dnsrequest *rc;
        if (MEDUSA_IS_ERR_OR_NULL(monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(monitor);
        rc = medusa_dnsrequest_create_unlocked(monitor, onevent, context);
        medusa_monitor_unlock(monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_dnsrequest * medusa_dnsrequest_create_with_options_unlocked (const struct medusa_dnsrequest_init_options *options)
{
        int rc;
        struct medusa_dnsrequest *dnsrequest;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->onevent)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
#if defined(MEDUSA_DNSREQUEST_USE_POOL) && (MEDUSA_DNSREQUEST_USE_POOL == 1)
        dnsrequest = medusa_pool_malloc(g_pool);
#else
        dnsrequest = malloc(sizeof(struct medusa_dnsrequest));
#endif
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(dnsrequest, 0, sizeof(struct medusa_dnsrequest));
        rc = medusa_dnsrequest_init_with_options_unlocked(dnsrequest, options);
        if (rc < 0) {
                medusa_dnsrequest_destroy_unlocked(dnsrequest);
                return MEDUSA_ERR_PTR(rc);
        }
        dnsrequest->subject.flags |= MEDUSA_SUBJECT_FLAG_ALLOC;
        return dnsrequest;
}

__attribute__ ((visibility ("default"))) struct medusa_dnsrequest * medusa_dnsrequest_create_with_options (const struct medusa_dnsrequest_init_options *options)
{
        struct medusa_dnsrequest *rc;
        if (MEDUSA_IS_ERR_OR_NULL(options)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(options->monitor)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(options->monitor);
        rc = medusa_dnsrequest_create_with_options_unlocked(options);
        medusa_monitor_unlock(options->monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) void medusa_dnsrequest_destroy_unlocked (struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return;
        }
        medusa_dnsrequest_uninit_unlocked(dnsrequest);
}

__attribute__ ((visibility ("default"))) void medusa_dnsrequest_destroy (struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        medusa_dnsrequest_destroy_unlocked(dnsrequest);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_dnsrequest_get_state_unlocked (const struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return MEDUSA_DNSREQUEST_STATE_UNKNOWN;
        }
        return dnsrequest_get_state(dnsrequest);
}

__attribute__ ((visibility ("default"))) unsigned int medusa_dnsrequest_get_state (const struct medusa_dnsrequest *dnsrequest)
{
        unsigned int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return MEDUSA_DNSREQUEST_STATE_UNKNOWN;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_get_state_unlocked(dnsrequest);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_set_connect_timeout_unlocked (struct medusa_dnsrequest *dnsrequest, double timeout)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        dnsrequest->connect_timeout = timeout;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_set_connect_timeout (struct medusa_dnsrequest *dnsrequest, double timeout)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_set_connect_timeout_unlocked(dnsrequest, timeout);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) double medusa_dnsrequest_get_connect_timeout_unlocked (const struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        return dnsrequest->connect_timeout;
}

__attribute__ ((visibility ("default"))) double medusa_dnsrequest_get_connect_timeout (const struct medusa_dnsrequest *dnsrequest)
{
        double rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_get_connect_timeout_unlocked(dnsrequest);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_set_read_timeout_unlocked (struct medusa_dnsrequest *dnsrequest, double timeout)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        dnsrequest->read_timeout = timeout;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_set_read_timeout (struct medusa_dnsrequest *dnsrequest, double timeout)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_set_read_timeout_unlocked(dnsrequest, timeout);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) double medusa_dnsrequest_get_read_timeout_unlocked (const struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        return dnsrequest->read_timeout;
}

__attribute__ ((visibility ("default"))) double medusa_dnsrequest_get_read_timeout (const struct medusa_dnsrequest *dnsrequest)
{
        double rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_get_read_timeout_unlocked(dnsrequest);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_set_nameserver_unlocked (struct medusa_dnsrequest *dnsrequest, const char *nameserver)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(nameserver)) {
                return -EINVAL;
        }
        if (!MEDUSA_IS_ERR_OR_NULL(dnsrequest->udpsocket)) {
                return -EINPROGRESS;
        }
        if (dnsrequest->nameserver != NULL) {
                free(dnsrequest->nameserver);
        }
        dnsrequest->nameserver = strdup(nameserver);
        if (dnsrequest->nameserver == NULL) {
                return -ENOMEM;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_set_nameserver (struct medusa_dnsrequest *dnsrequest, const char *nameserver)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(nameserver)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_set_nameserver_unlocked(dnsrequest, nameserver);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsrequest_get_nameserver_unlocked (struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return dnsrequest->nameserver;
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsrequest_get_nameserver (struct medusa_dnsrequest *dnsrequest)
{
        const char *rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_get_nameserver_unlocked(dnsrequest);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_set_type_unlocked (struct medusa_dnsrequest *dnsrequest, unsigned int type)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        if (!MEDUSA_IS_ERR_OR_NULL(dnsrequest->udpsocket)) {
                return -EINPROGRESS;
        }
        dnsrequest->type = type;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_set_type (struct medusa_dnsrequest *dnsrequest, unsigned int type)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_set_type_unlocked(dnsrequest, type);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_get_type_unlocked (struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        return dnsrequest->type;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_get_type (struct medusa_dnsrequest *dnsrequest)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_get_type_unlocked(dnsrequest);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_set_name_unlocked (struct medusa_dnsrequest *dnsrequest, const char *name)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(name)) {
                return -EINVAL;
        }
        if (!MEDUSA_IS_ERR_OR_NULL(dnsrequest->udpsocket)) {
                return -EINPROGRESS;
        }
        if (dnsrequest->name != NULL) {
                free(dnsrequest->name);
        }
        dnsrequest->name = strdup(name);
        if (dnsrequest->name == NULL) {
                return -ENOMEM;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_set_name (struct medusa_dnsrequest *dnsrequest, const char *name)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(name)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_set_name_unlocked(dnsrequest, name);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsrequest_get_name_unlocked (struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return dnsrequest->name;
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsrequest_get_name (struct medusa_dnsrequest *dnsrequest)
{
        const char *rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_get_name_unlocked(dnsrequest);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_lookup_unlocked (struct medusa_dnsrequest *dnsrequest)
{
        int rc;

        struct medusa_udpsocket_init_options medusa_udpsocket_init_options;
        struct medusa_udpsocket_connect_options medusa_udpsocket_connect_options;

        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }

        if (!MEDUSA_IS_ERR_OR_NULL(dnsrequest->udpsocket)) {
                return -EALREADY;
        }

        if (dnsrequest->name == NULL) {
                return -EINVAL;
        }
        if (dnsrequest->type == MEDUSA_DNSREQUEST_RECORD_TYPE_INVALID) {
                return -EINVAL;
        }
        if (dnsrequest->type == MEDUSA_DNSREQUEST_RECORD_TYPE_UNKNOWN) {
                return -EINVAL;
        }

        rc = medusa_udpsocket_init_options_default(&medusa_udpsocket_init_options);
        if (rc != 0) {
                return rc;
        }
        medusa_udpsocket_init_options.monitor     = medusa_dnsrequest_get_monitor_unlocked(dnsrequest);
        medusa_udpsocket_init_options.onevent     = dnsrequest_udpsocket_onevent;
        medusa_udpsocket_init_options.context     = dnsrequest;
        medusa_udpsocket_init_options.enabled     = 1;
        medusa_udpsocket_init_options.nonblocking = 1;
        medusa_udpsocket_init_options.reuseaddr   = 1;
        medusa_udpsocket_init_options.reuseport   = 1;
        dnsrequest->udpsocket = medusa_udpsocket_create_with_options_unlocked(&medusa_udpsocket_init_options);
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest->udpsocket)) {
                return MEDUSA_PTR_ERR(dnsrequest->udpsocket);
        }

        rc = medusa_udpsocket_connect_options_default(&medusa_udpsocket_connect_options);
        if (rc != 0) {
                return rc;
        }
        medusa_udpsocket_connect_options.address = dnsrequest->nameserver;
        medusa_udpsocket_connect_options.port    = 53;
        medusa_udpsocket_connect_options.protocol= MEDUSA_UDPSOCKET_PROTOCOL_ANY;
        rc = medusa_udpsocket_connect_with_options_unlocked(dnsrequest->udpsocket, &medusa_udpsocket_connect_options);
        if (rc != 0) {
                return rc;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_lookup (struct medusa_dnsrequest *dnsrequest)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_lookup_unlocked(dnsrequest);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_cancel_unlocked (struct medusa_dnsrequest *dnsrequest)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest->udpsocket)) {
                return -EALREADY;
        }
        dnsrequest_set_state(dnsrequest, MEDUSA_DNSREQUEST_STATE_DISCONNECTED);
        rc = medusa_dnsrequest_onevent_unlocked(dnsrequest, MEDUSA_DNSREQUEST_EVENT_CANCELED, NULL);
        if (rc < 0) {
                return -EIO;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_cancel (struct medusa_dnsrequest *dnsrequest)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_cancel_unlocked(dnsrequest);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_abort_unlocked (struct medusa_dnsrequest *dnsrequest)
{
        return medusa_dnsrequest_cancel_unlocked(dnsrequest);
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_abort (struct medusa_dnsrequest *dnsrequest)
{
        return medusa_dnsrequest_cancel(dnsrequest);
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_onevent_unlocked (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *param)
{
        int ret;
        struct medusa_monitor *monitor;
        ret = 0;
        monitor = dnsrequest->subject.monitor;
        if (dnsrequest->onevent != NULL) {
                if ((medusa_subject_is_active(&dnsrequest->subject)) ||
                    (events & MEDUSA_DNSREQUEST_EVENT_DESTROY)) {
                        medusa_monitor_unlock(monitor);
                        ret = dnsrequest->onevent(dnsrequest, events, dnsrequest->context, param);
                        medusa_monitor_lock(monitor);
                }
        }
        if (events & MEDUSA_DNSREQUEST_EVENT_DESTROY) {
                if (dnsrequest->nameserver != NULL) {
                        free(dnsrequest->nameserver);
                        dnsrequest->nameserver = NULL;
                }
                if (dnsrequest->name != NULL) {
                        free(dnsrequest->name);
                        dnsrequest->name = NULL;
                }
                if (!MEDUSA_IS_ERR_OR_NULL(dnsrequest->udpsocket)) {
                        medusa_udpsocket_destroy_unlocked(dnsrequest->udpsocket);
                        dnsrequest->udpsocket = NULL;
                }
                if (dnsrequest->subject.flags & MEDUSA_SUBJECT_FLAG_ALLOC) {
#if defined(MEDUSA_DNSREQUEST_USE_POOL) && (MEDUSA_DNSREQUEST_USE_POOL == 1)
                        medusa_pool_free(dnsrequest);
#else
                        free(dnsrequest);
#endif
                } else {
                        memset(dnsrequest, 0, sizeof(struct medusa_dnsrequest));
                }
        }
        return ret;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_onevent (struct medusa_dnsrequest *dnsrequest, unsigned int events, void *param)
{
        int rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -EINVAL;
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_onevent_unlocked(dnsrequest, events, param);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_dnsrequest_get_monitor_unlocked (struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return dnsrequest->subject.monitor;
}

__attribute__ ((visibility ("default"))) struct medusa_monitor * medusa_dnsrequest_get_monitor (struct medusa_dnsrequest *dnsrequest)
{
        struct medusa_monitor *rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_get_monitor_unlocked(dnsrequest);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

unsigned int medusa_dnsrequest_record_type_value (const char *type)
{
        if (strcasecmp(type, "INVALID") == 0)       return MEDUSA_DNSREQUEST_RECORD_TYPE_INVALID;
        if (strcasecmp(type, "A") == 0)             return MEDUSA_DNSREQUEST_RECORD_TYPE_A;
        if (strcasecmp(type, "NS") == 0)            return MEDUSA_DNSREQUEST_RECORD_TYPE_NS;
        if (strcasecmp(type, "CNAME") == 0)         return MEDUSA_DNSREQUEST_RECORD_TYPE_CNAME;
        if (strcasecmp(type, "PTR") == 0)           return MEDUSA_DNSREQUEST_RECORD_TYPE_PTR;
        if (strcasecmp(type, "MX") == 0)            return MEDUSA_DNSREQUEST_RECORD_TYPE_MX;
        if (strcasecmp(type, "TXT") == 0)           return MEDUSA_DNSREQUEST_RECORD_TYPE_TXT;
        if (strcasecmp(type, "AAAA") == 0)          return MEDUSA_DNSREQUEST_RECORD_TYPE_AAAA;
        if (strcasecmp(type, "SRV") == 0)           return MEDUSA_DNSREQUEST_RECORD_TYPE_SRV;
        if (strcasecmp(type, "ANY") == 0)           return MEDUSA_DNSREQUEST_RECORD_TYPE_ANY;
        if (strcasecmp(type, "UNKNOWN") == 0)       return MEDUSA_DNSREQUEST_RECORD_TYPE_UNKNOWN;
        return MEDUSA_DNSREQUEST_RECORD_TYPE_UNKNOWN;
}

const char * medusa_dnsrequest_record_type_string (unsigned int type)
{
        if (type == MEDUSA_DNSREQUEST_RECORD_TYPE_INVALID)      return "MEDUSA_DNSREQUEST_RECORD_TYPE_INVALID";
        if (type == MEDUSA_DNSREQUEST_RECORD_TYPE_A)            return "MEDUSA_DNSREQUEST_RECORD_TYPE_A";
        if (type == MEDUSA_DNSREQUEST_RECORD_TYPE_NS)           return "MEDUSA_DNSREQUEST_RECORD_TYPE_NS";
        if (type == MEDUSA_DNSREQUEST_RECORD_TYPE_CNAME)        return "MEDUSA_DNSREQUEST_RECORD_TYPE_CNAME";
        if (type == MEDUSA_DNSREQUEST_RECORD_TYPE_PTR)          return "MEDUSA_DNSREQUEST_RECORD_TYPE_PTR";
        if (type == MEDUSA_DNSREQUEST_RECORD_TYPE_MX)           return "MEDUSA_DNSREQUEST_RECORD_TYPE_MX";
        if (type == MEDUSA_DNSREQUEST_RECORD_TYPE_TXT)          return "MEDUSA_DNSREQUEST_RECORD_TYPE_TXT";
        if (type == MEDUSA_DNSREQUEST_RECORD_TYPE_AAAA)         return "MEDUSA_DNSREQUEST_RECORD_TYPE_AAAA";
        if (type == MEDUSA_DNSREQUEST_RECORD_TYPE_SRV)          return "MEDUSA_DNSREQUEST_RECORD_TYPE_SRV";
        if (type == MEDUSA_DNSREQUEST_RECORD_TYPE_ANY)          return "MEDUSA_DNSREQUEST_RECORD_TYPE_ANY";
        if (type == MEDUSA_DNSREQUEST_RECORD_TYPE_UNKNOWN)      return "MEDUSA_DNSREQUEST_RECORD_TYPE_UNKNOWN";
        return "MEDUSA_DNSREQUEST_RECORD_TYPE_UNKNOWN";
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsrequest_event_string (unsigned int events)
{
        if (events == MEDUSA_DNSREQUEST_EVENT_RESOLVING)        return "MEDUSA_DNSREQUEST_EVENT_RESOLVING";
        if (events == MEDUSA_DNSREQUEST_EVENT_RESOLVE_TIMEOUT)  return "MEDUSA_DNSREQUEST_EVENT_RESOLVE_TIMEOUT";
        if (events == MEDUSA_DNSREQUEST_EVENT_RESOLVED)         return "MEDUSA_DNSREQUEST_EVENT_RESOLVED";
        if (events == MEDUSA_DNSREQUEST_EVENT_CONNECTING)       return "MEDUSA_DNSREQUEST_EVENT_CONNECTING";
        if (events == MEDUSA_DNSREQUEST_EVENT_CONNECT_TIMEOUT)  return "MEDUSA_DNSREQUEST_EVENT_CONNECT_TIMEOUT";
        if (events == MEDUSA_DNSREQUEST_EVENT_CONNECTED)        return "MEDUSA_DNSREQUEST_EVENT_CONNECTED";
        if (events == MEDUSA_DNSREQUEST_EVENT_REQUESTING)       return "MEDUSA_DNSREQUEST_EVENT_REQUESTING";
        if (events == MEDUSA_DNSREQUEST_EVENT_REQUESTED)        return "MEDUSA_DNSREQUEST_EVENT_REQUESTED";
        if (events == MEDUSA_DNSREQUEST_EVENT_RECEIVING)        return "MEDUSA_DNSREQUEST_EVENT_RECEIVING";
        if (events == MEDUSA_DNSREQUEST_EVENT_RECEIVED)         return "MEDUSA_DNSREQUEST_EVENT_RECEIVED";
        if (events == MEDUSA_DNSREQUEST_EVENT_CANCELED)         return "MEDUSA_DNSREQUEST_EVENT_CANCELED";
        if (events == MEDUSA_DNSREQUEST_EVENT_ERROR)            return "MEDUSA_DNSREQUEST_EVENT_ERROR";
        if (events == MEDUSA_DNSREQUEST_EVENT_DISCONNECTED)     return "MEDUSA_DNSREQUEST_EVENT_DISCONNECTED";
        if (events == MEDUSA_DNSREQUEST_EVENT_DESTROY)          return "MEDUSA_DNSREQUEST_EVENT_DESTROY";
        return "MEDUSA_DNSREQUEST_EVENT_UNKNOWN";
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsrequest_state_string (unsigned int state)
{
        if (state == MEDUSA_DNSREQUEST_STATE_UNKNOWN)           return "MEDUSA_DNSREQUEST_STATE_UNKNOWN";
        if (state == MEDUSA_DNSREQUEST_STATE_DISCONNECTED)      return "MEDUSA_DNSREQUEST_STATE_DISCONNECTED";
        if (state == MEDUSA_DNSREQUEST_STATE_RESOLVING)         return "MEDUSA_DNSREQUEST_STATE_RESOLVING";
        if (state == MEDUSA_DNSREQUEST_STATE_RESOLVED)          return "MEDUSA_DNSREQUEST_STATE_RESOLVED";
        if (state == MEDUSA_DNSREQUEST_STATE_CONNECTING)        return "MEDUSA_DNSREQUEST_STATE_CONNECTING";
        if (state == MEDUSA_DNSREQUEST_STATE_CONNECTED)         return "MEDUSA_DNSREQUEST_STATE_CONNECTED";
        if (state == MEDUSA_DNSREQUEST_STATE_REQUESTING)        return "MEDUSA_DNSREQUEST_STATE_REQUESTING";
        if (state == MEDUSA_DNSREQUEST_STATE_REQUESTED)         return "MEDUSA_DNSREQUEST_STATE_REQUESTED";
        if (state == MEDUSA_DNSREQUEST_STATE_RECEIVING)         return "MEDUSA_DNSREQUEST_STATE_RECEIVING";
        if (state == MEDUSA_DNSREQUEST_STATE_RECEIVED)          return "MEDUSA_DNSREQUEST_STATE_RECEIVED";
        return "MEDUSA_DNSREQUEST_STATE_UNKNOWN";
}

__attribute__ ((constructor)) static void dnsrequest_constructor (void)
{
#if defined(MEDUSA_DNSREQUEST_USE_POOL) && (MEDUSA_DNSREQUEST_USE_POOL == 1)
        g_pool = medusa_pool_create("medusa-dnsrequest", sizeof(struct medusa_dnsrequest), 0, 0, MEDUSA_POOL_FLAG_DEFAULT | MEDUSA_POOL_FLAG_THREAD_SAFE, NULL, NULL, NULL);
#endif
}

__attribute__ ((destructor)) static void dnsrequest_destructor (void)
{
#if defined(MEDUSA_DNSREQUEST_USE_POOL) && (MEDUSA_DNSREQUEST_USE_POOL == 1)
        if (g_pool != NULL) {
                medusa_pool_destroy(g_pool);
        }
#endif
}
