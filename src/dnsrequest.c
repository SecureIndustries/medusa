
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

struct medusa_dnsrequest_reply_header {
        int questions;
        int answers;
        int nameservers;
        int additional_records;
        int authoritative_result;
        int truncated_result;
        int recursion_desired;
        int recursion_available;
        int result;
};

struct medusa_dnsrequest_record_generic {
        char *name;
        unsigned int type;
        unsigned int class;
        unsigned int ttl;
};

struct medusa_dnsrequest_record_a {
        char *name;
        unsigned int type;
        unsigned int class;
        unsigned int ttl;

        char address[INET_ADDRSTRLEN];
};

struct medusa_dnsrequest_record_ns {
        char *name;
        unsigned int type;
        unsigned int class;
        unsigned int ttl;

        char *nsdname;
};

struct medusa_dnsrequest_record_cname {
        char *name;
        unsigned int type;
        unsigned int class;
        unsigned int ttl;

        char *cname;
};

struct medusa_dnsrequest_record_ptr {
        char *name;
        unsigned int type;
        unsigned int class;
        unsigned int ttl;

        char *ptr;
};

struct medusa_dnsrequest_record_mx {
        char *name;
        unsigned int type;
        unsigned int class;
        unsigned int ttl;

        int preference;
        char *exchange;
};

struct medusa_dnsrequest_record_aaaa {
        char *name;
        unsigned int type;
        unsigned int class;
        unsigned int ttl;

        char address[INET6_ADDRSTRLEN];
};

struct medusa_dnsrequest_record_srv {
        char *name;
        unsigned int type;
        unsigned int class;
        unsigned int ttl;

        int priority;
        int weight;
        int port;
        char *target;
};

TAILQ_HEAD(medusa_dnsrequest_reply_answers, medusa_dnsrequest_reply_answer);
struct medusa_dnsrequest_reply_answer {
        TAILQ_ENTRY(medusa_dnsrequest_reply_answer) list;
        union {
                struct medusa_dnsrequest_record_generic generic;
                struct medusa_dnsrequest_record_a       a;
                struct medusa_dnsrequest_record_ns      ns;
                struct medusa_dnsrequest_record_cname   cname;
                struct medusa_dnsrequest_record_ptr     ptr;
                struct medusa_dnsrequest_record_mx      mx;
                struct medusa_dnsrequest_record_aaaa    aaaa;
                struct medusa_dnsrequest_record_srv     srv;
        } u;
};

struct medusa_dnsrequest_reply {
        struct medusa_dnsrequest_reply_header header;
        struct medusa_dnsrequest_reply_answers answers;
};

static void medusa_dnsrequest_record_generic_uninit (struct medusa_dnsrequest_record_generic *generic)
{
        if (generic == NULL) {
                return;
        }
        if (generic->name != NULL) {
                free(generic->name);
        }
}

static void medusa_dnsrequest_record_a_uninit (struct medusa_dnsrequest_record_a *a)
{
        if (a == NULL) {
                return;
        }
        memset(a->address, 0, sizeof(a->address));
}

static int medusa_dnsrequest_record_a_init (struct medusa_dnsrequest_record_a *a, dns_a_t *da)
{
        if (a == NULL) {
                goto bail;
        }
        if (da == NULL) {
                goto bail;
        }
        inet_ntop(AF_INET, &da->address, a->address, sizeof(a->address));
        return 0;
bail:   return -1;
}

static void medusa_dnsrequest_record_ns_uninit (struct medusa_dnsrequest_record_ns *ns)
{
        if (ns == NULL) {
                return;
        }
        if (ns->nsdname != NULL) {
                free(ns->nsdname);
                ns->nsdname = NULL;
        }
}

static int medusa_dnsrequest_record_ns_init (struct medusa_dnsrequest_record_ns *ns, dns_ns_t *dns)
{
        if (ns == NULL) {
                goto bail;
        }
        if (dns == NULL) {
                goto bail;
        }
        if (dns->nsdname != NULL) {
                ns->nsdname = strdup(dns->nsdname);
                if (ns->nsdname == NULL) {
                        goto bail;

                }
        }
        return 0;
bail:   return -1;
}

static void medusa_dnsrequest_record_cname_uninit (struct medusa_dnsrequest_record_cname *cname)
{
        if (cname == NULL) {
                return;
        }
        if (cname->cname != NULL) {
                free(cname->cname);
                cname->cname = NULL;
        }
}

static int medusa_dnsrequest_record_cname_init (struct medusa_dnsrequest_record_cname *cname, dns_cname_t *dcname)
{
        if (cname == NULL) {
                goto bail;
        }
        if (dcname == NULL) {
                goto bail;
        }
        if (dcname->cname != NULL) {
                cname->cname = strdup(dcname->cname);
                if (cname->cname == NULL) {
                        goto bail;

                }
        }
        return 0;
bail:   return -1;
}

static void medusa_dnsrequest_record_ptr_uninit (struct medusa_dnsrequest_record_ptr *ptr)
{
        if (ptr == NULL) {
                return;
        }
        if (ptr->ptr != NULL) {
                free(ptr->ptr);
                ptr->ptr = NULL;
        }
}

static int medusa_dnsrequest_record_ptr_init (struct medusa_dnsrequest_record_ptr *ptr, dns_ptr_t *dptr)
{
        if (ptr == NULL) {
                goto bail;
        }
        if (dptr == NULL) {
                goto bail;
        }
        if (dptr->ptr != NULL) {
                ptr->ptr = strdup(dptr->ptr);
                if (ptr->ptr == NULL) {
                        goto bail;

                }
        }
        return 0;
bail:   return -1;
}

static void medusa_dnsrequest_record_mx_uninit (struct medusa_dnsrequest_record_mx *mx)
{
        if (mx == NULL) {
                return;
        }
        mx->preference = 0;
        if (mx->exchange != NULL) {
                free(mx->exchange);
                mx->exchange = NULL;
        }
}

static int medusa_dnsrequest_record_mx_init (struct medusa_dnsrequest_record_mx *mx, dns_mx_t *dmx)
{
        if (mx == NULL) {
                goto bail;
        }
        if (dmx == NULL) {
                goto bail;
        }
        mx->preference = dmx->preference;
        if (dmx->exchange != NULL) {
                mx->exchange = strdup(dmx->exchange);
                if (mx->exchange == NULL) {
                        goto bail;

                }
        }
        return 0;
bail:   return -1;
}

static void medusa_dnsrequest_record_aaaa_uninit (struct medusa_dnsrequest_record_aaaa *aaaa)
{
        if (aaaa == NULL) {
                return;
        }
        memset(aaaa->address, 0, sizeof(aaaa->address));
}

static int medusa_dnsrequest_record_aaaa_init (struct medusa_dnsrequest_record_aaaa *aaaa, dns_aaaa_t *daaaa)
{
        if (aaaa == NULL) {
                goto bail;
        }
        if (daaaa == NULL) {
                goto bail;
        }
        inet_ntop(AF_INET6, &daaaa->address, aaaa->address, sizeof(aaaa->address));
        return 0;
bail:   return -1;
}

static void medusa_dnsrequest_record_srv_uninit (struct medusa_dnsrequest_record_srv *srv)
{
        if (srv == NULL) {
                return;
        }
        srv->priority = 0;
        srv->weight   = 0;
        srv->port     = 0;
        if (srv->target != NULL) {
                free(srv->target);
                srv->target = NULL;
        }
}

static int medusa_dnsrequest_record_srv_init (struct medusa_dnsrequest_record_srv *srv, dns_srv_t *dsrv)
{
        if (srv == NULL) {
                goto bail;
        }
        if (dsrv == NULL) {
                goto bail;
        }
        srv->priority = dsrv->priority;
        srv->weight   = dsrv->weight;
        srv->port     = dsrv->port;
        if (dsrv->target != NULL) {
                srv->target = strdup(dsrv->target);
                if (srv->target == NULL) {
                        goto bail;

                }
        }
        return 0;
bail:   return -1;
}

static void medusa_dnsrequest_reply_answer_destroy (struct medusa_dnsrequest_reply_answer *answer)
{
        if (answer == NULL) {
                return;
        }
        medusa_dnsrequest_record_generic_uninit(&answer->u.generic);
        switch (answer->u.generic.type) {
                case MEDUSA_DNSREQUEST_RECORD_TYPE_A:           medusa_dnsrequest_record_a_uninit(&answer->u.a);                break;
                case MEDUSA_DNSREQUEST_RECORD_TYPE_NS:          medusa_dnsrequest_record_ns_uninit(&answer->u.ns);              break;
                case MEDUSA_DNSREQUEST_RECORD_TYPE_CNAME:       medusa_dnsrequest_record_cname_uninit(&answer->u.cname);        break;
                case MEDUSA_DNSREQUEST_RECORD_TYPE_PTR:         medusa_dnsrequest_record_ptr_uninit(&answer->u.ptr);            break;
                case MEDUSA_DNSREQUEST_RECORD_TYPE_MX:          medusa_dnsrequest_record_mx_uninit(&answer->u.mx);              break;
                case MEDUSA_DNSREQUEST_RECORD_TYPE_AAAA:        medusa_dnsrequest_record_aaaa_uninit(&answer->u.aaaa);          break;
                case MEDUSA_DNSREQUEST_RECORD_TYPE_SRV:         medusa_dnsrequest_record_srv_uninit(&answer->u.srv);            break;
        }
        free(answer);
}

static struct medusa_dnsrequest_reply_answer * medusa_dnsrequest_reply_answer_create (dns_answer_t *danswer)
{
        int rc;
        struct medusa_dnsrequest_reply_answer *answer;

        answer = NULL;

        if (danswer == NULL) {
                goto bail;
        }

        answer = malloc(sizeof(struct medusa_dnsrequest_reply_answer));
        if (answer == NULL) {
                goto bail;
        }
        memset(answer, 0, sizeof(struct medusa_dnsrequest_reply_answer));

        if (danswer->generic.name != NULL) {
                answer->u.generic.name = strdup(danswer->generic.name);
                if (answer->u.generic.name == NULL) {
                        goto bail;
                }
        }
        answer->u.generic.type  = danswer->generic.type;
        answer->u.generic.class = danswer->generic.class;
        answer->u.generic.ttl   = danswer->generic.ttl;

        rc = -1;
        switch (answer->u.generic.type) {
                case MEDUSA_DNSREQUEST_RECORD_TYPE_A:           rc = medusa_dnsrequest_record_a_init(&answer->u.a, &danswer->a);             break;
                case MEDUSA_DNSREQUEST_RECORD_TYPE_NS:          rc = medusa_dnsrequest_record_ns_init(&answer->u.ns, &danswer->ns);          break;
                case MEDUSA_DNSREQUEST_RECORD_TYPE_CNAME:       rc = medusa_dnsrequest_record_cname_init(&answer->u.cname, &danswer->cname); break;
                case MEDUSA_DNSREQUEST_RECORD_TYPE_PTR:         rc = medusa_dnsrequest_record_ptr_init(&answer->u.ptr, &danswer->ptr);       break;
                case MEDUSA_DNSREQUEST_RECORD_TYPE_MX:          rc = medusa_dnsrequest_record_mx_init(&answer->u.mx, &danswer->mx);          break;
                case MEDUSA_DNSREQUEST_RECORD_TYPE_AAAA:        rc = medusa_dnsrequest_record_aaaa_init(&answer->u.aaaa, &danswer->aaaa);    break;
                case MEDUSA_DNSREQUEST_RECORD_TYPE_SRV:         rc = medusa_dnsrequest_record_srv_init(&answer->u.srv, &danswer->srv);       break;
        }
        if (rc != 0) {
                goto bail;
        }

        return answer;
bail:   if (answer != NULL) {
                medusa_dnsrequest_reply_answer_destroy(answer);
        }
        return NULL;
}

static void medusa_dnsrequest_reply_answers_uninit (struct medusa_dnsrequest_reply_answers *answers)
{
        struct medusa_dnsrequest_reply_answer *answer;
        struct medusa_dnsrequest_reply_answer *nanswer;
        if (answers == NULL) {
                return;
        }
        TAILQ_FOREACH_SAFE(answer, answers, list, nanswer) {
                TAILQ_REMOVE(answers, answer, list);
                medusa_dnsrequest_reply_answer_destroy(answer);
        }
        memset(answers, 0, sizeof(struct medusa_dnsrequest_reply_answers));
}

static int medusa_dnsrequest_reply_answers_init (struct medusa_dnsrequest_reply_answers *answers, dns_answer_t *danswers, int dnanswers)
{
        int i;
        struct medusa_dnsrequest_reply_answer *answer;

        if (answers == NULL) {
                goto bail;
        }

        memset(answers, 0, sizeof(struct medusa_dnsrequest_reply_answers));
        TAILQ_INIT(answers);

        for (i = 0; i < dnanswers; i++) {
                answer = medusa_dnsrequest_reply_answer_create(&danswers[i]);
                if (answer == NULL) {
                        goto bail;
                }
                TAILQ_INSERT_TAIL(answers, answer, list);
        }

        return 0;
bail:   if (answers != NULL) {
                medusa_dnsrequest_reply_answers_uninit(answers);
        }
        return -1;
}

static void medusa_dnsrequest_reply_header_uninit (struct medusa_dnsrequest_reply_header *header)
{
        if (header == NULL) {
                return;
        }
        memset(header, 0, sizeof(struct medusa_dnsrequest_reply_header));
}

static int medusa_dnsrequest_reply_header_init (struct medusa_dnsrequest_reply_header *header, dns_query_t *query)
{
        if (header == NULL) {
                goto bail;
        }
        if (query == NULL) {
                goto bail;
        }

        memset(header, 0, sizeof(struct medusa_dnsrequest_reply_header));

        header->questions               = query->qdcount;
        header->answers                 = query->ancount;
        header->nameservers             = query->nscount;
        header->additional_records      = query->arcount;
        header->authoritative_result    = query->aa;
        header->truncated_result        = query->tc;
        header->recursion_desired       = query->rd;
        header->recursion_available     = query->ra;
        header->result                  = query->rcode;

        return 0;
bail:   if (header != NULL) {
                medusa_dnsrequest_reply_header_uninit(header);
        }
        return -1;
}

static void medusa_dnsrequest_reply_destroy (struct medusa_dnsrequest_reply *reply)
{
        if (reply == NULL) {
                return;
        }
        medusa_dnsrequest_reply_header_uninit(&reply->header);
        medusa_dnsrequest_reply_answers_uninit(&reply->answers);
        free(reply);

}

static struct medusa_dnsrequest_reply * medusa_dnsrequest_reply_create (dns_query_t *query)
{
        int rc;
        struct medusa_dnsrequest_reply *reply;

        reply = NULL;

        if (query == NULL) {
                goto bail;
        }

        reply = malloc(sizeof(struct medusa_dnsrequest_reply));
        if (reply == NULL) {
                goto bail;
        }
        memset(reply, 0, sizeof(struct medusa_dnsrequest_reply));

        rc = medusa_dnsrequest_reply_header_init(&reply->header, query);
        if (rc != 0) {
                goto bail;
        }
        rc = medusa_dnsrequest_reply_answers_init(&reply->answers, query->answers, query->ancount);
        if (rc != 0) {
                goto bail;
        }

        return reply;
bail:   if (reply != NULL) {
                medusa_dnsrequest_reply_destroy(reply);
        }
        return NULL;
}

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

                dnsrequest->reply = medusa_dnsrequest_reply_create((dns_query_t *) bufresult);
                if (dnsrequest->reply == NULL) {
                        dnsrequest_set_state(dnsrequest, MEDUSA_DNSREQUEST_STATE_DISCONNECTED);
                        rc = medusa_dnsrequest_onevent_unlocked(dnsrequest, MEDUSA_DNSREQUEST_EVENT_ERROR, NULL);
                        if (rc < 0) {
                                goto bail;
                        }
                }

                dnsrequest_set_state(dnsrequest, MEDUSA_DNSREQUEST_STATE_RECEIVED);
                rc = medusa_dnsrequest_onevent_unlocked(dnsrequest, MEDUSA_DNSREQUEST_EVENT_RECEIVED, NULL);
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

__attribute__ ((visibility ("default"))) const struct medusa_dnsrequest_reply * medusa_dnsrequest_get_reply_unlocked (struct medusa_dnsrequest *dnsrequest)
{
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return dnsrequest->reply;
}

__attribute__ ((visibility ("default"))) const struct medusa_dnsrequest_reply * medusa_dnsrequest_get_reply (struct medusa_dnsrequest *dnsrequest)
{
        const struct medusa_dnsrequest_reply *rc;
        if (MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        medusa_monitor_lock(dnsrequest->subject.monitor);
        rc = medusa_dnsrequest_get_reply_unlocked(dnsrequest);
        medusa_monitor_unlock(dnsrequest->subject.monitor);
        return rc;
}

__attribute__ ((visibility ("default"))) const struct medusa_dnsrequest_reply_header * medusa_dnsrequest_reply_get_header (const struct medusa_dnsrequest_reply *reply)
{
        if (MEDUSA_IS_ERR_OR_NULL(reply)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return &reply->header;
}

__attribute__ ((visibility ("default"))) const struct medusa_dnsrequest_reply_answers * medusa_dnsrequest_reply_get_answers (const struct medusa_dnsrequest_reply *reply)
{
        if (MEDUSA_IS_ERR_OR_NULL(reply)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return &reply->answers;
}

__attribute__ ((visibility ("default"))) const struct medusa_dnsrequest_reply_answer * medusa_dnsrequest_reply_answers_get_first (const struct medusa_dnsrequest_reply_answers *answers)
{
        if (MEDUSA_IS_ERR_OR_NULL(answers)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return TAILQ_FIRST(answers);
}

__attribute__ ((visibility ("default"))) const struct medusa_dnsrequest_reply_answer * medusa_dnsrequest_reply_answer_get_next (const struct medusa_dnsrequest_reply_answer *answer)
{
        if (MEDUSA_IS_ERR_OR_NULL(answer)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return TAILQ_NEXT(answer, list);
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_reply_header_get_questions_count (const struct medusa_dnsrequest_reply_header *header)
{
        if (MEDUSA_IS_ERR_OR_NULL(header)) {
                return -EINVAL;
        }
        return header->questions;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_reply_header_get_answers_count (const struct medusa_dnsrequest_reply_header *header)
{
        if (MEDUSA_IS_ERR_OR_NULL(header)) {
                return -EINVAL;
        }
        return header->answers;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_reply_header_get_nameservers_count (const struct medusa_dnsrequest_reply_header *header)
{
        if (MEDUSA_IS_ERR_OR_NULL(header)) {
                return -EINVAL;
        }
        return header->nameservers;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_reply_header_get_additional_records (const struct medusa_dnsrequest_reply_header *header)
{
        if (MEDUSA_IS_ERR_OR_NULL(header)) {
                return -EINVAL;
        }
        return header->additional_records;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_reply_header_get_authoritative_result (const struct medusa_dnsrequest_reply_header *header)
{
        if (MEDUSA_IS_ERR_OR_NULL(header)) {
                return -EINVAL;
        }
        return header->authoritative_result;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_reply_header_get_truncated_result (const struct medusa_dnsrequest_reply_header *header)
{
        if (MEDUSA_IS_ERR_OR_NULL(header)) {
                return -EINVAL;
        }
        return header->truncated_result;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_reply_header_get_recursion_desired (const struct medusa_dnsrequest_reply_header *header)
{
        if (MEDUSA_IS_ERR_OR_NULL(header)) {
                return -EINVAL;
        }
        return header->recursion_desired;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_reply_header_get_recursion_available (const struct medusa_dnsrequest_reply_header *header)
{
        if (MEDUSA_IS_ERR_OR_NULL(header)) {
                return -EINVAL;
        }
        return header->recursion_available;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_reply_header_get_result_code (const struct medusa_dnsrequest_reply_header *header)
{
        if (MEDUSA_IS_ERR_OR_NULL(header)) {
                return -EINVAL;
        }
        return header->result;
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsrequest_reply_header_get_result_code_string (const struct medusa_dnsrequest_reply_header *header)
{
        if (MEDUSA_IS_ERR_OR_NULL(header)) {
                return NULL;
        }
        switch (header->result) {
                case 0: return "OKAY";
                case 1: return "FORMAT_ERROR";
                case 2: return "SERVER_FAILURE";
                case 3: return "NAME_ERROR";
                case 4: return "NOT_IMPLEMENTED";
                case 5: return "REFUSED";
                case 6: return "YXDOMAIN";
                case 7: return "YXRRSET";
                case 8: return "NXRRSET";
                case 9: return "NOTAUTH";
                case 10: return "NOTZONE";
        }
        return "ERROR";
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsrequest_reply_answer_get_name (const struct medusa_dnsrequest_reply_answer *answer)
{
        if (answer == NULL) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return answer->u.generic.name;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_reply_answer_get_class (const struct medusa_dnsrequest_reply_answer *answer)
{
        if (answer == NULL) {
                return -EINVAL;
        }
        return answer->u.generic.class;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_reply_answer_get_type (const struct medusa_dnsrequest_reply_answer *answer)
{
        if (answer == NULL) {
                return -EINVAL;
        }
        return answer->u.generic.type;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_reply_answer_get_ttl (const struct medusa_dnsrequest_reply_answer *answer)
{
        if (answer == NULL) {
                return -EINVAL;
        }
        return answer->u.generic.ttl;
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsrequest_reply_answer_a_get_address (const struct medusa_dnsrequest_reply_answer *answer)
{
        if (answer == NULL) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (answer->u.generic.type != MEDUSA_DNSREQUEST_RECORD_TYPE_A) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return answer->u.a.address;
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsrequest_reply_answer_ns_get_nsdname (const struct medusa_dnsrequest_reply_answer *answer)
{
        if (answer == NULL) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (answer->u.generic.type != MEDUSA_DNSREQUEST_RECORD_TYPE_NS) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return answer->u.ns.nsdname;
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsrequest_reply_answer_cname_get_cname (const struct medusa_dnsrequest_reply_answer *answer)
{
        if (answer == NULL) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (answer->u.generic.type != MEDUSA_DNSREQUEST_RECORD_TYPE_CNAME) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return answer->u.cname.cname;
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsrequest_reply_answer_ptr_get_ptr (const struct medusa_dnsrequest_reply_answer *answer)
{
        if (answer == NULL) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (answer->u.generic.type != MEDUSA_DNSREQUEST_RECORD_TYPE_PTR) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return answer->u.ptr.ptr;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_reply_answer_mx_get_preference (const struct medusa_dnsrequest_reply_answer *answer)
{
        if (answer == NULL) {
                return -EINVAL;
        }
        if (answer->u.generic.type != MEDUSA_DNSREQUEST_RECORD_TYPE_MX) {
                return -EINVAL;
        }
        return answer->u.mx.preference;
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsrequest_reply_answer_mx_get_exchange (const struct medusa_dnsrequest_reply_answer *answer)
{
        if (answer == NULL) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (answer->u.generic.type != MEDUSA_DNSREQUEST_RECORD_TYPE_MX) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return answer->u.mx.exchange;
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsrequest_reply_answer_aaaa_get_address (const struct medusa_dnsrequest_reply_answer *answer)
{
        if (answer == NULL) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (answer->u.generic.type != MEDUSA_DNSREQUEST_RECORD_TYPE_AAAA) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return answer->u.aaaa.address;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_reply_answer_srv_get_priority (const struct medusa_dnsrequest_reply_answer *answer)
{
        if (answer == NULL) {
                return -EINVAL;
        }
        if (answer->u.generic.type != MEDUSA_DNSREQUEST_RECORD_TYPE_SRV) {
                return -EINVAL;
        }
        return answer->u.srv.priority;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_reply_answer_srv_get_weight (const struct medusa_dnsrequest_reply_answer *answer)
{
        if (answer == NULL) {
                return -EINVAL;
        }
        if (answer->u.generic.type != MEDUSA_DNSREQUEST_RECORD_TYPE_SRV) {
                return -EINVAL;
        }
        return answer->u.srv.weight;
}

__attribute__ ((visibility ("default"))) int medusa_dnsrequest_reply_answer_srv_get_port (const struct medusa_dnsrequest_reply_answer *answer)
{
        if (answer == NULL) {
                return -EINVAL;
        }
        if (answer->u.generic.type != MEDUSA_DNSREQUEST_RECORD_TYPE_SRV) {
                return -EINVAL;
        }
        return answer->u.srv.port;
}

__attribute__ ((visibility ("default"))) const char * medusa_dnsrequest_reply_answer_srv_get_target (const struct medusa_dnsrequest_reply_answer *answer)
{
        if (answer == NULL) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (answer->u.generic.type != MEDUSA_DNSREQUEST_RECORD_TYPE_SRV) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return answer->u.srv.target;
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
                if (dnsrequest->reply != NULL) {
                        medusa_dnsrequest_reply_destroy(dnsrequest->reply);
                        dnsrequest->reply = NULL;
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
