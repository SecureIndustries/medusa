
#if !defined(MEDUSA_DNSRESOLVER_STRUCT_H)
#define MEDUSA_DNSRESOLVER_STRUCT_H

TAILQ_HEAD(medusa_dnsresolver_lookups, medusa_dnsresolver_lookup);
struct medusa_dnsresolver_lookup {
        struct medusa_subject subject;
        unsigned int state;
        unsigned int error;
        unsigned int enabled;
        int (*onevent) (struct medusa_dnsresolver_lookup *dnsresolver_lookup, unsigned int events, void *context, void *param);
        void *context;
        char *nameserver;
        void *userdata;
        TAILQ_ENTRY(medusa_dnsresolver_lookup) tailq;
};

struct medusa_dnsresolver {
        struct medusa_subject subject;
        unsigned int state;
        unsigned int error;
        unsigned int enabled;
        int (*onevent) (struct medusa_dnsresolver *dnsresolver, unsigned int events, void *context, void *param);
        void *context;
        char *nameserver;
        void *userdata;
        struct medusa_dnsresolver_lookups lookups;
};

int medusa_dnsresolver_init (struct medusa_dnsresolver *dnsresolver, struct medusa_monitor *monitor, int (*onevent) (struct medusa_dnsresolver *dnsresolver, unsigned int events, void *context, void *param), void *context);
int medusa_dnsresolver_init_with_options (struct medusa_dnsresolver *dnsresolver, const struct medusa_dnsresolver_init_options *options);
void medusa_dnsresolver_uninit (struct medusa_dnsresolver *dnsresolver);

#endif
