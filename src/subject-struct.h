
TAILQ_HEAD(medusa_subjects, medusa_subject);
struct medusa_subject {
        TAILQ_ENTRY(medusa_subject) subjects;
        unsigned int refcount;
        unsigned int flags;
        int (*event) (struct medusa_subject *subject, unsigned int events);
        void (*destroy) (struct medusa_subject *subject);
        struct medusa_monitor *monitor;
};
