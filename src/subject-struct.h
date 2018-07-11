
enum {
        medusa_subject_flag_mod       = 0x00000001,
        medusa_subject_flag_del       = 0x00000002,
        medusa_subject_flag_poll      = 0x00000004,
        medusa_subject_flag_rogue     = 0x00000008
};

TAILQ_HEAD(medusa_subjects, medusa_subject);
struct medusa_subject {
        TAILQ_ENTRY(medusa_subject) subjects;
        unsigned int type;
        int (*event) (struct medusa_subject *subject, unsigned int events);
        void (*destroy) (struct medusa_subject *subject);
        void *context;
        struct medusa_monitor *monitor;
        unsigned int flags;
};
