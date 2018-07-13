
enum {
        MEDUSA_SUBJECT_FLAG_NONE        = 0x00000000,
        MEDUSA_SUBJECT_FLAG_MOD         = 0x00000001,
        MEDUSA_SUBJECT_FLAG_DEL         = 0x00000002,
        MEDUSA_SUBJECT_FLAG_POLL        = 0x00000004,
        MEDUSA_SUBJECT_FLAG_ROGUE       = 0x00000008
#define MEDUSA_SUBJECT_FLAG_NONE        MEDUSA_SUBJECT_FLAG_NONE
#define MEDUSA_SUBJECT_FLAG_MOD         MEDUSA_SUBJECT_FLAG_MOD
#define MEDUSA_SUBJECT_FLAG_DEL         MEDUSA_SUBJECT_FLAG_DEL
#define MEDUSA_SUBJECT_FLAG_POLL        MEDUSA_SUBJECT_FLAG_POLL
#define MEDUSA_SUBJECT_FLAG_ROGUE       MEDUSA_SUBJECT_FLAG_ROGUE
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
