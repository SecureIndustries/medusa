
#if !defined(MEDUSA_SUBJECT_STRUCT_H)
#define MEDUSA_SUBJECT_STRUCT_H

enum {
        MEDUSA_SUBJECT_FLAG_ALLOC               = 0x00000001,
        MEDUSA_SUBJECT_FLAG_MOD                 = 0x00000100,
        MEDUSA_SUBJECT_FLAG_DEL                 = 0x00000200,
        MEDUSA_SUBJECT_FLAG_ROGUE               = 0x00000400,
        MEDUSA_SUBJECT_FLAG_HEAP                = 0x00010000,
#define MEDUSA_SUBJECT_FLAG_ALLOC               MEDUSA_SUBJECT_FLAG_ALLOC
#define MEDUSA_SUBJECT_FLAG_MOD                 MEDUSA_SUBJECT_FLAG_MOD
#define MEDUSA_SUBJECT_FLAG_DEL                 MEDUSA_SUBJECT_FLAG_DEL
#define MEDUSA_SUBJECT_FLAG_ROGUE               MEDUSA_SUBJECT_FLAG_ROGUE
#define MEDUSA_SUBJECT_FLAG_HEAP                MEDUSA_SUBJECT_FLAG_HEAP
};

#define MEDUSA_SUBJECT_TYPE_MASK                0xff
#define MEDUSA_SUBJECT_TYPE_SHIFT               0x18

enum {
        MEDUSA_SUBJECT_TYPE_UNKNOWN             = 0,
        MEDUSA_SUBJECT_TYPE_IO                  = 1,
        MEDUSA_SUBJECT_TYPE_TIMER               = 2,
        MEDUSA_SUBJECT_TYPE_SIGNAL              = 3,
        MEDUSA_SUBJECT_TYPE_TCPSOCKET           = 4,
        MEDUSA_SUBJECT_TYPE_HTTPREQUEST         = 5,
        MEDUSA_SUBJECT_TYPE_EXEC                = 6,
#define MEDUSA_SUBJECT_TYPE_UNKNOWN             MEDUSA_SUBJECT_TYPE_UNKNOWN
#define MEDUSA_SUBJECT_TYPE_IO                  MEDUSA_SUBJECT_TYPE_IO
#define MEDUSA_SUBJECT_TYPE_TIMER               MEDUSA_SUBJECT_TYPE_TIMER
#define MEDUSA_SUBJECT_TYPE_SIGNAL              MEDUSA_SUBJECT_TYPE_SIGNAL
#define MEDUSA_SUBJECT_TYPE_TCPSOCKET           MEDUSA_SUBJECT_TYPE_TCPSOCKET
#define MEDUSA_SUBJECT_TYPE_HTTPREQUEST         MEDUSA_SUBJECT_TYPE_HTTPREQUEST
#define MEDUSA_SUBJECT_TYPE_EXEC                MEDUSA_SUBJECT_TYPE_EXEC
};

TAILQ_HEAD(medusa_subjects, medusa_subject);
struct medusa_subject {
        TAILQ_ENTRY(medusa_subject) list;
        unsigned int flags;
        struct medusa_monitor *monitor;
};

static inline void medusa_subject_set_type (struct medusa_subject *subject, unsigned int type)
{
        subject->flags = (subject->flags & ~(MEDUSA_SUBJECT_TYPE_MASK << MEDUSA_SUBJECT_TYPE_SHIFT)) |
                         ((type & MEDUSA_SUBJECT_TYPE_MASK) << MEDUSA_SUBJECT_TYPE_SHIFT);
}

static inline unsigned int medusa_subject_get_type (struct medusa_subject *subject)
{
        return (subject->flags >> MEDUSA_SUBJECT_TYPE_SHIFT) & MEDUSA_SUBJECT_TYPE_MASK;
}

#endif
