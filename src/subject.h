
struct medusa_subject;
struct medusa_monitor;

enum {
        MEDUSA_SUBJECT_FLAG_NONE        = 0x00000000,
        MEDUSA_SUBJECT_FLAG_IO          = 0x00000001,
        MEDUSA_SUBJECT_FLAG_TIMER       = 0x00000002,
        MEDUSA_SUBJECT_FLAG_MOD         = 0x00000100,
        MEDUSA_SUBJECT_FLAG_DEL         = 0x00000200,
        MEDUSA_SUBJECT_FLAG_POLL        = 0x00010000,
        MEDUSA_SUBJECT_FLAG_ROGUE       = 0x01000000
#define MEDUSA_SUBJECT_FLAG_IO          MEDUSA_SUBJECT_FLAG_IO
#define MEDUSA_SUBJECT_FLAG_TIMER       MEDUSA_SUBJECT_FLAG_TIMER
#define MEDUSA_SUBJECT_FLAG_NONE        MEDUSA_SUBJECT_FLAG_NONE
#define MEDUSA_SUBJECT_FLAG_MOD         MEDUSA_SUBJECT_FLAG_MOD
#define MEDUSA_SUBJECT_FLAG_DEL         MEDUSA_SUBJECT_FLAG_DEL
#define MEDUSA_SUBJECT_FLAG_POLL        MEDUSA_SUBJECT_FLAG_POLL
#define MEDUSA_SUBJECT_FLAG_ROGUE       MEDUSA_SUBJECT_FLAG_ROGUE
};

int medusa_subject_add (struct medusa_monitor *monitor, struct medusa_subject *subject);
int medusa_subject_mod (struct medusa_subject *subject);
int medusa_subject_del (struct medusa_subject *subject);

void medusa_subject_destroy (struct medusa_subject *subject);
