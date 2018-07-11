
struct medusa_subject;
struct medusa_monitor;

enum {
        MEDUSA_SUBJECT_TYPE_IO          = 1,
        MEDUSA_SUBJECT_TYPE_TIMER       = 2,
#define MEDUSA_SUBJECT_TYPE_IO          MEDUSA_SUBJECT_TYPE_IO
#define MEDUSA_SUBJECT_TYPE_TIMER       MEDUSA_SUBJECT_TYPE_TIMER
};

int medusa_subject_set (struct medusa_subject *subject, unsigned int type, int (*event) (struct medusa_subject *subject, unsigned int events), void (*destroy) (struct medusa_subject *subject), void *context);
int medusa_subject_mod (struct medusa_subject *subject);
int medusa_subject_del (struct medusa_subject *subject);

void medusa_subject_destroy (struct medusa_subject *subject);
