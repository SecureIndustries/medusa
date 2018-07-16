
struct medusa_subject;
struct medusa_monitor;

enum {
        MEDUSA_SUBJECT_TYPE_IO          = 1,
        MEDUSA_SUBJECT_TYPE_TIMER       = 2,
#define MEDUSA_SUBJECT_TYPE_IO          MEDUSA_SUBJECT_TYPE_IO
#define MEDUSA_SUBJECT_TYPE_TIMER       MEDUSA_SUBJECT_TYPE_TIMER
};

int medusa_subject_add (struct medusa_monitor *monitor, struct medusa_subject *subject);
int medusa_subject_mod (struct medusa_subject *subject);
int medusa_subject_del (struct medusa_subject *subject);

void medusa_subject_destroy (struct medusa_subject *subject);
