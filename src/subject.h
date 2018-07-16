
struct medusa_subject;
struct medusa_monitor;

enum {
        MEDUSA_SUBJECT_TYPE_IO          = 1,
        MEDUSA_SUBJECT_TYPE_TIMER       = 2,
#define MEDUSA_SUBJECT_TYPE_IO          MEDUSA_SUBJECT_TYPE_IO
#define MEDUSA_SUBJECT_TYPE_TIMER       MEDUSA_SUBJECT_TYPE_TIMER
};

void medusa_subject_destroy (struct medusa_subject *subject);

int medusa_monitor_add (struct medusa_monitor *monitor, struct medusa_subject *subject);
int medusa_monitor_mod (struct medusa_subject *subject);
int medusa_monitor_del (struct medusa_subject *subject);
