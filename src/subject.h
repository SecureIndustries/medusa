
struct medusa_subject;
struct medusa_monitor;

enum {
        medusa_subject_type_io          = 1,
        medusa_subject_type_timer       = 2,
#define medusa_subject_type_io          medusa_subject_type_io
#define medusa_subject_type_timer       medusa_subject_type_timer
};

int medusa_subject_set (struct medusa_subject *subject, unsigned int type, int (*callback) (struct medusa_subject *subject, unsigned int events), void *context);
int medusa_subject_mod (struct medusa_subject *subject);
int medusa_subject_del (struct medusa_subject *subject);

void medusa_subject_destroy (struct medusa_subject *subject);
