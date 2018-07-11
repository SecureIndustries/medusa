
#include "event.h"
#include "queue.h"
#include "subject.h"
#include "subject-struct.h"
#include "io.h"
#include "timer.h"
#include "monitor.h"

int medusa_subject_set (struct medusa_subject *subject, unsigned int type, int (*callback) (struct medusa_subject *subject, unsigned int events), void *context)
{
        subject->type = type;
        subject->callback = callback;
        subject->context = context;
        subject->flags = 0;
        subject->monitor = 0;
        return 0;
}

int medusa_subject_mod (struct medusa_subject *subject)
{
        if (subject->monitor != 0) {
                return medusa_monitor_mod(subject->monitor, subject);
        }
        return 0;
}

int medusa_subject_del (struct medusa_subject *subject)
{
        if (subject->monitor != 0) {
                return medusa_monitor_del(subject->monitor, subject);
        }
        return 0;
}

void medusa_subject_destroy (struct medusa_subject *subject)
{
        if (subject->type == medusa_subject_type_io) {
                medusa_io_destroy((struct medusa_io *) subject);
        } else if (subject->type == medusa_subject_type_timer) {
                medusa_timer_destroy((struct medusa_timer *) subject);
        }
}
