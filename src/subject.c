
#include "io.h"
#include "timer.h"
#include "monitor.h"

#include "queue.h"
#include "subject-struct.h"

#include "subject.h"

int medusa_subject_set (struct medusa_subject *subject, unsigned int type, int (*event) (struct medusa_subject *subject, unsigned int events), void (*destroy) (struct medusa_subject *subject), void *context)
{
        subject->type = type;
        subject->event = event;
        subject->destroy = destroy;
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
        subject->destroy(subject);
}
