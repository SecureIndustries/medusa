
#include <stdlib.h>

#include "io.h"
#include "timer.h"
#include "event.h"
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
        subject->flags = MEDUSA_SUBJECT_FLAG_NONE;
        subject->monitor = NULL;
        return 0;
}

int medusa_subject_mod (struct medusa_subject *subject)
{
        if (subject->monitor != NULL) {
                return medusa_monitor_mod(subject);
        }
        return 0;
}

int medusa_subject_del (struct medusa_subject *subject)
{
        if (subject->monitor != NULL) {
                return medusa_monitor_del(subject);
        }
        return 0;
}

void medusa_subject_destroy (struct medusa_subject *subject)
{
        medusa_subject_del(subject);
        if (subject->event != NULL) {
                subject->event(subject, MEDUSA_EVENT_DESTROY);
        }
        subject->destroy(subject);
}
