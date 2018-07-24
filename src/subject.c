
#include <stdlib.h>

#include "io.h"
#include "timer.h"
#include "monitor.h"

#include "queue.h"
#include "subject-struct.h"

#include "subject.h"

void medusa_subject_destroy (struct medusa_subject *subject)
{
        if (subject->event != NULL) {
                if (subject->flags & MEDUSA_SUBJECT_FLAG_IO) {
                        subject->event(subject, MEDUSA_IO_EVENT_DESTROY);
                } else if (subject->flags & MEDUSA_SUBJECT_FLAG_TIMER) {
                        subject->event(subject, MEDUSA_TIMER_EVENT_DESTROY);
                }
        }
        if (subject->destroy != NULL) {
                subject->destroy(subject);
        }
}
