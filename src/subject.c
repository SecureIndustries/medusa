
#include <stdlib.h>

#include "io.h"
#include "timer.h"
#include "event.h"
#include "monitor.h"

#include "queue.h"
#include "subject-struct.h"

#include "subject.h"

void medusa_subject_destroy (struct medusa_subject *subject)
{
        if (subject->event != NULL) {
                subject->event(subject, MEDUSA_EVENT_DESTROY);
        }
        if (subject->destroy != NULL) {
                subject->destroy(subject);
        }
}
