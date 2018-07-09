
#include <unistd.h>

#include "medusa/time.h"
#include "medusa/subject.h"

int main (int argc, char *argv[])
{
        struct medusa_subject *subject;
        (void) argc;
        (void) argv;
        subject = medusa_subject_create_signal(-1, NULL, NULL);
        if (subject != NULL) {
                return -1;
        }
        return 0;
}
