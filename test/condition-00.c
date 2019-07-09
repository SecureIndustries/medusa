
#include <stdio.h>
#include <unistd.h>

#include "medusa/error.h"
#include "medusa/condition.h"

int main (int argc, char *argv[])
{
        struct medusa_condition *condition;
        (void) argc;
        (void) argv;
        condition = medusa_condition_create(NULL, NULL, NULL);
        if (!MEDUSA_IS_ERR_OR_NULL(condition)) {
                fprintf(stderr, "error\n");
                return -1;
        }
        fprintf(stderr, "success\n");
        return 0;
}
