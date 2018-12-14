
#include <stdio.h>
#include <stdlib.h>

#include <medusa/error.h>
#include <medusa/httprequest.h>

int main (int argc, char *argv[])
{
        struct medusa_httprequest *httprequest;
        (void) argc;
        (void) argv;
        fprintf(stderr, "start\n");
        httprequest = medusa_httprequest_create(NULL, NULL, NULL);
        if (!MEDUSA_IS_ERR_OR_NULL(httprequest)) {
                return -1;
        }
        fprintf(stderr, "success\n");
        return 0;
}
