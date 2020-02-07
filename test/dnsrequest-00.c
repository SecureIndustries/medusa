
#include <stdio.h>
#include <stdlib.h>

#include <medusa/error.h>
#include <medusa/dnsrequest.h>

int main (int argc, char *argv[])
{
        struct medusa_dnsrequest *dnsrequest;
        (void) argc;
        (void) argv;
        fprintf(stderr, "start\n");
        dnsrequest = medusa_dnsrequest_create(NULL, NULL, NULL);
        if (!MEDUSA_IS_ERR_OR_NULL(dnsrequest)) {
                return -1;
        }
        fprintf(stderr, "success\n");
        return 0;
}
