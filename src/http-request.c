
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "error.h"
#include "queue.h"
#include "http-request.h"

TAILQ_HEAD(headers, header);
struct header {
        TAILQ_ENTRY(header) list;
        char *key;
        char *value;
};

struct medusa_http_request {
        char *method;
        char *url;
        int major;
        int minor;
        struct headers headers;
        struct medusa_http_request_callback callback;
        void *context;
};

static void header_destroy (struct header *header)
{
        if (header == NULL) {
                return;
        }
        if (header->key != NULL) {
                free(header->key);
        }
        if (header->value != NULL) {
                free(header->value);
        }
        free(header);
}

static struct header * header_create (const char *key, const char *value)
{
        struct header *header;
        if (key == NULL) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (value == NULL) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        header = malloc(sizeof(struct header));
        if (header == NULL) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(header, 0, sizeof(struct header));
        header->key = strdup(key);
        if (header->key == NULL) {
                header_destroy(header);
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        header->value = strdup(value);
        if (header->value == NULL) {
                header_destroy(header);
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        return header;
}

struct medusa_http_request * medusa_http_request_create (void)
{
        struct medusa_http_request *request;
        request = malloc(sizeof(struct medusa_http_request));
        if (request == NULL) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(request, 0, sizeof(struct medusa_http_request));
        request->major = 1;
        request->minor = 0;
        TAILQ_INIT(&request->headers);
        return request;
}

void medusa_http_request_destroy (struct medusa_http_request *request)
{
        struct header *header;
        struct header *nheader;
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return;
        }
        TAILQ_FOREACH_SAFE(header, &request->headers, list, nheader) {
                TAILQ_REMOVE(&request->headers, header, list);
                header_destroy(header);
        }
        if (request->method != NULL) {
                free(request->method);
        }
        if (request->url != NULL) {
                free(request->url);
        }
        free(request);
}

int medusa_http_request_set_method (struct medusa_http_request *request, const char *method)
{
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return -EINVAL;
        }
        if (method == NULL) {
                return -EINVAL;
        }
        if (request->method != NULL) {
                free(request->method);
        }
        request->method = strdup(method);
        if (request->method == NULL) {
                return -ENOMEM;
        }
        return 0;
}

int medusa_http_request_set_url (struct medusa_http_request *request, const char *url)
{
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return -EINVAL;
        }
        if (url == NULL) {
                return -EINVAL;
        }
        if (request->url != NULL) {
                free(request->url);
        }
        request->url = strdup(url);
        if (request->url == NULL) {
                return -ENOMEM;
        }
        return 0;
}

int medusa_http_request_set_version (struct medusa_http_request *request, int major, int minor)
{
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return -EINVAL;
        }
        request->major = major;
        request->minor = minor;
        return 0;
}

int medusa_http_request_add_header (struct medusa_http_request *request, const char *key, const char *value)
{
        struct header *header;
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(key)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(value)) {
                return -EINVAL;
        }
        header = header_create(key, value);
        if (MEDUSA_IS_ERR_OR_NULL(header)) {
                return MEDUSA_PTR_ERR(header);
        }
        TAILQ_INSERT_TAIL(&request->headers, header, list);
        return 0;
}

int medusa_http_request_del_header (struct medusa_http_request *request, const char *key)
{
        struct header *header;
        struct header *nheader;
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(key)) {
                return -EINVAL;
        }
        TAILQ_FOREACH_SAFE(header, &request->headers, list, nheader) {
                if (strcasecmp(header->key, key) == 0) {
                        TAILQ_REMOVE(&request->headers, header, list);
                        header_destroy(header);
                }
        }
        return 0;
}

int medusa_http_request_set_callback (struct medusa_http_request *request, const struct medusa_http_request_callback *callback, void *context)
{
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(callback)) {
                return -EINVAL;
        }
        memcpy(&request->callback, callback, sizeof(struct medusa_http_request_callback));
        request->context = context;
        return 0;
}
