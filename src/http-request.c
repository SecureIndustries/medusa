
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include "error.h"
#include "queue.h"
#include "http-request.h"
#include "http-request-struct.h"

static void header_destroy (struct medusa_http_request_header *header)
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

static struct medusa_http_request_header * header_vcreate (const char *key, const char *value, va_list ap)
{
        int size;
        va_list cp;
        struct medusa_http_request_header *header;
        size = 0;
        if (key == NULL) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (value == NULL) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        header = malloc(sizeof(struct medusa_http_request_header));
        if (header == NULL) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(header, 0, sizeof(struct medusa_http_request_header));
        header->key = strdup(key);
        if (header->key == NULL) {
                header_destroy(header);
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        va_copy(cp, ap);
        size = vsnprintf(NULL, 0, value, cp);
        va_end(cp);
        if (size < 0) {
                header_destroy(header);
                return MEDUSA_ERR_PTR(-EIO);
        }
        header->value = malloc(size + 1);
        if (header->value == NULL) {
                header_destroy(header);
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        va_copy(cp, ap);
        size = vsnprintf(header->value, size + 1, value, cp);
        va_end(cp);
        if (size < 0) {
                header_destroy(header);
                return MEDUSA_ERR_PTR(-EIO);
        }
        return header;
}

__attribute__ ((__unused__)) static struct medusa_http_request_header * header_create (const char *key, const char *value, ...)
{
        va_list ap;
        struct medusa_http_request_header *header;
        va_start(ap, value);
        header = header_vcreate(key, value, ap);
        va_end(ap);
        return header;
}

__attribute__ ((visibility ("default"))) struct medusa_http_request * medusa_http_request_create (void)
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

__attribute__ ((visibility ("default"))) void medusa_http_request_destroy (struct medusa_http_request *request)
{
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return;
        }
        medusa_http_request_reset(request);
        free(request);
}

__attribute__ ((visibility ("default"))) int medusa_http_request_reset (struct medusa_http_request *request)
{
        struct medusa_http_request_header *header;
        struct medusa_http_request_header *nheader;
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return -EINVAL;
        }
        TAILQ_FOREACH_SAFE(header, &request->headers, list, nheader) {
                TAILQ_REMOVE(&request->headers, header, list);
                header_destroy(header);
        }
        if (request->method != NULL) {
                free(request->method);
                request->method = NULL;
        }
        if (request->url != NULL) {
                free(request->url);
                request->url = NULL;
        }
        request->major = 1;
        request->minor = 0;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_http_request_set_method (struct medusa_http_request *request, const char *method, ...)
{
        int size;
        va_list ap;
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return -EINVAL;
        }
        if (method == NULL) {
                return -EINVAL;
        }
        if (request->method != NULL) {
                free(request->method);
                request->method = NULL;
        }
        va_start(ap, method);
        size = vsnprintf(NULL, 0, method, ap);
        va_end(ap);
        if (size < 0) {
                return -EIO;
        }
        request->method = malloc(size + 1);
        if (request->method == NULL) {
                return -ENOMEM;
        }
        va_start(ap, method);
        size = vsnprintf(request->method, size, method, ap);
        va_end(ap);
        if (size < 0) {
                if (request->method != NULL) {
                        free(request->method);
                        request->method = NULL;
                }
                return -EIO;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) const char * medusa_http_request_get_method (const struct medusa_http_request *request)
{
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return request->method;
}

__attribute__ ((visibility ("default"))) int medusa_http_request_set_url (struct medusa_http_request *request, const char *url, ...)
{
        int size;
        va_list ap;
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return -EINVAL;
        }
        if (url == NULL) {
                return -EINVAL;
        }
        if (request->url != NULL) {
                free(request->url);
                request->url = NULL;
        }
        va_start(ap, url);
        size = vsnprintf(NULL, 0, url, ap);
        va_end(ap);
        if (size < 0) {
                return -EIO;
        }
        request->url = malloc(size + 1);
        if (request->url == NULL) {
                return -ENOMEM;
        }
        va_start(ap, url);
        size = vsnprintf(request->url, size, url, ap);
        va_end(ap);
        if (size < 0) {
                if (request->url != NULL) {
                        free(request->url);
                        request->url = NULL;
                }
                return -EIO;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) const char * medusa_http_request_get_url (const struct medusa_http_request *request)
{
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return request->url;
}

__attribute__ ((visibility ("default"))) int medusa_http_request_set_version (struct medusa_http_request *request, int major, int minor)
{
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return -EINVAL;
        }
        request->major = major;
        request->minor = minor;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_http_request_get_version_major (const struct medusa_http_request *request)
{
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return -EINVAL;
        }
        return request->major;
}

__attribute__ ((visibility ("default"))) int medusa_http_request_get_version_minor (const struct medusa_http_request *request)
{
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return -EINVAL;
        }
        return request->minor;
}

__attribute__ ((visibility ("default"))) int medusa_http_request_add_header (struct medusa_http_request *request, const char *key, const char *value, ...)
{
        va_list ap;
        struct medusa_http_request_header *header;
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(key)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(value)) {
                return -EINVAL;
        }
        va_start(ap, value);
        header = header_vcreate(key, value, ap);
        va_end(ap);
        if (MEDUSA_IS_ERR_OR_NULL(header)) {
                return MEDUSA_PTR_ERR(header);
        }
        TAILQ_INSERT_TAIL(&request->headers, header, list);
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_http_request_del_header (struct medusa_http_request *request, const char *key)
{
        struct medusa_http_request_header *header;
        struct medusa_http_request_header *nheader;
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

__attribute__ ((visibility ("default"))) const char * medusa_http_request_get_header_value (const struct medusa_http_request *request, const char *key)
{
        struct medusa_http_request_header *header;
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(key)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        TAILQ_FOREACH(header, &request->headers, list) {
                if (strcasecmp(header->key, key) == 0) {
                        return header->value;
                }
        }
        return MEDUSA_ERR_PTR(-ENOENT);
}

__attribute__ ((visibility ("default"))) int medusa_http_request_set_callback (struct medusa_http_request *request, const struct medusa_http_request_callback *callback, void *context)
{
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(callback)) {
                return -EINVAL;
        }
        memcpy(&request->callback, callback, sizeof(struct medusa_http_request_callback));
        request->callback_context = context;
        return 0;
}

int medusa_http_request_is_valid (const struct medusa_http_request *request)
{
        if (MEDUSA_IS_ERR_OR_NULL(request)) {
                return 0;
        }
        if (MEDUSA_IS_ERR_OR_NULL(request->method)) {
                return 0;
        }
        if (MEDUSA_IS_ERR_OR_NULL(request->url)) {
                return 0;
        }
        return 1;
}
