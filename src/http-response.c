
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include "error.h"
#include "queue.h"
#include "http-response.h"
#include "http-response-struct.h"

static void header_destroy (struct medusa_http_response_header *header)
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

static struct medusa_http_response_header * header_vcreate (const char *key, const char *value, va_list ap)
{
        int size;
        va_list cp;
        struct medusa_http_response_header *header;
        size = 0;
        if (key == NULL) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (value == NULL) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        header = malloc(sizeof(struct medusa_http_response_header));
        if (header == NULL) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(header, 0, sizeof(struct medusa_http_response_header));
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

__attribute__ ((__unused__)) static struct medusa_http_response_header * header_create (const char *key, const char *value, ...)
{
        va_list ap;
        struct medusa_http_response_header *header;
        va_start(ap, value);
        header = header_vcreate(key, value, ap);
        va_end(ap);
        return header;
}

__attribute__ ((visibility ("default"))) struct medusa_http_response * medusa_http_response_create (void)
{
        struct medusa_http_response *response;
        response = malloc(sizeof(struct medusa_http_response));
        if (response == NULL) {
                return MEDUSA_ERR_PTR(-ENOMEM);
        }
        memset(response, 0, sizeof(struct medusa_http_response));
        response->major = 1;
        response->minor = 0;
        TAILQ_INIT(&response->headers);
        return response;
}

__attribute__ ((visibility ("default"))) void medusa_http_response_destroy (struct medusa_http_response *response)
{
        if (MEDUSA_IS_ERR_OR_NULL(response)) {
                return;
        }
        medusa_http_response_reset(response);
        free(response);
}

__attribute__ ((visibility ("default"))) int medusa_http_response_reset (struct medusa_http_response *response)
{
        struct medusa_http_response_header *header;
        struct medusa_http_response_header *nheader;
        if (MEDUSA_IS_ERR_OR_NULL(response)) {
                return -EINVAL;
        }
        TAILQ_FOREACH_SAFE(header, &response->headers, list, nheader) {
                TAILQ_REMOVE(&response->headers, header, list);
                header_destroy(header);
        }
        response->code = 0;
        if (response->reason != NULL) {
                free(response->reason);
                response->reason = NULL;
        }
        response->major = 1;
        response->minor = 0;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_http_response_set_status (struct medusa_http_response *response, int code, const char *reason, ...)
{
        int size;
        va_list ap;
        if (MEDUSA_IS_ERR_OR_NULL(response)) {
                return -EINVAL;
        }
        response->code = code;
        if (response->reason != NULL) {
                free(response->reason);
                response->reason = NULL;
        }
        if (reason == NULL) {
                return 0;
        }
        va_start(ap, reason);
        size = vsnprintf(NULL, 0, reason, ap);
        va_end(ap);
        if (size < 0) {
                return -EIO;
        }
        response->reason = malloc(size + 1);
        if (response->reason == NULL) {
                return -ENOMEM;
        }
        va_start(ap, reason);
        size = vsnprintf(response->reason, size + 1, reason, ap);
        va_end(ap);
        if (size < 0) {
                if (response->reason != NULL) {
                        free(response->reason);
                        response->reason = NULL;
                }
                return -EIO;
        }
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_http_response_get_status_code (const struct medusa_http_response *response)
{
        if (MEDUSA_IS_ERR_OR_NULL(response)) {
                return -EINVAL;
        }
        return response->code;
}

__attribute__ ((visibility ("default"))) const char * medusa_http_response_get_status_reason (const struct medusa_http_response *response)
{
        if (MEDUSA_IS_ERR_OR_NULL(response)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        return response->reason;
}

__attribute__ ((visibility ("default"))) int medusa_http_response_set_version (struct medusa_http_response *response, int major, int minor)
{
        if (MEDUSA_IS_ERR_OR_NULL(response)) {
                return -EINVAL;
        }
        response->major = major;
        response->minor = minor;
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_http_response_get_version_major (const struct medusa_http_response *response)
{
        if (MEDUSA_IS_ERR_OR_NULL(response)) {
                return -EINVAL;
        }
        return response->major;
}

__attribute__ ((visibility ("default"))) int medusa_http_response_get_version_minor (const struct medusa_http_response *response)
{
        if (MEDUSA_IS_ERR_OR_NULL(response)) {
                return -EINVAL;
        }
        return response->minor;
}

__attribute__ ((visibility ("default"))) int medusa_http_response_add_header (struct medusa_http_response *response, const char *key, const char *value, ...)
{
        va_list ap;
        struct medusa_http_response_header *header;
        if (MEDUSA_IS_ERR_OR_NULL(response)) {
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
        TAILQ_INSERT_TAIL(&response->headers, header, list);
        return 0;
}

__attribute__ ((visibility ("default"))) int medusa_http_response_del_header (struct medusa_http_response *response, const char *key)
{
        struct medusa_http_response_header *header;
        struct medusa_http_response_header *nheader;
        if (MEDUSA_IS_ERR_OR_NULL(response)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(key)) {
                return -EINVAL;
        }
        TAILQ_FOREACH_SAFE(header, &response->headers, list, nheader) {
                if (strcasecmp(header->key, key) == 0) {
                        TAILQ_REMOVE(&response->headers, header, list);
                        header_destroy(header);
                }
        }
        return 0;
}

__attribute__ ((visibility ("default"))) const char * medusa_http_response_get_header_value (const struct medusa_http_response *response, const char *key)
{
        struct medusa_http_response_header *header;
        if (MEDUSA_IS_ERR_OR_NULL(response)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        if (MEDUSA_IS_ERR_OR_NULL(key)) {
                return MEDUSA_ERR_PTR(-EINVAL);
        }
        TAILQ_FOREACH(header, &response->headers, list) {
                if (strcasecmp(header->key, key) == 0) {
                        return header->value;
                }
        }
        return MEDUSA_ERR_PTR(-ENOENT);
}

__attribute__ ((visibility ("default"))) int medusa_http_response_set_callback (struct medusa_http_response *response, const struct medusa_http_response_callback *callback, void *context)
{
        if (MEDUSA_IS_ERR_OR_NULL(response)) {
                return -EINVAL;
        }
        if (MEDUSA_IS_ERR_OR_NULL(callback)) {
                return -EINVAL;
        }
        memcpy(&response->callback, callback, sizeof(struct medusa_http_response_callback));
        response->callback_context = context;
        return 0;
}

int medusa_http_response_is_valid (const struct medusa_http_response *response)
{
        if (MEDUSA_IS_ERR_OR_NULL(response)) {
                return 0;
        }
        if (response->code <= 0) {
        	return 0;
        }
        return 1;
}
