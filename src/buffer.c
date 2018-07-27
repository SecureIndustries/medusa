
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

#include "buffer.h"
#include "buffer-struct.h"

int medusa_buffer_resize (struct medusa_buffer *buffer, int64_t size)
{
	void *data;
	if (buffer == NULL) {
		return -1;
	}
	if (buffer->size >= size) {
		return 0;
	}
	data = realloc(buffer->buffer, size);
	if (data == NULL) {
		data = malloc(size);
		if (data == NULL) {
			return -1;
		}
		if (buffer->length > 0) {
			memcpy(data, buffer->buffer, buffer->length);
		}
		free(buffer->buffer);
		buffer->buffer = data;
	} else {
		buffer->buffer = data;
	}
	buffer->size = size;
	return 0;
}

int medusa_buffer_grow (struct medusa_buffer *buffer, int64_t size)
{
	return medusa_buffer_resize(buffer, medusa_buffer_length(buffer) + size);
}

void medusa_buffer_reset (struct medusa_buffer *buffer)
{
	if (buffer == NULL) {
		return;
	}
	buffer->length = 0;
}

void * medusa_buffer_base (const struct medusa_buffer *buffer)
{
	if (buffer == NULL) {
		return NULL;
	}
	return buffer->buffer;
}

int64_t medusa_buffer_length (const struct medusa_buffer *buffer)
{
	if (buffer == NULL) {
		return -1;
	}
	return buffer->length;
}

int medusa_buffer_set_length (struct medusa_buffer *buffer, int64_t length)
{
	if (buffer == NULL) {
		return -1;
	}
	if (length > buffer->size) {
		return -1;
	}
	buffer->length = length;
	return 0;
}

int medusa_buffer_push (struct medusa_buffer *buffer, const void *data, int64_t length)
{
	int rc;
	if (buffer == NULL) {
		return -1;
	}
	if (length < 0) {
		return -1;
	}
	if (length == 0) {
		return 0;
	}
	if (data == NULL) {
		return -1;
	}
	rc = medusa_buffer_resize(buffer, buffer->length + length);
	if (rc != 0) {
		return -1;
	}
	memcpy(buffer->buffer + buffer->length, data, length);
	buffer->length += length;
	return 0;
}

int medusa_buffer_printf (struct medusa_buffer *buffer, const char *format, ...)
{
	int rc;
	int size;
	va_list va;
	va_start(va, format);
	if (buffer == NULL) {
		goto bail;
	}
	if (format == NULL) {
		goto bail;
	}
	size = vsnprintf(NULL, 0, format, va);
	if (size < 0) {
		goto bail;
	}
	rc = medusa_buffer_grow(buffer, size + 1);
	if (rc != 0) {
		goto bail;
	}
	va_end(va);
	va_start(va, format);
	rc = vsnprintf(medusa_buffer_base(buffer) + medusa_buffer_length(buffer), size + 1, format, va);
	if (rc <= 0) {
		goto bail;
	}
	buffer->length += rc;
	va_end(va);
	return 0;
bail:	va_end(va);
	return -1;
}

int medusa_buffer_vprintf (struct medusa_buffer *buffer, const char *format, va_list va)
{
	int rc;
	int size;
	va_list vs;
	if (buffer == NULL) {
		goto bail;
	}
	va_copy(vs, va);
	size = vsnprintf(NULL, 0, format, vs);
	if (size < 0) {
		goto bail;
	}
	rc = medusa_buffer_grow(buffer, size + 1);
	if (rc != 0) {
		goto bail;
	}
	va_copy(vs, va);
	rc = vsnprintf(medusa_buffer_base(buffer) + medusa_buffer_length(buffer), size + 1, format, vs);
	if (rc <= 0) {
		goto bail;
	}
	buffer->length += rc;
	return 0;
bail:	return -1;
}

int medusa_buffer_eat (struct medusa_buffer *buffer, int64_t length)
{
	if (buffer == NULL) {
		return -1;
	}
	if (length < 0) {
		length = buffer->length;
	}
	if (buffer->length < length) {
		length = buffer->length;
	}
	if (buffer->length > length) {
		memmove(buffer->buffer, buffer->buffer + length, buffer->length - length);
		buffer->length -= length;
	} else {
		buffer->length = 0;
	}
	return 0;
}

int64_t medusa_buffer_size (const struct medusa_buffer *buffer)
{
	if (buffer == NULL) {
		return -1;
	}
	return buffer->size;
}

int medusa_buffer_init (struct medusa_buffer *buffer)
{
        if (buffer == NULL) {
                return -1;
        }
        memset(buffer, 0, sizeof(struct medusa_buffer));
        return 0;
}

void medusa_buffer_uninit (struct medusa_buffer *buffer)
{
        if (buffer == NULL) {
                return;
        }
        if (buffer->buffer != NULL) {
                free(buffer->buffer);
        }
}

void medusa_buffer_destroy (struct medusa_buffer *buffer)
{
        if (buffer == NULL) {
                return;
        }
        if (buffer->buffer != NULL) {
                free(buffer->buffer);
        }
	free(buffer);
}

struct medusa_buffer * medusa_buffer_create (void)
{
	struct medusa_buffer *buffer;
	buffer = malloc(sizeof(struct medusa_buffer));
	if (buffer == NULL) {
		goto bail;
	}
	memset(buffer, 0, sizeof(struct medusa_buffer));
	return buffer;
bail:	if (buffer != NULL) {
		medusa_buffer_destroy(buffer);
	}
	return NULL;
}
