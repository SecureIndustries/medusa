
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "queue.h"

#include "subject.h"
#include "monitor.h"

#include "subject-private.h"

#include "monitor-epoll.h"
#include "monitor-kqueue.h"
#include "monitor-poll.h"
#include "monitor-select.h"
#include "monitor-backend.h"

struct medusa_monitor {
	struct medusa_subjects subjects;
	struct medusa_monitor_backend *backend;
};

struct medusa_monitor * medusa_monitor_create (const struct medusa_monitor_init_options *options)
{
	struct medusa_monitor *monitor;
	(void) options;
	monitor = NULL;
	monitor = malloc(sizeof(struct medusa_monitor));
	if (monitor == NULL) {
		goto bail;
	}
	memset(monitor, 0, sizeof(struct medusa_monitor));
	TAILQ_INIT(&monitor->subjects);
	return monitor;
bail:	if (monitor != NULL) {
		medusa_monitor_destroy(monitor);
	}
	return NULL;
}

void medusa_monitor_destroy (struct medusa_monitor *monitor)
{
	struct medusa_subject *subject;
	struct medusa_subject *nsubject;
	if (monitor == NULL) {
		return;
	}
	TAILQ_FOREACH_SAFE(subject, &monitor->subjects, subjects, nsubject) {
		TAILQ_REMOVE(&monitor->subjects, subject, subjects);
		medusa_subject_destroy(subject);
	}
	if (monitor->backend != NULL) {
		monitor->backend->destroy(monitor->backend);
	}
	free(monitor);
}

int medusa_monitor_add (struct medusa_monitor *monitor, struct medusa_subject *subject)
{
	int rc;
	if (monitor == NULL) {
		goto bail;
	}
	if (subject == NULL) {
		goto bail;
	}
	rc = medusa_subject_retain(subject);
	if (rc != 0) {
		goto bail;
	}
	TAILQ_INSERT_TAIL(&monitor->subjects, subject, subjects);
	return 0;
bail:	return -1;
}

int medusa_monitor_mod (struct medusa_monitor *monitor, struct medusa_subject *subject)
{
	if (monitor == NULL) {
		goto bail;
	}
	if (subject == NULL) {
		goto bail;
	}
	return 0;
bail:	return -1;
}

int medusa_monitor_del (struct medusa_monitor *monitor, struct medusa_subject *subject)
{
	if (monitor == NULL) {
		goto bail;
	}
	if (subject == NULL) {
		goto bail;
	}
	TAILQ_REMOVE(&monitor->subjects, subject, subjects);
	medusa_subject_destroy(subject);
	return 0;
bail:	return -1;
}
