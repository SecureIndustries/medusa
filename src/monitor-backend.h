
struct medusa_monitor_backend {
	const char *name;
	int (*add) (struct medusa_monitor_backend *backend, struct medusa_subject *subject, unsigned int events);
	int (*mod) (struct medusa_monitor_backend *backend, struct medusa_subject *subject, unsigned int events);
	int (*del) (struct medusa_monitor_backend *backend, struct medusa_subject *subject);
	void (*destroy) (struct medusa_monitor_backend *backend);
};
