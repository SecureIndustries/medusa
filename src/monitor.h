
struct medusa_monitor;

enum {
	medusa_monitor_backend_epoll,
	medusa_monitor_backend_kqueue,
	medusa_monitor_backend_poll,
	medusa_monitor_backend_select
};

struct medusa_monitor_init_options {
	unsigned int backend;
};

struct medusa_monitor * medusa_monitor_create (const struct medusa_monitor_init_options *options);
void medusa_monitor_destroy (struct medusa_monitor *monitor);

int medusa_monitor_add (struct medusa_monitor *monitor, struct medusa_subject *subject);
int medusa_monitor_mod (struct medusa_monitor *monitor, struct medusa_subject *subject);
int medusa_monitor_del (struct medusa_monitor *monitor, struct medusa_subject *subject);
