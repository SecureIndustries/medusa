
struct medusa_monitor;

struct medusa_monitor_create_options {

};

struct medusa_monitor * medusa_monitor_create (struct medusa_monitor_create_options *options);
void medusa_monitor_destroy (struct medusa_monitor *monitor);

int medusa_monitor_add (struct medusa_monitor *monitor, struct medusa_subject *subject);
int medusa_monitor_mod (struct medusa_monitor *monitor, struct medusa_subject *subject);
int medusa_monitor_del (struct medusa_monitor *monitor, struct medusa_subject *subject);
