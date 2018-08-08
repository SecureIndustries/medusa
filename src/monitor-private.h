
#if !defined(MEDUSA_MONITOR_PRIVATE_H)
#define MEDUSA_MONITOR_PRIVATE_H

struct medusa_subject;
struct medusa_monitor;

int medusa_monitor_add (struct medusa_monitor *monitor, struct medusa_subject *subject);
int medusa_monitor_mod (struct medusa_subject *subject);
int medusa_monitor_del (struct medusa_subject *subject);

#endif
