
#if !defined(MEDUSA_EXEC_PRIVATE_H)
#define MEDUSA_EXEC_PRIVATE_H

struct medusa_exec;

int medusa_exec_init_unlocked (struct medusa_exec *exec, struct medusa_monitor *monitor, const char *argv[], int (*onevent) (struct medusa_exec *exec, unsigned int events, void *context, void *param), void *context);
int medusa_exec_init_with_options_unlocked (struct medusa_exec *exec, const struct medusa_exec_init_options *options);

struct medusa_exec * medusa_exec_create_unlocked (struct medusa_monitor *monitor, const char *argv[], int (*onevent) (struct medusa_exec *exec, unsigned int events, void *context, void *param), void *context);
struct medusa_exec * medusa_exec_create_with_options_unlocked (const struct medusa_exec_init_options *options);

void medusa_exec_uninit_unlocked (struct medusa_exec *exec);
void medusa_exec_destroy_unlocked (struct medusa_exec *exec);

int medusa_exec_get_pid_unlocked (const struct medusa_exec *exec);
int medusa_exec_get_wstatus_unlocked (const struct medusa_exec *exec);

int medusa_exec_set_enabled_unlocked (struct medusa_exec *exec, int enabled);
int medusa_exec_get_enabled_unlocked (const struct medusa_exec *exec);

void * medusa_exec_get_userdata_unlocked (struct medusa_exec *exec);
int medusa_exec_set_userdata_unlocked (struct medusa_exec *exec, void *userdata);

struct medusa_monitor * medusa_exec_get_monitor_unlocked (const struct medusa_exec *exec);

int medusa_exec_onevent_unlocked (struct medusa_exec *exec, unsigned int events, void *param);
int medusa_exec_onevent (struct medusa_exec *exec, unsigned int events, void *param);

int medusa_exec_is_valid_unlocked (const struct medusa_exec *exec);

#endif
