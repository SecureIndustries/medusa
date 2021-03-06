
#if !defined(MEDUSA_CONDITION_PRIVATE_H)
#define MEDUSA_CONDITION_PRIVATE_H

struct medusa_condition;

struct medusa_condition * medusa_condition_create_unlocked (struct medusa_monitor *monitor, int (*onevent) (struct medusa_condition *condition, unsigned int events, void *context, void *param), void *context);
struct medusa_condition * medusa_condition_create_with_options_unlocked (const struct medusa_condition_init_options *options);
void medusa_condition_destroy_unlocked (struct medusa_condition *condition);

int medusa_condition_signal_unlocked (struct medusa_condition *condition);
int medusa_condition_set_signalled_unlocked (struct medusa_condition *condition, int signalled);
int medusa_condition_get_signalled_unlocked (const struct medusa_condition *condition);

int medusa_condition_set_enabled_unlocked (struct medusa_condition *condition, int enabled);
int medusa_condition_get_enabled_unlocked (const struct medusa_condition *condition);

int medusa_condition_set_context_unlocked (struct medusa_condition *condition, void *context);
void * medusa_condition_get_context_unlocked (struct medusa_condition *condition);

int medusa_condition_set_userdata_unlocked (struct medusa_condition *condition, void *userdata);
void * medusa_condition_get_userdata_unlocked (struct medusa_condition *condition);

int medusa_condition_set_userdata_ptr_unlocked (struct medusa_condition *condition, void *userdata);
void * medusa_condition_get_userdata_ptr_unlocked (struct medusa_condition *condition);

int medusa_condition_set_userdata_int_unlocked (struct medusa_condition *condition, int userdara);
int medusa_condition_get_userdata_int_unlocked (struct medusa_condition *condition);

int medusa_condition_set_userdata_uint_unlocked (struct medusa_condition *condition, unsigned int userdata);
unsigned int medusa_condition_get_userdata_uint_unlocked (struct medusa_condition *condition);

struct medusa_monitor * medusa_condition_get_monitor_unlocked (const struct medusa_condition *condition);

int medusa_condition_onevent_unlocked (struct medusa_condition *condition, unsigned int events, void *param);
int medusa_condition_is_valid_unlocked (const struct medusa_condition *condition);

#endif
