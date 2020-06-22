
#if !defined(MEDUSA_SIGNAL_PRIVATE_H)
#define MEDUSA_SIGNAL_PRIVATE_H

struct medusa_signal;

int medusa_signal_create_singleshot_unlocked (struct medusa_monitor *monitor, int number, int (*onevent) (struct medusa_signal *signal, unsigned int events, void *context, void *param), void *context);

struct medusa_signal * medusa_signal_create_unlocked (struct medusa_monitor *monitor, int number, int (*onevent) (struct medusa_signal *signal, unsigned int events, void *context, void *param), void *context);
struct medusa_signal * medusa_signal_create_with_options_unlocked (const struct medusa_signal_init_options *options);

void medusa_signal_uninit_unlocked (struct medusa_signal *signal);
void medusa_signal_destroy_unlocked (struct medusa_signal *signal);

int medusa_signal_get_number_unlocked (const struct medusa_signal *signal);

int medusa_signal_set_singleshot_unlocked (struct medusa_signal *signal, int singleshot);
int medusa_signal_get_singleshot_unlocked (const struct medusa_signal *signal);

int medusa_signal_set_resolution_unlocked (struct medusa_signal *signal, unsigned int resolution);
unsigned int medusa_signal_get_resolution_unlocked (const struct medusa_signal *signal);

int medusa_signal_set_enabled_unlocked (struct medusa_signal *signal, int enabled);
int medusa_signal_get_enabled_unlocked (const struct medusa_signal *signal);

int medusa_signal_set_context_unlocked (struct medusa_signal *signal, void *context);
void * medusa_signal_get_context_unlocked (struct medusa_signal *signal);

int medusa_signal_set_userdata_unlocked (struct medusa_signal *signal, void *userdata);
void * medusa_signal_get_userdata_unlocked (struct medusa_signal *signal);

int medusa_signal_set_userdata_ptr_unlocked (struct medusa_signal *signal, void *userdata);
void * medusa_signal_get_userdata_ptr_unlocked (struct medusa_signal *signal);

int medusa_signal_set_userdata_int_unlocked (struct medusa_signal *signal, int userdara);
int medusa_signal_get_userdata_int_unlocked (struct medusa_signal *signal);

int medusa_signal_set_userdata_uint_unlocked (struct medusa_signal *signal, unsigned int userdata);
unsigned int medusa_signal_get_userdata_uint_unlocked (struct medusa_signal *signal);

struct medusa_monitor * medusa_signal_get_monitor_unlocked (const struct medusa_signal *signal);

int medusa_signal_onevent_unlocked (struct medusa_signal *signal, unsigned int events, void *param);
int medusa_signal_onevent (struct medusa_signal *signal, unsigned int events, void *param);

int medusa_signal_is_valid_unlocked (const struct medusa_signal *signal);

#endif
