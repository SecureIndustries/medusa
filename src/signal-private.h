
#if !defined(MEDUSA_SIGNAL_PRIVATE_H)
#define MEDUSA_SIGNAL_PRIVATE_H

struct medusa_signal;

void medusa_signal_uninit_unlocked (struct medusa_signal *signal);
void medusa_signal_destroy_unlocked (struct medusa_signal *signal);

int medusa_signal_get_number_unlocked (const struct medusa_signal *signal);

int medusa_signal_set_singleshot_unlocked (struct medusa_signal *signal, int singleshot);
int medusa_signal_get_singleshot_unlocked (const struct medusa_signal *signal);

int medusa_signal_set_resolution_unlocked (struct medusa_signal *signal, unsigned int resolution);
unsigned int medusa_signal_get_resolution_unlocked (const struct medusa_signal *signal);

int medusa_signal_set_enabled_unlocked (struct medusa_signal *signal, int enabled);
int medusa_signal_get_enabled_unlocked (const struct medusa_signal *signal);

struct medusa_monitor * medusa_signal_get_monitor_unlocked (const struct medusa_signal *signal);

int medusa_signal_onevent_unlocked (struct medusa_signal *signal, unsigned int events);
int medusa_signal_is_valid_unlocked (const struct medusa_signal *signal);

#endif
