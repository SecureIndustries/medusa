
#if !defined(MEDUSA_CONDITION_H)
#define MEDUSA_CONDITION_H

enum {
        MEDUSA_CONDITION_EVENT_SIGNAL   = (1 << 0), /* 0x00000001 */
        MEDUSA_CONDITION_EVENT_DESTROY  = (1 << 1), /* 0x00000002 */
#define MEDUSA_CONDITION_EVENT_SIGNAL   MEDUSA_CONDITION_EVENT_SIGNAL
#define MEDUSA_CONDITION_EVENT_DESTROY  MEDUSA_CONDITION_EVENT_DESTROY
};

struct medusa_condition;
struct medusa_monitor;

struct medusa_condition_init_options {
        struct medusa_monitor *monitor;
        int (*onevent) (struct medusa_condition *condition, unsigned int events, void *context, ...);
        void *context;
        int enabled;
};

#ifdef __cplusplus
extern "C"
{
#endif

int medusa_condition_init_options_default (struct medusa_condition_init_options *options);

struct medusa_condition * medusa_condition_create (struct medusa_monitor *monitor, int (*onevent) (struct medusa_condition *condition, unsigned int events, void *context, ...), void *context);
struct medusa_condition * medusa_condition_create_with_options (const struct medusa_condition_init_options *options);
void medusa_condition_destroy (struct medusa_condition *condition);

int medusa_condition_signal (struct medusa_condition *condition);
int medusa_condition_set_signalled (struct medusa_condition *condition, int signalled);
int medusa_condition_get_signalled (const struct medusa_condition *condition);

int medusa_condition_set_enabled (struct medusa_condition *condition, int enabled);
int medusa_condition_get_enabled (const struct medusa_condition *condition);

int medusa_condition_enable (struct medusa_condition *condition);
int medusa_condition_disable (struct medusa_condition *condition);

int medusa_condition_set_userdata (struct medusa_condition *condition, void *userdata);
void * medusa_condition_get_userdata (struct medusa_condition *condition);

int medusa_condition_set_userdata_ptr (struct medusa_condition *condition, void *userdata);
void * medusa_condition_get_userdata_ptr (struct medusa_condition *condition);

int medusa_condition_set_userdata_int (struct medusa_condition *condition, int userdara);
int medusa_condition_get_userdata_int (struct medusa_condition *condition);

int medusa_condition_set_userdata_uint (struct medusa_condition *condition, unsigned int userdata);
unsigned int medusa_condition_get_userdata_uint (struct medusa_condition *condition);

struct medusa_monitor * medusa_condition_get_monitor (const struct medusa_condition *condition);

const char * medusa_condition_event_string (unsigned int events);

#ifdef __cplusplus
}
#endif

#endif
