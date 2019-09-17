
#if !defined(MEDUSA_CONDITION_STRUCT_H)
#define MEDUSA_CONDITION_STRUCT_H

struct medusa_monitor;
struct medusa_condition_init_options;

struct medusa_condition {
        struct medusa_subject subject;
        unsigned int flags;
        int (*onevent) (struct medusa_condition *condition, unsigned int events, void *context, void *param);
        void *context;
        unsigned int _signalled;
        unsigned int _position;
        void *userdata;
};

int medusa_condition_init (struct medusa_condition *condition, struct medusa_monitor *monitor, int (*onevent) (struct medusa_condition *condition, unsigned int events, void *context, void *param), void *context);
int medusa_condition_init_with_options (struct medusa_condition *condition, const struct medusa_condition_init_options *options);
void medusa_condition_uninit (struct medusa_condition *condition);

#endif
