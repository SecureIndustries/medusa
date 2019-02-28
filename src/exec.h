
#if !defined(MEDUSA_EXEC_H)
#define MEDUSA_EXEC_H

struct medusa_exec;
struct medusa_monitor;

enum {
        MEDUSA_EXEC_EVENT_NONE          = 0x00000000,
        MEDUSA_EXEC_EVENT_STARTED       = 0x00000001,
        MEDUSA_EXEC_EVENT_STOPPED       = 0x00000002,
        MEDUSA_EXEC_EVENT_DESTROY       = 0x00000004
#define MEDUSA_EXEC_EVENT_NONE          MEDUSA_EXEC_EVENT_NONE
#define MEDUSA_EXEC_EVENT_STARTED       MEDUSA_EXEC_EVENT_STARTED
#define MEDUSA_EXEC_EVENT_STOPPED       MEDUSA_EXEC_EVENT_STOPPED
#define MEDUSA_EXEC_EVENT_DESTROY MEDUSA_EXEC_EVENT_DESTROY
};

struct medusa_exec_init_options {
        struct medusa_monitor *monitor;
        const char **argv;
        int (*onevent) (struct medusa_exec *exec, unsigned int events, void *context, ...);
        void *context;
        unsigned int events;
        int enabled;
};

#ifdef __cplusplus
extern "C"
{
#endif

int medusa_exec_init_options_default (struct medusa_exec_init_options *options);

struct medusa_exec * medusa_exec_create (struct medusa_monitor *monitor, const char *argv[], int (*onevent) (struct medusa_exec *exec, unsigned int events, void *context, ...), void *context);
struct medusa_exec * medusa_exec_create_with_options (const struct medusa_exec_init_options *options);
void medusa_exec_destroy (struct medusa_exec *exec);

int medusa_exec_get_pid (const struct medusa_exec *exec);

int medusa_exec_set_enabled (struct medusa_exec *exec, int enabled);
int medusa_exec_get_enabled (const struct medusa_exec *exec);

int medusa_exec_enable (struct medusa_exec *exec);
int medusa_exec_disable (struct medusa_exec *exec);

int medusa_exec_start (struct medusa_exec *exec);
int medusa_exec_stop (struct medusa_exec *exec);

struct medusa_monitor * medusa_exec_get_monitor (const struct medusa_exec *exec);

#ifdef __cplusplus
}
#endif

#endif
