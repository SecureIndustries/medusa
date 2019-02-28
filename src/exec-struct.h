
#if !defined(MEDUSA_exec_STRUCT_H)
#define MEDUSA_exec_STRUCT_H

struct medusa_monitor;
struct medusa_exec_init_options;
struct medusa_exec;

struct medusa_exec {
        struct medusa_subject subject;
        unsigned int flags;
        char **argv;
        int (*onevent) (struct medusa_exec *exec, unsigned int events, void *context, ...);
        void *context;
        pid_t pid;
};

int medusa_exec_init (struct medusa_exec *exec, struct medusa_monitor *monitor, const char *argv[], int (*onevent) (struct medusa_exec *exec, unsigned int events, void *context, ...), void *context);
int medusa_exec_init_with_options (struct medusa_exec *exec, const struct medusa_exec_init_options *options);
void medusa_exec_uninit (struct medusa_exec *exec);

#endif
