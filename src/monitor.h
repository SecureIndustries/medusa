
struct medusa_subject;
struct medusa_monitor;

enum {
        medusa_monitor_backend_default,
        medusa_monitor_backend_epoll,
        medusa_monitor_backend_kqueue,
        medusa_monitor_backend_poll,
        medusa_monitor_backend_select
#define medusa_monitor_backend_default medusa_monitor_backend_default
#define medusa_monitor_backend_epoll   medusa_monitor_backend_epoll
#define medusa_monitor_backend_kqueue  medusa_monitor_backend_kqueue
#define medusa_monitor_backend_poll    medusa_monitor_backend_poll
#define medusa_monitor_backend_select  medusa_monitor_backend_select
};

enum {
        medusa_monitor_run_flag_once    = 0x00000001,
        medusa_monitor_run_flag_nowait  = 0x00000002
#define medusa_monitor_run_flag_once    medusa_monitor_run_flag_once
#define medusa_monitor_run_flag_nowait  medusa_monitor_run_flag_nowait
};

struct medusa_monitor_init_options {
        struct {
                unsigned int type;
                union {
                        struct {

                        } epoll;
                        struct {

                        } kqueue;
                        struct {

                        } poll;
                        struct {

                        } select;
                } u;
        } backend;
};

int medusa_monitor_init_options_default (struct medusa_monitor_init_options *options);

struct medusa_monitor * medusa_monitor_create (const struct medusa_monitor_init_options *options);
void medusa_monitor_destroy (struct medusa_monitor *monitor);

int medusa_monitor_add (struct medusa_monitor *monitor, struct medusa_subject *subject, ...);
int medusa_monitor_mod (struct medusa_monitor *monitor, struct medusa_subject *subject, ...);
int medusa_monitor_del (struct medusa_monitor *monitor, struct medusa_subject *subject);

int medusa_monitor_run (struct medusa_monitor *monitor, unsigned int flags);
