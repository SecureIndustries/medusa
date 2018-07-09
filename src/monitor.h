
struct medusa_subject;
struct medusa_monitor;

enum {
        medusa_monitor_poll_default,
        medusa_monitor_poll_epoll,
        medusa_monitor_poll_kqueue,
        medusa_monitor_poll_poll,
        medusa_monitor_poll_select
#define medusa_monitor_poll_default     medusa_monitor_poll_default
#define medusa_monitor_poll_epoll       medusa_monitor_poll_epoll
#define medusa_monitor_poll_kqueue      medusa_monitor_poll_kqueue
#define medusa_monitor_poll_poll        medusa_monitor_poll_poll
#define medusa_monitor_poll_select      medusa_monitor_poll_select
};

enum {
        medusa_monitor_timer_default,
        medusa_monitor_timer_timerfd,
#define medusa_monitor_timer_default    medusa_monitor_timer_default
#define medusa_monitor_timer_timerfd    medusa_monitor_timer_timerfd
};

enum {
        medusa_monitor_run_once         = 0x00000001,
        medusa_monitor_run_nowait       = 0x00000002,
        medusa_monitor_run_timeout      = 0x00000004
#define medusa_monitor_run_once         medusa_monitor_run_once
#define medusa_monitor_run_nowait       medusa_monitor_run_nowait
#define medusa_monitor_run_timeout      medusa_monitor_run_timeout
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
        } poll;
        struct {
                unsigned int type;
                union {
                        struct {

                        } timerfd;
                } u;
        } timer;
};

int medusa_monitor_init_options_default (struct medusa_monitor_init_options *options);

struct medusa_monitor * medusa_monitor_create (const struct medusa_monitor_init_options *options);
void medusa_monitor_destroy (struct medusa_monitor *monitor);

int medusa_monitor_add (struct medusa_monitor *monitor, struct medusa_subject *subject, ...);
int medusa_monitor_mod (struct medusa_monitor *monitor, struct medusa_subject *subject, ...);
int medusa_monitor_del (struct medusa_monitor *monitor, struct medusa_subject *subject);

int medusa_monitor_run (struct medusa_monitor *monitor, unsigned int flags, ...);
int medusa_monitor_break (struct medusa_monitor *monitor);
int medusa_monitor_continue (struct medusa_monitor *monitor);
