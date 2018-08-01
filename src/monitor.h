
struct medusa_monitor;

enum {
        MEDUSA_MONITOR_POLL_DEFAULT,
        MEDUSA_MONITOR_POLL_EPOLL,
        MEDUSA_MONITOR_POLL_KQUEUE,
        MEDUSA_MONITOR_POLL_POLL,
        MEDUSA_MONITOR_POLL_SELECT
#define MEDUSA_MONITOR_POLL_DEFAULT     MEDUSA_MONITOR_POLL_DEFAULT
#define MEDUSA_MONITOR_POLL_EPOLL       MEDUSA_MONITOR_POLL_EPOLL
#define MEDUSA_MONITOR_POLL_KQUEUE      MEDUSA_MONITOR_POLL_KQUEUE
#define MEDUSA_MONITOR_POLL_POLL        MEDUSA_MONITOR_POLL_POLL
#define MEDUSA_MONITOR_POLL_SELECT      MEDUSA_MONITOR_POLL_SELECT
};

enum {
        MEDUSA_MONITOR_TIMER_DEFAULT,
        MEDUSA_MONITOR_TIMER_TIMERFD,
#define MEDUSA_MONITOR_TIMER_DEFAULT    MEDUSA_MONITOR_TIMER_DEFAULT
#define MEDUSA_MONITOR_TIMER_TIMERFD    MEDUSA_MONITOR_TIMER_TIMERFD
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

int medusa_monitor_run (struct medusa_monitor *monitor);
int medusa_monitor_run_once (struct medusa_monitor *monitor);
int medusa_monitor_run_timeout (struct medusa_monitor *monitor, double timeout);

int medusa_monitor_get_running (struct medusa_monitor *monitor);

int medusa_monitor_break (struct medusa_monitor *monitor);
int medusa_monitor_continue (struct medusa_monitor *monitor);
