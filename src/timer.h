
enum {
        MEDUSA_TIMER_RESOLUTION_DEFAULT,
        MEDUSA_TIMER_RESOLUTION_NANOSECOMDS,
        MEDUSA_TIMER_RESOLUTION_MICROSECONDS,
        MEDUSA_TIMER_RESOLUTION_MILLISECONDS,
        MEDUSA_TIMER_RESOLUTION_SECONDS
#define MEDUSA_TIMER_RESOLUTION_DEFAULT         MEDUSA_TIMER_RESOLUTION_DEFAULT
#define MEDUSA_TIMER_RESOLUTION_NANOSECOMDS     MEDUSA_TIMER_RESOLUTION_NANOSECOMDS
#define MEDUSA_TIMER_RESOLUTION_MICROSECONDS    MEDUSA_TIMER_RESOLUTION_MICROSECONDS
#define MEDUSA_TIMER_RESOLUTION_MILLISECONDS    MEDUSA_TIMER_RESOLUTION_MILLISECONDS
#define MEDUSA_TIMER_RESOLUTION_SECONDS         MEDUSA_TIMER_RESOLUTION_SECONDS
};

enum {
        MEDUSA_TIMER_EVENT_TIMEOUT      = 0x00000010,
        MEDUSA_TIMER_EVENT_DESTROY      = 0x00000020
#define MEDUSA_TIMER_EVENT_TIMEOUT      MEDUSA_TIMER_EVENT_TIMEOUT
#define MEDUSA_TIMER_EVENT_DESTROY      MEDUSA_TIMER_EVENT_DESTROY
};

struct medusa_timer;
struct medusa_monitor;

struct medusa_timer * medusa_timer_create (struct medusa_monitor *monitor, int (*onevent) (struct medusa_timer *timer, unsigned int events, void *context), void *context);
void medusa_timer_destroy (struct medusa_timer *timer);

int medusa_timer_set_initial (struct medusa_timer *timer, double initial);
double medusa_timer_get_initial (const struct medusa_timer *timer);

int medusa_timer_set_interval (struct medusa_timer *timer, double interval);
double medusa_timer_get_interval (const struct medusa_timer *timer);

double medusa_timer_get_remaining_time (const struct medusa_timer *timer);

int medusa_timer_set_single_shot (struct medusa_timer *timer, int single_shot);
int medusa_timer_get_single_shot (const struct medusa_timer *timer);

int medusa_timer_set_resolution (struct medusa_timer *timer, unsigned int resolution);
unsigned int medusa_timer_get_resolution (const struct medusa_timer *timer);

int medusa_timer_set_enabled (struct medusa_timer *timer, int enabled);
int medusa_timer_get_enabled (const struct medusa_timer *timer);

int medusa_timer_start (struct medusa_timer *timer);
int medusa_timer_stop (struct medusa_timer *timer);

int medusa_timer_is_valid (const struct medusa_timer *timer);
struct medusa_monitor * medusa_timer_get_monitor (struct medusa_timer *timer);
