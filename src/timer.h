
enum {
        MEDUSA_TIMER_TYPE_PRECISE,
        MEDUSA_TIMER_TYPE_COARSE
#define MEDUSA_TIMER_TYPE_PRECISE       MEDUSA_TIMER_TYPE_PRECISE
#define MEDUSA_TIMER_TYPE_COARSE        MEDUSA_TIMER_TYPE_COARSE
};

struct medusa_timer;
struct medusa_monitor;

struct medusa_timer * medusa_timer_create (struct medusa_monitor *monitor);
void medusa_timer_destroy (struct medusa_timer *timer);

int medusa_timer_set_initial (struct medusa_timer *timer, double initial);
double medusa_timer_get_initial (const struct medusa_timer *timer);

int medusa_timer_set_interval (struct medusa_timer *timer, double interval);
double medusa_timer_get_interval (const struct medusa_timer *timer);

double medusa_timer_get_remaining_time (const struct medusa_timer *timer);

int medusa_timer_set_single_shot (struct medusa_timer *timer, int single_shot);
int medusa_timer_get_single_shot (const struct medusa_timer *timer);

int medusa_timer_set_type (struct medusa_timer *timer, unsigned int type);
unsigned int medusa_timer_get_type (const struct medusa_timer *timer);

int medusa_timer_set_callback (struct medusa_timer *timer, int (*callback) (struct medusa_timer *timer, unsigned int events, void *context), void *context);

int medusa_timer_set_active (struct medusa_timer *timer, int active);
int medusa_timer_get_active (const struct medusa_timer *timer);

int medusa_timer_start (struct medusa_timer *timer);
int medusa_timer_stop (struct medusa_timer *timer);

int medusa_timer_is_valid (const struct medusa_timer *timer);
struct medusa_subject * medusa_timer_get_subject (struct medusa_timer *timer);
struct medusa_monitor * medusa_timer_get_monitor (struct medusa_timer *timer);
