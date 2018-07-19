
enum {
        MEDUSA_TIMER_FLAG_ENABLED       = 0x00000001,
        MEDUSA_TIMER_FLAG_SINGLE_SHOT   = 0x00000002,
        MEDUSA_TIMER_FLAG_PRECISE       = 0x00000004,
        MEDUSA_TIMER_FLAG_COARSE        = 0x00000008
#define MEDUSA_TIMER_FLAG_ENABLED       MEDUSA_TIMER_FLAG_ENABLED
#define MEDUSA_TIMER_FLAG_SINGLE_SHOT   MEDUSA_TIMER_FLAG_SINGLE_SHOT
#define MEDUSA_TIMER_FLAG_PRECISE       MEDUSA_TIMER_FLAG_PRECISE
#define MEDUSA_TIMER_FLAG_COARSE        MEDUSA_TIMER_FLAG_COARSE
};

struct medusa_timer {
        struct medusa_subject subject;

        unsigned int flags;

        struct timespec initial;
        struct timespec interval;
        int (*callback) (struct medusa_timer *timer, unsigned int events, void *context);
        void *context;

        struct timespec _timespec;
        unsigned int _position;
};

int medusa_timer_init (struct medusa_monitor *monitor, struct medusa_timer *timer);
void medusa_timer_uninit (struct medusa_timer *timer);
