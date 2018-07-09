
struct medusa_subject;
struct medusa_monitor;

enum {
        medusa_subject_type_io          = 1,
        medusa_subject_type_timer       = 2,
        medusa_subject_type_signal      = 3
#define medusa_subject_type_io          medusa_subject_type_io
#define medusa_subject_type_timer       medusa_subject_type_timer
#define medusa_subject_type_signal      medusa_subject_type_signal
};

struct medusa_subject_io_init_options {
        int fd;
};

struct medusa_subject_timer_init_options {
        struct medusa_timerspec timerspec;
};

struct medusa_subject_signal_init_options {
        int number;
};

struct medusa_subject_init_options {
        unsigned int type;
        union {
                struct medusa_subject_io_init_options io;
                struct medusa_subject_timer_init_options timer;
                struct medusa_subject_signal_init_options signal;
        } u;
        struct {
                int (*function) (struct medusa_subject *subject, unsigned int events);
                void *context;
        } callback;
};

int medusa_subject_retain (struct medusa_subject *subject);

void medusa_subject_uninit (struct medusa_subject *subject);
int medusa_subject_init (struct medusa_subject *subject, const struct medusa_subject_init_options *options);
int medusa_subject_init_io (struct medusa_subject *subject, int fd, int (*callback) (struct medusa_subject *subject, unsigned int events), void *context);
int medusa_subject_init_timer (struct medusa_subject *subject, struct medusa_timerspec timerspec, int (*callback) (struct medusa_subject *subject, unsigned int events), void *context);
int medusa_subject_init_signal (struct medusa_subject *subject, int number, int (*callback) (struct medusa_subject *subject, unsigned int events), void *context);

void medusa_subject_destroy (struct medusa_subject *subject);
struct medusa_subject * medusa_subject_create (const struct medusa_subject_init_options *options);
struct medusa_subject * medusa_subject_create_io (int fd, int (*callback) (struct medusa_subject *subject, unsigned int events), void *context);
struct medusa_subject * medusa_subject_create_timer (struct medusa_timerspec timerspec, int (*callback) (struct medusa_subject *subject, unsigned int events), void *context);
struct medusa_subject * medusa_subject_create_signal (int number, int (*callback) (struct medusa_subject *subject, unsigned int events), void *context);

unsigned int medusa_subject_get_type (const struct medusa_subject *subject);
int (*medusa_subject_get_callback_function (const struct medusa_subject *subject)) (struct medusa_subject *subject, unsigned int events);
void * medusa_subject_get_callback_context (const struct medusa_subject *subject);
int medusa_subject_io_get_fd (const struct medusa_subject *subject);
