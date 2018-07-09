
struct medusa_subject_io {
        int fd;
};

struct medusa_subject_timer {
        struct medusa_timerspec timerspec;
};

struct medusa_subject_signal {
        int number;
};

TAILQ_HEAD(medusa_subjects, medusa_subject);
struct medusa_subject {
        TAILQ_ENTRY(medusa_subject) subjects;
        unsigned int type;
        union {
                struct medusa_subject_io io;
                struct medusa_subject_timer timer;
                struct medusa_subject_signal signal;
        } u;
        struct {
                int (*function) (void *context, struct medusa_subject *subject, unsigned int events);
                void *context;
        } callback;
        struct {
                long long refcount;
                struct medusa_monitor *monitor;
        } internal;
};
