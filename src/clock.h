
struct timespec;

int clock_monotonic (struct timespec *timespec);
int clock_monotonic_raw (struct timespec *timespec);
int clock_monotonic_coarse (struct timespec *timespec);
