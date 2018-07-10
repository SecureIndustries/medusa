
struct medusa_timespec;

int clock_monotonic (struct medusa_timespec *timespec);
int clock_monotonic_raw (struct medusa_timespec *timespec);
int clock_boottime (struct medusa_timespec *timespec);
