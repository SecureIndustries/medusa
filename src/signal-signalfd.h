
#if !defined(MEDUSA_SIGNAL_SIGNALFD_H)
#define MEDUSA_SIGNAL_SIGNALFD_H

struct medusa_signal_signalfd_init_options {

};

struct medusa_signal_backend * medusa_signal_signalfd_create (const struct medusa_signal_signalfd_init_options *options);

#endif
