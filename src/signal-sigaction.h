
#if !defined(MEDUSA_SIGNAL_SIGACTION_H)
#define MEDUSA_SIGNAL_SIGACTION_H

struct medusa_signal_sigaction_init_options {

};

struct medusa_signal_backend * medusa_signal_sigaction_create (const struct medusa_signal_sigaction_init_options *options);

#endif
