
#if !defined(MEDUSA_POLL_EPOLL_H)
#define MEDUSA_POLL_EPOLL_H

struct medusa_monitor_epoll_init_options {

};

struct medusa_poll_backend * medusa_monitor_epoll_create (const struct medusa_monitor_epoll_init_options *options);

#endif
