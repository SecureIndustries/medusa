
MONITOR_EPOLL_ENABLE  ?= y
MONITOR_KQUEUE_ENABLE ?= y
MONITOR_POLL_ENABLE   ?= y
MONITOR_SELECT_ENABLE ?= y

target.a-y = \
	libmedusa-monitor.a

target.so-y = \
	libmedusa-monitor.so

libmedusa-monitor.a_cflags-y = \
	-fvisibility=hidden

libmedusa-monitor.a_files-y = \
	monitor.c \
	monitor-epoll.c \
	monitor-kqueue.c \
	monitor-poll.c \
	monitor-select.c \
	subject.c

libmedusa-monitor.so_cflags-y = \
	-fvisibility=hidden

libmedusa-monitor.so_files-y = \
	monitor.c \
	monitor-epoll.c \
	monitor-kqueue.c \
	monitor-poll.c \
	monitor-select.c \
	subject.c

include ../Makefile.lib
