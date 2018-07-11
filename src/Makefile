
POLL_EPOLL_ENABLE     ?= y
POLL_KQUEUE_ENABLE    ?= y
POLL_POLL_ENABLE      ?= y
POLL_SELECT_ENABLE    ?= y

TIMER_TIMERFD_ENABLE  ?= y

target.a-y = \
	libmedusa-monitor.a

target.so-y = \
	libmedusa-monitor.so

libmedusa-monitor.a_cflags-y = \
	-fvisibility=hidden

libmedusa-monitor.a_files-y = \
	clock.c \
	io.c \
	monitor.c \
	subject.c \
	timer.c

libmedusa-monitor.a_cflags-${POLL_EPOLL_ENABLE} += \
	-DPOLL_EPOLL_ENABLE=1
libmedusa-monitor.a_files-${POLL_EPOLL_ENABLE} += \
	poll-epoll.c

libmedusa-monitor.a_cflags-${POLL_KQUEUE_ENABLE} += \
	-DPOLL_KQUEUE_ENABLE=1
libmedusa-monitor.a_files-${POLL_KQUEUE_ENABLE} += \
	poll-kqueue.c

libmedusa-monitor.a_cflags-${POLL_POLL_ENABLE} += \
	-DPOLL_POLL_ENABLE=1
libmedusa-monitor.a_files-${POLL_POLL_ENABLE} += \
	poll-poll.c

libmedusa-monitor.a_cflags-${POLL_SELECT_ENABLE} += \
	-DPOLL_SELECT_ENABLE=1
libmedusa-monitor.a_files-${POLL_SELECT_ENABLE} += \
	poll-select.c

libmedusa-monitor.a_cflags-${TIMER_TIMERFD_ENABLE} += \
	-DTIMER_TIMERFD_ENABLE=1
libmedusa-monitor.a_files-${TIMER_TIMERFD_ENABLE} += \
	timer-timerfd.c

libmedusa-monitor.so_cflags-y = \
	${libmedusa-monitor.a_cflags-y}

libmedusa-monitor.so_files-y = \
	${libmedusa-monitor.a_files-y}

dist.dir = ../dist
dist.base = medusa

dist.include-y = \
	event.h \
	io.h \
	monitor.h \
	queue.h \
	subject.h \
	time.h \
	timer.h

dist.lib-y = \
	libmedusa-monitor.a \
	libmedusa-monitor.so

include ../Makefile.lib
