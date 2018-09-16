
ifeq ($(__LINUX__), y)
POLL_EPOLL_ENABLE     ?= y
endif
ifeq ($(__DARWIN__), y)
POLL_KQUEUE_ENABLE    ?= y
endif
POLL_POLL_ENABLE      ?= y
POLL_SELECT_ENABLE    ?= y

ifeq ($(__LINUX__), y)
TIMER_TIMERFD_ENABLE  ?= y
endif

ifeq ($(__LINUX__), y)
SIGNAL_SIGACTION_ENABLE  ?= y
endif

target.a-y = \
	libmedusa-monitor.a \
	libmedusa-socket.a

target.so-y = \
	libmedusa-monitor.so \
	libmedusa-socket.so

libmedusa-monitor.a_cflags-y = \
	-fvisibility=hidden

libmedusa-monitor.a_files-y = \
	clock.c \
	pool.c \
	buffer.c \
	buffer-simple.c \
	buffer-chunked.c \
	pqueue.c \
	io.c \
	signal.c \
	timer.c \
	monitor.c

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

libmedusa-monitor.a_cflags-${SIGNAL_SIGACTION_ENABLE} += \
	-DSIGNAL_SIGACTION_ENABLE=1
libmedusa-monitor.a_files-${SIGNAL_SIGACTION_ENABLE} += \
	signal-sigaction.c

libmedusa-monitor.so_cflags-y = \
	${libmedusa-monitor.a_cflags-y}

libmedusa-monitor.so_files-y = \
	${libmedusa-monitor.a_files-y}

libmedusa-monitor.so_ldflags-y = \
	-lpthread \
	-lrt

libmedusa-socket.a_cflags-y = \
	-fvisibility=hidden

libmedusa-socket.a_files-y = \
	tcpsocket.c

libmedusa-socket.so_cflags-y = \
	${libmedusa-socket.a_cflags-y}

libmedusa-socket.so_files-y = \
	${libmedusa-socket.a_files-y}

libmedusa-socket.so_ldflags-y = \
	-lmedusa-monitor

libmedusa-socket.so_depends-y = \
	libmedusa-monitor.a \
	libmedusa-monitor.so

dist.dir = ../dist
dist.base = medusa

dist.include-y = \
	monitor.h \
	clock.h \
	error.h \
	pool.h \
	buffer.h \
	io.h \
	signal.h \
	timer.h \
	tcpsocket.h

dist.lib-y = \
	libmedusa-monitor.a \
	libmedusa-monitor.so \
	libmedusa-socket.a \
	libmedusa-socket.so

include ../Makefile.lib
