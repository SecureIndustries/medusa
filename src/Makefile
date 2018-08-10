
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

target.a-y = \
	libmedusa-monitor.a \
	libmedusa-socket.a \
	libmedusa-http.a

target.so-y = \
	libmedusa-monitor.so \
	libmedusa-socket.so \
	libmedusa-http.so

libmedusa-monitor.a_cflags-y = \
	-fvisibility=hidden

libmedusa-monitor.a_files-y = \
	clock.c \
	pool.c \
	buffer.c \
	pqueue.c \
	io.c \
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

libmedusa-monitor.so_cflags-y = \
	${libmedusa-monitor.a_cflags-y}

libmedusa-monitor.so_files-y = \
	${libmedusa-monitor.a_files-y}

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

libmedusa-http.a_cflags-y = \
	-fvisibility=hidden

libmedusa-http.a_includes-y = \
	../3rdparty/http-parser
	
libmedusa-http.a_files-y = \
	../3rdparty/http-parser/http_parser.c \
	http-server.c \
	http-client.c \
	http-request.c

libmedusa-http.so_cflags-y = \
	${libmedusa-http.a_cflags-y}

libmedusa-http.so_includes-y = \
	${libmedusa-http.a_includes-y}

libmedusa-http.so_files-y = \
	${libmedusa-http.a_files-y}

libmedusa-http.so_ldflags-y = \
	-lmedusa-socket

libmedusa-http.so_depends-y = \
	libmedusa-socket.a \
	libmedusa-socket.so

dist.dir = ../dist
dist.base = medusa

dist.include-y = \
	monitor.h \
	clock.h \
	error.h \
	pool.h \
	buffer.h \
	io.h \
	timer.h \
	tcpsocket.h \
	http.h \
	http-server.h \
	http-client.h \
	http-request.h

dist.lib-y = \
	libmedusa-monitor.a \
	libmedusa-monitor.so \
	libmedusa-socket.a \
	libmedusa-socket.so \
	libmedusa-http.a \
	libmedusa-http.so

include ../Makefile.lib
