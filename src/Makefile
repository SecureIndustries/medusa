
ifeq ($(__LINUX__), y)
MEDUSA_POLL_EPOLL_ENABLE     	?= y
endif
ifeq ($(__DARWIN__), y)
MEDUSA_POLL_KQUEUE_ENABLE    	?= y
endif
MEDUSA_POLL_POLL_ENABLE      	?= y
MEDUSA_POLL_SELECT_ENABLE    	?= y

ifeq ($(__LINUX__), y)
MEDUSA_TIMER_TIMERFD_ENABLE  	?= y
endif

MEDUSA_SIGNAL_SIGACTION_ENABLE	?= y
ifeq ($(__LINUX__), y)
MEDUSA_SIGNAL_SIGNALFD_ENABLE	?= y
endif

target.a-y = \
	libmedusa.a \

target.o-y = \
	libmedusa.o \

target.so-y = \
	libmedusa.so \

libmedusa.a_cflags-y = \
	-fvisibility=hidden

libmedusa.a_files-y = \
	clock.c \
	pool.c \
	buffer.c \
	buffer-simple.c \
	pqueue.c \
	exec.c \
	io.c \
	signal.c \
	timer.c \
	monitor.c

libmedusa.a_cflags-${MEDUSA_POLL_EPOLL_ENABLE} += \
	-DMEDUSA_POLL_EPOLL_ENABLE=1
libmedusa.a_files-${MEDUSA_POLL_EPOLL_ENABLE} += \
	poll-epoll.c

libmedusa.a_cflags-${MEDUSA_POLL_KQUEUE_ENABLE} += \
	-DMEDUSA_POLL_KQUEUE_ENABLE=1
libmedusa.a_files-${MEDUSA_POLL_KQUEUE_ENABLE} += \
	poll-kqueue.c

libmedusa.a_cflags-${MEDUSA_POLL_POLL_ENABLE} += \
	-DMEDUSA_POLL_POLL_ENABLE=1
libmedusa.a_files-${MEDUSA_POLL_POLL_ENABLE} += \
	poll-poll.c

libmedusa.a_cflags-${MEDUSA_POLL_SELECT_ENABLE} += \
	-DMEDUSA_POLL_SELECT_ENABLE=1
libmedusa.a_files-${MEDUSA_POLL_SELECT_ENABLE} += \
	poll-select.c

libmedusa.a_cflags-${MEDUSA_TIMER_TIMERFD_ENABLE} += \
	-DMEDUSA_TIMER_TIMERFD_ENABLE=1
libmedusa.a_files-${MEDUSA_TIMER_TIMERFD_ENABLE} += \
	timer-timerfd.c

libmedusa.a_cflags-${MEDUSA_SIGNAL_SIGACTION_ENABLE} += \
	-DMEDUSA_SIGNAL_SIGACTION_ENABLE=1
libmedusa.a_files-${MEDUSA_SIGNAL_SIGACTION_ENABLE} += \
	signal-sigaction.c

libmedusa.a_cflags-${MEDUSA_SIGNAL_SIGNALFD_ENABLE} += \
	-DMEDUSA_SIGNAL_SIGNALFD_ENABLE=1
libmedusa.a_files-${MEDUSA_SIGNAL_SIGNALFD_ENABLE} += \
	signal-signalfd.c

libmedusa.a_files-y += \
	tcpsocket.c \
	udpsocket.c

libmedusa.a_files-y += \
	httprequest.c \
	../3rdparty/http-parser/http_parser.c

libmedusa.o_cflags-y = \
	${libmedusa.a_cflags-y}

libmedusa.o_files-y = \
	${libmedusa.a_files-y}

libmedusa.so_cflags-y = \
	${libmedusa.a_cflags-y}

libmedusa.so_files-y = \
	${libmedusa.a_files-y}

libmedusa.so_ldflags-y = \
	-lpthread

libmedusa.so_ldflags-$(__LINUX__) += \
	-lrt

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
	tcpsocket.h \
	udpsocket.h \
	httprequest.h \
	exec.h \
	queue.h

dist.lib-y = \
	libmedusa.a \
	libmedusa.so \

include ../Makefile.lib
