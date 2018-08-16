
target-y = \
	medusa-echo-client

medusa-echo-client_includes-y = \
	../../dist/include

medusa-echo-client_libraries-y = \
	../../dist/lib

medusa-echo-client_files-y = \
	echo-client.c

medusa-echo-client_ldflags-y = \
	-Wl,-Bstatic \
	-lmedusa-socket \
	-lmedusa-monitor \
	-Wl,-Bdynamic \
	-lrt \
	-lreadline

medusa-echo-client_depends-y = \
	../../dist/lib/libmedusa-socket.a \
	../../dist/lib/libmedusa-monitor.a

dist.dir = ../../dist

dist.bin-y = \
	medusa-echo-client

include ../../Makefile.lib
