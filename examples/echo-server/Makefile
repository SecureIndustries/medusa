
target-y = \
	medusa-echo-server

medusa-echo-server_includes-y = \
	../../3rdparty/http-parser \
	../../dist/include

medusa-echo-server_libraries-y = \
	../../dist/lib

medusa-echo-server_files-y = \
	../../3rdparty/http-parser/http_parser.c \
	echo-server.c

medusa-echo-server_ldflags-y = \
	-Wl,-Bstatic \
	-lmedusa-socket \
	-lmedusa-monitor \
	-Wl,-Bdynamic \
	-lrt \
	-lreadline

medusa-echo-server_depends-y = \
	../../dist/lib/libmedusa-socket.a \
	../../dist/lib/libmedusa-monitor.a

dist.dir = ../../dist

dist.bin-y = \
	medusa-echo-server

include ../../Makefile.lib
