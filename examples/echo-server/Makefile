target-y = \
	medusa-echo-server

medusa-echo-server_includes-y = \
	../../dist/include

medusa-echo-server_libraries-y = \
	../../dist/lib

medusa-echo-server_files-y = \
	echo-server.c

medusa-echo-server_ldflags-y = \
	../../dist/lib/libmedusa.a

medusa-echo-server_ldflags-y += \
	-lpthread \
	-lm

medusa-echo-server_ldflags-$(__LINUX__) += \
	-lrt

medusa-echo-server_depends-y = \
	../../dist/lib/libmedusa.a

dist.dir = ../../dist

dist.bin-y = \
	medusa-echo-server

include ../../Makefile.lib
