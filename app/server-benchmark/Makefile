
target-y = \
	medusa-server-benchmark

medusa-server-benchmark_includes-y = \
	../../3rdparty/http-parser \
	../../dist/include

medusa-server-benchmark_libraries-y = \
	../../dist/lib

medusa-server-benchmark_files-y = \
	../../3rdparty/http-parser/http_parser.c \
	server-benchmark.c

medusa-server-benchmark_ldflags-y = \
	-Wl,-Bstatic \
	-lmedusa-monitor \
	-Wl,-Bdynamic

medusa-server-benchmark_depends-y = \
	../../dist/lib/libmedusa-monitor.a

dist.dir = ../../dist

dist.bin-y = \
	medusa-server-benchmark

include ../../Makefile.lib
