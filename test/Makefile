
$(eval tests = $(sort $(subst .c,,$(wildcard *-??.c))))

target-y = \
	${tests}

all:

define test-defaults
	$1_files-y = \
		$1.c

	$1_includes-y = \
		../dist/include

	$1_libraries-y = \
		../dist/lib

	$1_ldflags-y = \
		-Wl,-Bstatic \
		-lmedusa-http \
		-lmedusa-socket \
		-lmedusa-monitor \
		-Wl,-Bdynamic \
		-lpthread

	$1_depends-y = \
		../dist/lib/libmedusa-http.a \
		../dist/lib/libmedusa-socket.a \
		../dist/lib/libmedusa-monitor.a
endef

$(eval $(foreach T,${tests},$(eval $(call test-defaults,$T))))

include ../Makefile.lib

tests: all
	${Q}echo "running tests";
	${Q}for T in ${tests}; do \
		printf "  $${T} ... "; \
		./$${T} 2>/dev/null 1>/dev/null; \
		retval=$$?; \
		if [ $$retval != 0 ]; then \
			echo "fail (rc: $$retval)"; \
		else \
			echo "success"; \
		fi \
	done
