
$(eval tests = $(sort $(subst .c,,$(wildcard *-??.c))))

target-y = \
	${tests}

$(eval tests_event = $(sort $(subst .c,,$(wildcard *-??-event.c))))

target-n += \
	${tests_event}

all:

define test-defaults
	$1_files-y = \
		$1.c

	$1_includes-y = \
		../dist/include

	$1_libraries-y = \
		../dist/lib

	$1_ldflags-y = \
		../dist/lib/libmedusa.a \
		-lpthread

	$1_ldflags-$(__LINUX__) += \
		-lrt

	$1_depends-y = \
		../dist/lib/libmedusa.a
endef

define test_event-defaults
	$1_files-y = \
		$1.c

	$1_ldflags-y = \
		-levent \
		-levent_pthreads \
		-lpthread

	$1_ldflags-$(__LINUX__) += \
		-lrt

endef

$(eval $(foreach T,${tests},$(eval $(call test-defaults,$T))))
$(eval $(foreach T,${tests_event},$(eval $(call test_event-defaults,$T))))

include ../Makefile.lib

tests: all
	${Q}echo "running tests";
	${Q}for T in ${tests} ${tests_event}; do \
		printf "  $${T} ..."; \
		./$${T} 2>/dev/null 1>/dev/null; \
		retval=$$?; \
		if [ $$retval != 0 ]; then \
			printf " fail (rc: $$retval)"; \
		else \
			printf " success"; \
		fi; \
		printf "\n"; \
	done

clean:
	${Q}${RM} *.out
	${Q}${RM} *.png
