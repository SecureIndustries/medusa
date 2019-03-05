
MEDUSA_BUILD_TEST     ?= n
MEDUSA_BUILD_EXAMPLES ?= n

subdir-y = \
	src

app_depends-y = \
	src

subdir-${MEDUSA_BUILD_TEST} += \
	test

test_depends-y = \
	src

subdir-${MEDUSA_BUILD_EXAMPLES} += \
	examples

examples_depends-y = \
	src

include Makefile.lib

tests: all
	@${Q}+${MAKE} -C test tests
