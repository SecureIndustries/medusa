
subdir-y = \
	src \
	test \
	examples

app_depends-y = \
	src

test_depends-y = \
	src

examples_depends-y = \
	src

include Makefile.lib

tests: all
	@${Q}+${MAKE} -C test tests
