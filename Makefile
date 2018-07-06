
subdir-y = \
	app \
	src \
	test

app_depends-y = \
	src

test_depends-y = \
	src

include Makefile.lib

tests: test
	@${Q}+${MAKE} -C test tests
