
subdir-y = \
	src \
	test

subdir-y += \
	app

app_depends-y = \
	src

test_depends-y = \
	src

include Makefile.lib

tests: all
	@${Q}+${MAKE} -C test tests
