
MEDUSA_BUILD_TEST     ?= n
MEDUSA_BUILD_EXAMPLES ?= n

MEDUSA_TCPSOCKET_OPENSSL_ENABLE ?= y

subdir-y = \
	src

subdir-${MEDUSA_BUILD_TEST} += \
	test

subdir-${MEDUSA_BUILD_EXAMPLES} += \
	examples

src_makeflags-y = \
	MEDUSA_TCPSOCKET_OPENSSL_ENABLE=${MEDUSA_TCPSOCKET_OPENSSL_ENABLE}

test_depends-y = \
	src

test_makeflags-y = \
	MEDUSA_TCPSOCKET_OPENSSL_ENABLE=${MEDUSA_TCPSOCKET_OPENSSL_ENABLE}

examples_depends-y = \
	src

examples_makeflags-y = \
	MEDUSA_TCPSOCKET_OPENSSL_ENABLE=${MEDUSA_TCPSOCKET_OPENSSL_ENABLE}

include Makefile.lib

tests: all
	@${Q}+${MAKE} -C test tests

install: src test
	install -d ${DESTDIR}/usr/local/include/medusa
	install -m 0644 dist/include/medusa/buffer.h ${DESTDIR}/usr/local/include/medusa/buffer.h
	install -m 0644 dist/include/medusa/clock.h ${DESTDIR}/usr/local/include/medusa/clock.h
	install -m 0644 dist/include/medusa/error.h ${DESTDIR}/usr/local/include/medusa/error.h
	install -m 0644 dist/include/medusa/exec.h ${DESTDIR}/usr/local/include/medusa/exec.h
	install -m 0644 dist/include/medusa/httprequest.h ${DESTDIR}/usr/local/include/medusa/httprequest.h
	install -m 0644 dist/include/medusa/io.h ${DESTDIR}/usr/local/include/medusa/io.h
	install -m 0644 dist/include/medusa/monitor.h ${DESTDIR}/usr/local/include/medusa/monitor.h
	install -m 0644 dist/include/medusa/pool.h ${DESTDIR}/usr/local/include/medusa/pool.h
	install -m 0644 dist/include/medusa/queue.h ${DESTDIR}/usr/local/include/medusa/queue.h
	install -m 0644 dist/include/medusa/signal.h ${DESTDIR}/usr/local/include/medusa/signal.h
	install -m 0644 dist/include/medusa/condition.h ${DESTDIR}/usr/local/include/medusa/condition.h
	install -m 0644 dist/include/medusa/tcpsocket.h ${DESTDIR}/usr/local/include/medusa/tcpsocket.h
	install -m 0644 dist/include/medusa/udpsocket.h ${DESTDIR}/usr/local/include/medusa/udpsocket.h
	install -m 0644 dist/include/medusa/timer.h ${DESTDIR}/usr/local/include/medusa/timer.h
	
	install -d ${DESTDIR}/usr/local/lib
	if [ -f dist/lib/libmedusa.so ]; then install -m 0755 dist/lib/libmedusa.so ${DESTDIR}/usr/local/lib/libmedusa.so; fi

	install -d ${DESTDIR}/usr/local/lib
	if [ -f dist/lib/libmedusa.a ]; then install -m 0644 dist/lib/libmedusa.a ${DESTDIR}/usr/local/lib/libmedusa.a; fi

	install -d ${DESTDIR}/usr/local/lib/pkgconfig
	sed 's?'prefix=/usr/local'?'prefix=${DESTDIR}/usr/local'?g' libmedusa.pc > ${DESTDIR}/usr/local/lib/pkgconfig/libmedusa.pc

uninstall:
	rm -rf ${DESTDIR}/usr/local/include/medusa
	
	rm -f ${DESTDIR}/usr/local/lib/libmedusa.so
	rm -f ${DESTDIR}/usr/local/lib/libmedusa.a
	
	rm -f ${DESTDIR}/usr/local/lib/pkgconfig/libmedusa.pc
