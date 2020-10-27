
MEDUSA_VERSION			 = 1.0.0
MEDUSA_SONAME			 = 1

MEDUSA_BUILD_TEST     		?= n
MEDUSA_BUILD_EXAMPLES 		?= n

MEDUSA_TCPSOCKET_OPENSSL_ENABLE ?= y

prefix	?= /usr/local

subdir-y = \
	src

subdir-${MEDUSA_BUILD_TEST} += \
	test

subdir-${MEDUSA_BUILD_EXAMPLES} += \
	examples

src_makeflags-y = \
	MEDUSA_VERSION=${MEDUSA_VERSION} \
	MEDUSA_SONAME=${MEDUSA_SONAME} \
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
	${Q}+${MAKE} ${test_makeflags-y} -C test tests

install: src test
	install -d ${DESTDIR}/${prefix}/include/medusa
	install -m 0644 dist/include/medusa/buffer.h ${DESTDIR}/${prefix}/include/medusa/buffer.h
	install -m 0644 dist/include/medusa/clock.h ${DESTDIR}/${prefix}/include/medusa/clock.h
	install -m 0644 dist/include/medusa/error.h ${DESTDIR}/${prefix}/include/medusa/error.h
	install -m 0644 dist/include/medusa/exec.h ${DESTDIR}/${prefix}/include/medusa/exec.h
	install -m 0644 dist/include/medusa/httprequest.h ${DESTDIR}/${prefix}/include/medusa/httprequest.h
	install -m 0644 dist/include/medusa/httpserver.h ${DESTDIR}/${prefix}/include/medusa/httpserver.h
	install -m 0644 dist/include/medusa/io.h ${DESTDIR}/${prefix}/include/medusa/io.h
	install -m 0644 dist/include/medusa/monitor.h ${DESTDIR}/${prefix}/include/medusa/monitor.h
	install -m 0644 dist/include/medusa/pool.h ${DESTDIR}/${prefix}/include/medusa/pool.h
	install -m 0644 dist/include/medusa/queue.h ${DESTDIR}/${prefix}/include/medusa/queue.h
	install -m 0644 dist/include/medusa/signal.h ${DESTDIR}/${prefix}/include/medusa/signal.h
	install -m 0644 dist/include/medusa/condition.h ${DESTDIR}/${prefix}/include/medusa/condition.h
	install -m 0644 dist/include/medusa/tcpsocket.h ${DESTDIR}/${prefix}/include/medusa/tcpsocket.h
	install -m 0644 dist/include/medusa/udpsocket.h ${DESTDIR}/${prefix}/include/medusa/udpsocket.h
	install -m 0644 dist/include/medusa/timer.h ${DESTDIR}/${prefix}/include/medusa/timer.h
	install -m 0644 dist/include/medusa/dnsrequest.h ${DESTDIR}/${prefix}/include/medusa/dnsrequest.h
	install -m 0644 dist/include/medusa/websocketserver.h ${DESTDIR}/${prefix}/include/medusa/websocketserver.h
	
	install -d ${DESTDIR}/${prefix}/lib
	install -m 0755 dist/lib/libmedusa.so.${MEDUSA_SONAME} ${DESTDIR}/${prefix}/lib/
	ln -sf libmedusa.so.${MEDUSA_SONAME} ${DESTDIR}/${prefix}/lib/libmedusa.so.${MEDUSA_VERSION}
	install -m 0644 dist/lib/libmedusa.a ${DESTDIR}/${prefix}/lib/

	install -d ${DESTDIR}/${prefix}/lib/pkgconfig
	sed 's?'prefix=/usr/local'?'prefix=${DESTDIR}/${prefix}'?g' libmedusa.pc > ${DESTDIR}/${prefix}/lib/pkgconfig/libmedusa.pc

uninstall:
	rm -rf ${DESTDIR}/${prefix}/include/medusa
	
	rm -f ${DESTDIR}/${prefix}/lib/libmedusa.so*
	rm -f ${DESTDIR}/${prefix}/lib/libmedusa.a
	
	rm -f ${DESTDIR}/${prefix}/lib/pkgconfig/libmedusa.pc
