ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libmctp.la
libmctp_la_SOURCES = core.c alloc.c log.c \
		     libmctp.h libmctp-alloc.h libmctp-log.h

if LIBMCTP_BINDING_serial
libmctp_la_SOURCES += serial.c libmctp-serial.h
endif

if LIBMCTP_BINDING_astlpc
libmctp_la_SOURCES += astlpc.c libmctp-astlpc.h
endif

bin_PROGRAMS = utils/mctp-demux-daemon
utils_mctp_demux_daemon_LDADD = libmctp.la

TESTS = $(check_PROGRAMS)

check_PROGRAMS = tests/test_eid tests/test_seq
# We set a global LDADD here, as there's no way to specify it for all
# tests. This means other targets' LDADDs need to be overridden.
LDADD = tests/libtest-utils.a libmctp.la

noinst_LIBRARIES = tests/libtest-utils.a

tests_libtest_utils_a_SOURCES = tests/test-utils.c tests/test-utils.h
