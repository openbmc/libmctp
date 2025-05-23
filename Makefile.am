ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libmctp.la
libmctp_la_SOURCES = core.c alloc.c log.c \
		     libmctp-alloc.h libmctp-log.h \
		     libmctp-cmds.h control.c
include_HEADERS = libmctp.h

if LIBMCTP_BINDING_serial
libmctp_la_SOURCES += serial.c crc-16-ccitt.c
include_HEADERS += libmctp-serial.h
endif

if LIBMCTP_BINDING_astlpc
libmctp_la_SOURCES += astlpc.c crc32.c
include_HEADERS += libmctp-astlpc.h
endif

if HAVE_SYSTEMD
systemdsystemunit_DATA = \
	systemd/system/mctp-demux.service \
	systemd/system/mctp-demux.socket
endif

bin_PROGRAMS = utils/mctp-demux-daemon
noinst_PROGRAMS = utils/mctp-in utils/mctp-pipe
utils_mctp_demux_daemon_SOURCES = utils/mctp-demux-daemon.c
if HAVE_PCAP
utils_mctp_demux_daemon_SOURCES += utils/mctp-capture.c
endif
utils_mctp_demux_daemon_LDADD = libmctp.la $(pcap_LIBS)
utils_mctp_demux_daemon_CFLAGS = $(pcap_CFLAGS)

pkgconfig_DATA = libmctp.pc

if AUTOCONF_CODE_COVERAGE_2019_01_06
include $(top_srcdir)/aminclude_static.am
clean-local: code-coverage-clean
distclean-local: code-coverage-dist-clean
else
@CODE_COVERAGE_RULES@
endif

AM_CPPFLAGS = $(CODE_COVERAGE_CPPFLAGS)
AM_CFLAGS = $(CODE_COVERAGE_CFLAGS)
AM_LDFLAGS = $(CODE_COVERAGE_LDFLAGS)

TESTS = $(check_PROGRAMS)

check_PROGRAMS = tests/test_eid tests/test_seq tests/test_bridge \
		 tests/test_astlpc tests/test_serial tests/test_cmds \
		 tests/test_core
# We set a global LDADD here, as there's no way to specify it for all
# tests. This means other targets' LDADDs need to be overridden.
LDADD = tests/libtest-utils.a libmctp.la

noinst_LIBRARIES = tests/libtest-utils.a

tests_libtest_utils_a_SOURCES = tests/test-utils.c tests/test-utils.h

@VALGRIND_CHECK_RULES@
