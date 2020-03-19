# Initialization
AC_PREREQ([2.69])
AC_INIT([libmctp], 0.9, [https://github.com/openbmc/libmctp/issues])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([subdir-objects -Wall -Werror -Wno-portability foreign dist-xz])
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CC
AM_PROG_AR
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# libtool init
LT_INIT

AC_CHECK_HEADERS_ONCE([endian.h])

# pkg-config
PKG_PROG_PKG_CONFIG
PKG_INSTALLDIR
AC_ARG_WITH([systemdsystemunitdir],
     [AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files])],
     [],
     [with_systemdsystemunitdir=auto]
)
AS_IF([test "x$with_systemdsystemunitdir" = "xyes" -o "x$with_systemdsystemunitdir" = "xauto"],
    [def_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)
     AS_IF([test "x$def_systemdsystemunitdir" = "x"],
           [AS_IF([test "x$with_systemdsystemunitdir" = "xyes"],
                  [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])]
            )
            with_systemdsystemunitdir=no],
           [with_systemdsystemunitdir="$def_systemdsystemunitdir"]
     )]
)
AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
      [AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])]
)
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemdsystemunitdir" != "xno"])

# Set defaults for standard library compiles. We may want to
# AC_ARG_WITH these in the future.
AC_DEFINE([MCTP_HAVE_SYSLOG], [1], [Define to enable syslog])
AC_DEFINE([MCTP_HAVE_FILEIO], [1], [Define to enable filesystem functions])
AC_DEFINE([MCTP_HAVE_STDIO], [1], [Define to enable stdio functions])
AC_DEFINE([MCTP_DEFAULT_ALLOC], [1],
    [Define to populate allocation functions to defaults (malloc/free)])

# Enable all bindings. AC_ARG_ENABLE in future.
AM_CONDITIONAL([LIBMCTP_BINDING_serial], [true])
AM_CONDITIONAL([LIBMCTP_BINDING_astlpc], [true])
AM_CONDITIONAL([LIBMCTP_BINDING_astpcie], [true])

AX_CODE_COVERAGE
m4_ifdef([_AX_CODE_COVERAGE_RULES],
    [AM_CONDITIONAL(AUTOCONF_CODE_COVERAGE_2019_01_06, [true])],
    [AM_CONDITIONAL(AUTOCONF_CODE_COVERAGE_2019_01_06, [false])])
AX_ADD_AM_MACRO_STATIC([])

AC_CONFIG_FILES([Makefile libmctp.pc])
AC_OUTPUT
