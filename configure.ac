# Initialization
AC_PREREQ([2.69])
AC_INIT([libmctp], 0.9, [https://github.com/openbmc/libmctp/issues])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([subdir-objects -Wall -Werror foreign dist-xz])
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CC
AM_PROG_AR
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# libtool init
LT_INIT

# Set defaults for standard library compiles. We may want to
# AC_ARG_WITH these in the future.
AC_DEFINE([MCTP_HAVE_SYSLOG], [1], [Define to enable syslog])
AC_DEFINE([MCTP_HAVE_FILEIO], [1], [Define to enable filesystem functions])
AC_DEFINE([MCTP_DEFAULT_ALLOC], [1],
    [Define to populate allocation functions to defaults (malloc/free)])

# Enable all bindings. AC_ARG_ENABLE in future.
AM_CONDITIONAL([LIBMCTP_BINDING_serial], [true])
AM_CONDITIONAL([LIBMCTP_BINDING_astlpc], [true])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
