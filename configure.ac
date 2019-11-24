AC_PREREQ([2.63])
AC_INIT([bwrap-oci], [0.2], [atomic-devel@projectatomic.io])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AC_USE_SYSTEM_EXTENSIONS

AM_INIT_AUTOMAKE([1.11 -Wno-portability foreign tar-ustar no-dist-gzip dist-xz subdir-objects])
AM_MAINTAINER_MODE([enable])
AM_SILENT_RULES([yes])

AC_PROG_SED
AC_PROG_CC
AM_PROG_CC_C_O

PKG_CHECK_MODULES(JSON_GLIB, [json-glib-1.0])
PKG_CHECK_MODULES(GIO_UNIX, [gio-unix-2.0])
AC_CHECK_LIB(seccomp, seccomp_rule_add)

AC_CHECK_HEADERS([error.h])

AC_PATH_PROG(BWRAP, [bwrap])
AC_DEFINE_UNQUOTED([BWRAP], ["$BWRAP"], [Path to bwrap])

AC_CONFIG_FILES([
Makefile
])

AH_BOTTOM([
#ifndef HAVE_ERROR_H
#ifndef _ERROR_LOCAL
#define _ERROR_LOCAL 1
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static void error(int status, int errnum, const char *msg, ...) {
	if (errnum)
		fprintf(stderr, ": %s\n", strerror(errnum));
	else
		fputc('\n', stderr);
	if (status)
		exit(status);
}
#endif
#endif
])
AC_OUTPUT
