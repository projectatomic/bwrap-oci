AM_CFLAGS = $(WARN_CFLAGS)
CLEANFILES =

GITIGNOREFILES = build-aux/ gtk-doc.make config.h.in aclocal.m4

bin_PROGRAMS = bwrap-oci

bwrap_oci_SOURCES = \
	bwrap-oci.c \
	$(NULL)

bwrap_oci_CFLAGS = $(AM_CFLAGS) $(JSON_GLIB_CFLAGS)
bwrap_oci_LDADD = $(SELINUX_LIBS) $(JSON_GLIB_LIBS)

-include $(top_srcdir)/git.mk

TESTS = tests/bind.conf tests/cwd.conf tests/env.conf tests/hostname.conf \
	tests/label.conf tests/mount.conf tests/mount-label.conf tests/rootfs.conf \
	tests/seccomp.conf tests/tty.conf tests/uid.conf

TEST_EXTENSIONS = .conf
CONF_LOG_COMPILER = $(top_srcdir)/tests/tests-runner

EXTRA_DIST = $(TESTS:.conf=.conf.expected)
EXTRA_DIST += $(TESTS:.conf=.conf.command)
