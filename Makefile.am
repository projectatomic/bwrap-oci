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
