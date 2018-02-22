XSLTPROC = xsltproc

XSLTPROC_FLAGS = \
	--nonet \
	--stringparam man.output.quietly 1 \
	--stringparam funcsynopsis.style ansi \
	--stringparam man.th.extra1.suppress 1 \
	--stringparam man.authors.section.enabled 0 \
	--stringparam man.copyright.section.enabled 0

.xml.1:
	$(XSLTPROC) $(XSLTPROC_FLAGS) http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

# Based on rpmbuild-cwd, that is:
# Licensed under the new-BSD license (http://www.opensource.org/licenses/bsd-license.php)
# Copyright (C) 2010 Red Hat, Inc.
# Written by Colin Walters <walters@verbum.org>
WD := $(shell pwd)

.PHONY: rpm

bwrap-oci.spec: $(srcdir)/rpm/bwrap-oci.spec.template
	sed -e 's|#VERSION#|$(VERSION)|g' < $< > $@

rpm: dist-gzip bwrap-oci.spec
	echo $(VERSION)
	$(MAKE) -C $(WD) dist-xz
	rpmbuild -ba --define "_sourcedir $(WD)" --define "_specdir $(WD)" --define "_builddir $(WD)" --define "_srcrpmdir $(WD)" --define "_rpmdir $(WD)" --define "_buildrootdir $(WD)/.build" bwrap-oci.spec

man_MANS = bwrap-oci.1

CLEANFILES = $(man_MANS) bwrap-oci.spec

AM_CFLAGS = $(WARN_CFLAGS)

GITIGNOREFILES = build-aux/ gtk-doc.make config.h.in aclocal.m4

bin_PROGRAMS = bwrap-oci

bwrap_oci_SOURCES = \
	bwrap-oci.c \
	list.c \
	safe-read-write.c \
	util.c \
	run.c \
	kill.c \
	spec.c \
	subugidmap.c \
	$(NULL)

bwrap_oci_CFLAGS = $(AM_CFLAGS) $(JSON_GLIB_CFLAGS) $(GIO_UNIX_CFLAGS)
bwrap_oci_LDADD = $(SELINUX_LIBS) $(JSON_GLIB_LIBS) $(GIO_UNIX_LIBS)

-include $(top_srcdir)/git.mk

TESTS = tests/bind.conf tests/cwd.conf tests/env.conf tests/hostname.conf \
	tests/label.conf tests/mount.conf tests/mount-label.conf tests/rootfs.conf \
	tests/seccomp.conf tests/tty.conf tests/uid.conf tests/devtmpfs.conf

TEST_EXTENSIONS = .conf
CONF_LOG_COMPILER = $(top_srcdir)/tests/tests-runner

EXTRA_DIST = autogen.sh bwrap-oci.xml safe-read-write.h util.h list.h run.h kill.h spec.h subugidmap.h

EXTRA_DIST += $(TESTS:.conf=.conf.expected)
EXTRA_DIST += $(TESTS:.conf=.conf.command)
