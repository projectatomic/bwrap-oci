# Based on rpmbuild-cwd, that is:
# Licensed under the new-BSD license (http://www.opensource.org/licenses/bsd-license.php)
# Copyright (C) 2010 Red Hat, Inc.
# Written by Colin Walters <walters@verbum.org>
WD := $(shell pwd)

rpm:
	$(MAKE) -C $(WD)/.. dist-xz
	rpmbuild -ba --define "_sourcedir $(WD)/.." --define "_specdir $(WD)" --define "_builddir $(WD)" --define "_srcrpmdir $(WD)" --define "_rpmdir $(WD)" --define "_buildrootdir $(WD)/.build" bwrap-oci.spec
