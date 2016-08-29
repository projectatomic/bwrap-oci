# Based on rpmbuild-cwd, that is:
# Licensed under the new-BSD license (http://www.opensource.org/licenses/bsd-license.php)
# Copyright (C) 2010 Red Hat, Inc.
# Written by Colin Walters <walters@verbum.org>

rpm:
	PWD=$(pwd)
	make -C .. dist-xz
	rpmbuild -ba --define "_sourcedir ${PWD}/.." --define "_specdir ${PWD}" --define "_builddir ${PWD}" --define "_srcrpmdir ${PWD}" --define "_rpmdir ${PWD}" --define "_buildrootdir ${PWD}/.build" bwrap-oci.spec
