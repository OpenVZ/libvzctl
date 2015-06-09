#  Copyright (c) 1999-2010, Parallels, Inc. All rights reserved.
#

include $(top_srcdir)/paths.am

SUBDIRS = dists lib scripts src

noinst_HEADERS = $(wildcard include/linux/*.h)
pkginclude_HEADERS = include/libvzctl.h

EXTRA_DIST = libvzctl.spec

rpms: dist
	tar --exclude=.svn --exclude=.git -cjf ../libvzctl.tar.bz2 ../libvzctl
	rpmbuild --nodeps -ta ../libvzctl.tar.bz2 

.PHONY: rpms
