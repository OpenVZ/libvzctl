#  Copyright (c) 1999-2017, Parallels International GmbH
# Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#  Our contact details: Virtuozzo International GmbH, Vordergasse 59, 8200
#  Schaffhausen, Switzerland.

include $(top_srcdir)/paths.am

if FULL_BUILD
SUBDIRS = dists lib scripts src
else
SUBDIRS = lib
endif

noinst_HEADERS = $(wildcard include/linux/*.h)
pkginclude_HEADERS = include/libvzctl.h

EXTRA_DIST = libvzctl.spec

rpms: dist
	tar --exclude=.svn --exclude=.git -cjf ../libvzctl.tar.bz2 ../libvzctl
	rpmbuild --nodeps -ta ../libvzctl.tar.bz2 

.PHONY: rpms
