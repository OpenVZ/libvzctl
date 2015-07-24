#  Copyright (C) 2000-2010 Parallels. All rights reserved.
#

include $(top_srcdir)/paths.am

AM_CPPFLAGS = -Wall -I$(top_srcdir)/include -I$(top_srcdir)/lib \
	      -DSBINDIR=\"$(sbindir)\" \
	      -DPKGCONFDIR=\"$(pkgconfdir)\" \
	      -DPKGLIBDIR=\"$(pkglibdir)\"

#sbin_PROGRAMS = test vzctl
noinst_PROGRAMS = test

VZCTL_LIBS = $(top_builddir)/lib/libvzctl2.la -lpthread


test_SOURCES = test.c test_config.c test_vzctl.c
test_LDADD = $(VZCTL_LIBS) $(UTIL_LIBS)
