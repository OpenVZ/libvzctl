#  Copyright (C) 2000-2010 Parallels. All rights reserved.
#

include $(top_srcdir)/paths.am

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/lib \
	      -DSBINDIR=\"$(sbindir)\" \
	      -DPKGCONFDIR=\"$(pkgconfdir)\" \
	      -DPKGLIBDIR=\"$(pkglibdir)\"

exec_wrapdir=$(pkglibdir)

exec_wrap_PROGRAMS = exec_wrap

VZCTL_LIBS = $(top_builddir)/lib/libvzctl2.la -lpthread $(UUID_LIBS)


exec_wrap_SOURCES = exec_wrap.c
exec_wrap_LDADD = $(VZCTL_LIBS) $(UTIL_LIBS)

