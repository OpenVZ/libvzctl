#  Copyright (c) 2000-2017, Parallels International GmbH

include $(top_srcdir)/paths.am

AM_CPPFLAGS = -I. -I./include -I../include \
	      -DSBINDIR=\"$(sbindir)\" \
	      -DPKGCONFDIR=\"$(pkgconfdir)\" \
	      -DPKGLIBDIR=\"$(pkglibdir)\" \
	      -DSCRIPTDIR=\"$(scriptdir)\" \
	      -DSCRIPTDDIR=\"$(scriptddir)\" \
	      -DDISTCONFDIR=\"$(distconfdir)\" \
	      $(XML_CFLAGS) $(DBUS_CFLAGS)

lib_LTLIBRARIES = libvzctl2.la
pkginclude_HEADERS = vzctl_param.h vzerror.h list.h
libvzctl2_la_SOURCES =  bitmap.c \
			bindmount.c \
			cap.c \
			cgroup.c \
			cleanup.c \
			config.c \
			cpt.c \
			cr_criu.c \
			cpu.c \
			create.c \
			destroy.c \
			dev.c \
			dist.c \
			env.c \
			env_ops.c \
			env_vzops.c \
			env_nsops.c \
			env_config.c \
			env_configure.c \
			exec.c \
			fs.c \
			fs_vzfs.c \
			ha.c \
			io.c \
			image.c \
			iptables.c \
			lock.c \
			logger.c \
			meminfo.c \
			name.c \
			net.c \
			quota.c \
			readelf.c \
			res.c \
			scandir.c \
			snapshot.c \
			sysfs_perm.c \
			ub.c \
			util.c \
			veth.c \
			vz.c \
			vzfeatures.c \
			evt.c \
			disk.c \
			disk_configure.c \
			xml.c \
			vzauth.c \
			vztmpl.c \
			cluster.c \
			vzenv.c \
			slm.c \
			tc.c \
			systemd.c \
			nl.c \
			vcmm.c

# 1. Start with version information of `0:0:0' for each libtool library.
# 2. Update the version information only immediately before a public release of your software. More frequent updates are unnecessary, and only guarantee that the current interface number gets larger faster.
# 3. If the library source code has changed at all since the last update, then increment revision (`c:r:a' becomes `c:r+1:a').
# 4. If any interfaces have been added, removed, or changed since the last update, increment current, and set revision to 0.
# 5. If any interfaces have been added since the last public release, then increment age.
# 6. If any interfaces have been removed since the last public release, then set age to 0. 
libvzctl2_la_LDFLAGS = -version-info 2:1:0 -Wl,--version-script=version.map
libvzctl2_la_LIBADD = $(XML_LIBS) $(UTIL_LIBS) $(PLOOP_LIBS) -lcrypt $(UUID_LIBS) $(DBUS_LIBS) $(VCMMD_LIBS)

