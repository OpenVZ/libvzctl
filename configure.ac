#  Copyright (c) 2000-2017, Parallels International GmbH
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

# Generic configuration
AC_PREREQ(2.59)
AC_INIT(libvzctl, 7.0.726.3, igor@parallels.com)

# Change sysconfdir default since otherwise some important files
# (an initscript, files for logrotate, cron, and udev) will be installed
# to some nonsence/non-working place like under /usr/local/etc/
#
# NOTE: this changes expected configure behavior: if you specify --prefix
#        it will not change sysconfdir, instead now one have to specify
#        --sysconfdir explicitly. To make it more clear we print
#        current sysconfdir value at the end of configure run.
#
# FIXME: dirty hack, may not work with some autoconf versions.
test $sysconfdir = '${prefix}/etc' && sysconfdir=/etc

AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

# If we are on an x86_64, redefine libdir from default value
if test "$target_cpu" = "x86_64" -a "$libdir" = '${exec_prefix}/lib'; then
	if debarch=$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null); then
		# Debian/Ubuntu
		libdir='${exec_prefix}/'$debarch
	else
		# Assume Red Hat/SUSE: libs go to lib64
		libdir='${exec_prefix}/lib64'
	fi
fi

# Automake
AM_INIT_AUTOMAKE([1.6 foreign dist-bzip2])

# Disable build of static libraries by default.
AC_DISABLE_STATIC

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_INSTALL
AC_PROG_LN_S

AC_ARG_WITH([vzevent],
	[AS_HELP_STRING([--without-vzevent],
		[disable vzevent support])],
	[],
	[with_vzevent=yes])
AC_ARG_WITH([vzlibexeconly],
	[AS_HELP_STRING([--with-vzlibexeconly],
		[build libvzctlexec only])],
	[vzlibexec_only=yes],
	[])
AC_ARG_WITH([vcmmd],
	[AS_HELP_STRING([--without-vcmmd],
		[disable vcmmd support])],
	[],
	[with_vcmmd=yes])

# Checks for e2fsprogs lib
AC_CHECK_HEADER([ext2fs/ext2_fs.h], ,
	AC_MSG_ERROR([Please install e2fsprogs devel package]))

AC_CHECK_LIB(util, openpty,
	UTIL_LIBS="-lutil", AC_MSG_ERROR([libutil not found]),)
AC_SUBST(UTIL_LIBS)


AS_IF([test "x$vzlibexec_only" != xyes],
	AC_CHECK_HEADER([ploop/libploop.h], ,
		AC_MSG_ERROR([Please install ploop devel package]))
	AC_CHECK_LIB([ploop], [ploop_replace_image], PLOOP_LIBS="-lploop",
		AC_MSG_ERROR([Please install ploop package]))
	AC_SUBST(PLOOP_LIBS)
	AC_DEFINE(USE_PLOOP)
	AS_IF([test "x$with_vzevent" = xyes],
		AC_CHECK_HEADER([vz/vzevent.h], ,
			AC_MSG_ERROR([Please install libvzevent devel package]))
		AC_CHECK_LIB([vzevent], [vzevt_register], VZEVENT_LIBS="-lvzevent",
			AC_MSG_ERROR([Please install libvzevent devel package]))
		AC_SUBST(VZEVENT_LIBS)
		AC_DEFINE(USE_VZEVENT))
	AS_IF([test "x$with_vcmmd" = xyes],
		AC_CHECK_HEADER([libvcmmd/vcmmd.h], ,
			AC_MSG_ERROR([Please install libvcmmd devel package]))
		AC_CHECK_LIB([vcmmd], [vcmmd_strerror], VCMMD_LIBS="-lvcmmd",
			AC_MSG_ERROR([Please install libvcmmd package]))
		AC_SUBST(VCMMD_LIBS)
		AC_DEFINE(USE_VCMMD))
)


# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE

PKG_CHECK_MODULES([XML], [libxml-2.0 > 2.6.16], ,
	AC_MSG_ERROR([Please install libxml2 devel package]))
PKG_CHECK_MODULES([UUID], [uuid], ,
	AC_MSG_ERROR([Please install libuuid devel package]))

# Compiler settings
#CFLAGS="${CFLAGS} -Wall -Wpointer-arith -Wcast-qual -Winline -Wextra"
CFLAGS="${CFLAGS} -Wall -Werror -Wpointer-arith -Winline"
CFLAGS="${CFLAGS} -Wcast-align -Wno-unused-parameter"
CFLAGS="${CFLAGS} -Wno-missing-field-initializers"
CFLAGS="${CFLAGS} -D_FILE_OFFSET_BITS=64"

if test x$build_cpu = xppc64 -o x$build_cpu = xpowerpc64; then
	CFLAGS="${CFLAGS} -m64"
fi

# Site settings
AM_CONDITIONAL(ARCH_IA64,   test x$build_cpu = xia64)
AM_CONDITIONAL(ARCH_X86_64, test x$build_cpu = xx86_64)


# Final info page
AC_CONFIG_COMMANDS_PRE([SUMMARY="$PACKAGE_STRING configured successfully:

         CC: $CC ($($CC --version | head -n1))
     CFLAGS: '$CFLAGS'
      build: $build
       host: $host
     target: $target
     prefix: $prefix
 sysconfdir: $sysconfdir
     libdir: $libdir
"])

# Output

AM_CONDITIONAL([FULL_BUILD], [test "x$vzlibexec_only" != xyes])

AM_COND_IF([FULL_BUILD],
	[AC_CONFIG_FILES([dists/Makefile
		scripts/Makefile
		src/Makefile
		test/Makefile])])

AC_CONFIG_FILES([lib/Makefile Makefile])
AC_OUTPUT

AC_MSG_NOTICE([$SUMMARY])
