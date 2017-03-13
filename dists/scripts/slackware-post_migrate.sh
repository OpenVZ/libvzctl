#!/bin/bash
# Copyright (c) 1999-2017, Parallels International GmbH
#
# This file is part of OpenVZ libraries. OpenVZ is free software; you can
# redistribute it and/or modify it under the terms of the GNU Lesser General
# Public License as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.
#
# Our contact details: Parallels International GmbH, Vordergasse 59, 8200
# Schaffhausen, Switzerland.

EXT='.migsave'

function backup()
{
	local file=$1
	echo "slackware-post_migrate: modifying ${file}"
	[ -f "${file}${EXT}" ] || cp -fp "${file}" "${file}${EXT}"
}

function mk_mtab()
{
	cp -fp /etc/rc.d/rc.S /etc/rc.d/rc.S.tmp || return
	sed -e  's/\/bin\/rm -f \/etc\/mtab.*/#&/' < /etc/rc.d/rc.S > \
		/etc/rc.d/rc.S.tmp && mv -f /etc/rc.d/rc.S.tmp /etc/rc.d/rc.S
	[ -e /etc/mtab ] && rm -f /etc/mtab
	ln -sf /proc/mounts /etc/mtab
}

function make_dev()
{
	[ -d /dev ] || mkdir -p /dev
	cd /dev
	MAKEDEV std urandom pty console ptmx
}

# Do not launch mingetty on tty devices - they are not accessible from
# VPS
CFG_FILE=/etc/inittab
if [ -f ${CFG_FILE} ]; then
	backup ${CFG_FILE}
	cp -fp  ${CFG_FILE} ${CFG_FILE}.$$
	sed '/^.*getty.*$/d' < ${CFG_FILE} > ${CFG_FILE}.$$ \
		&& mv -f ${CFG_FILE}.$$ ${CFG_FILE}
	if [ $? -ne 0 ]; then
		rm -f ${CFG_FILE}.$$ 2>/dev/null
	fi
fi

if [ -x /sbin/klogd ]; then
	ln -sf /bin/true /sbin/klogd 2>/dev/null
fi

# Fix /etc/fstab
CFG_FILE=/etc/fstab
backup ${CFG_FILE}
sed -e '/^\s*$\|^\s*\#\|devpts\|proc/! {s/\(.*\)/#mig# \1/;}' < ${CFG_FILE} > \
	${CFG_FILE}.$$ && mv ${CFG_FILE}.$$ ${CFG_FILE}

# Fix /etc/syslog.conf
CFG_FILE=/etc/syslog.conf
if [ -f ${CFG_FILE} ]; then
	backup ${CFG_FILE}
	cp -fp  ${CFG_FILE} ${CFG_FILE}.$$
	sed -e 's/\([[:space:]]\)\(\/var\/log\/\)/\1-\2/g' \
		< ${CFG_FILE} > ${CFG_FILE}.$$ \
		&& mv -f ${CFG_FILE}.$$ ${CFG_FILE}
	if [ $? -ne 0 ]; then
		rm -f ${CFG_FILE}.$$ 2>/dev/null
	fi
fi

mk_mtab
make_dev
exit 0
