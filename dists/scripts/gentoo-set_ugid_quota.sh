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
#
# This script configures quota startup script inside VPS
#
# Parameters are passed in environment variables.
# Required parameters:
#   MINOR	- root device minor number
#   MAJOR	- root device major number
SCRIPTNAME='/etc/init.d/vzquota'
DEFAULT="/etc/runlevels/default/vzquota"

setup_vzquota()
{
	if [ -z "$MAJOR" ]; then
		rm -f ${SCRIPTNAME} > /dev/null 2>&1
		rm -f ${DEFAULT} > /dev/null 2>&1
		rm -f /etc/mtab > /dev/null 2>&1
		ln -sf /proc/mounts /etc/mtab
		exit 0
	fi

	echo -e '#!/sbin/runscript

start() {
	[ -e "/dev/'${DEVFS}'" ] || mknod /dev/'${DEVFS}' b '$MAJOR' '$MINOR'
	rm -f /etc/mtab >/dev/null 2>&1
	echo "/dev/'${DEVFS}' / reiserfs rw,usrquota,grpquota 0 0" > /etc/mtab
	mnt=`grep -v " / " /proc/mounts`
	if [ $? == 0 ]; then
		echo "$mnt" >> /etc/mtab
	fi
	quotaon -aug
	return
}

stop() {
	return
}

' > ${SCRIPTNAME} || {
		echo "Unable to create ${SCRIPTNAME}"
		exit 1
	}
	chmod 755 ${SCRIPTNAME}

	ln -sf ${SCRIPTNAME} ${DEFAULT}
}

if grep -q '/dev/ploop' /proc/mounts; then
	setup_quota
else
	setup_vzquota
fi

exit 0
