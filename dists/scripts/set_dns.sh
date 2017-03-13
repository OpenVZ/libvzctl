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
# This script sets up resolver inside VPS
# For usage info see vz-veconfig(5) man page.
#
# Some parameters are passed in environment variables.
# Required parameters:
#   SEARCHDOMAIN
#       Sets search domain(s). Modifies /etc/resolv.conf
#   NAMESERVER
#       Sets name server(s). Modifies /etc/resolv.conf
RESOLVCONF=/etc/resolvconf/resolv.conf.d/base

set_dns()
{
	local cfgfile="$1"
	local server="$2"
	local search="$3"
	local post_configure_cmd=
	local srv fname

	# Use resolvconf static storage
	if which resolvconf >/dev/null 2>&1; then
		cfgfile=$RESOLVCONF
		[ "${VE_STATE}" = "running" ] && post_configure_cmd='resolvconf -u'
	fi

	if [ -n "${search}" ]; then
		if [ "${search}" = '#' ]; then
			sed "/search.*/d" < ${cfgfile} > ${cfgfile}.$$ && \
				if [ $? -ne 0 ]; then
					rm -f ${cfgfile}.$$
					error "Can't change file ${cfgfile}" ${VZ_FS_NO_DISK_SPACE}
				fi
				mv -f ${cfgfile}.$$ ${cfgfile} || rm -f ${cfgfile}.$$
		else
			put_param2 "${cfgfile}" search "${search}"
		fi
	fi
	if [ -n "${server}" ]; then
		[ -f "${cfgfile}" ] || touch "${cfgfile}"
		${CP} ${cfgfile} ${cfgfile}.$$ || error "Can't copy file $cfgfile" $VZ_FS_NO_DISK_SPACE
		sed "/nameserver.*/d" ${cfgfile} > ${cfgfile}.$$
		if [ $? -ne 0 ]; then
			rm -f ${cfgfile}.$$
			error "Can't change file ${cfgfile}" ${VZ_FS_NO_DISK_SPACE}
		fi

		if [ "${server}" != '#' ]; then
			for srv in ${server}; do
				echo "nameserver ${srv}" >> ${cfgfile}.$$ || \
					 error "Can't change file ${cfgfile}" ${VZ_FS_NO_DISK_SPACE}
			done
		fi

		mv -f ${cfgfile}.$$ ${cfgfile} || rm -f ${cfgfile}.$$
	fi

	[ -n "${post_configure_cmd}" ] && ${post_configure_cmd}
}

set_dns /etc/resolv.conf "${NAMESERVER}" "${SEARCHDOMAIN}"

exit 0
