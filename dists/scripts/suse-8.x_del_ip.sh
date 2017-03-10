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
# This script deletes IP alias(es) inside VPS for SuSE-8 like systems.
#
# Parameters are passed in environment variables.
# Required parameters:
#   IP_ADDR       - IPs to delete, several addresses should be divided by space
# Optional parameters:
#   IPDELALL      - delete all ip addresses
VENET_DEV=venet0
VENET_DEV_CFG=ifcfg-${VENET_DEV}
IFCFG_DIR=/etc/sysconfig/network/

function del_ip()
{
	local ipm ip
	local filetodel
	local file
	local aliasid

	[ -d ${IFCFG_DIR} ] || return 0
	cd ${IFCFG_DIR} || return 0
	if [ "x${IPDELALL}" = "xyes" ]; then
		ifdown ${VENET_DEV}
		rm -rf ${VENET_DEV_CFG}:* >/dev/null 2>&1
		rm -f ${VENET_DEV_CFG} >/dev/null 2>&1
		return 0;
	fi
	for ipm in ${IP_ADDR}; do
		ip=${ipm%%/*}
		# find and delete a file with this alias
		filetodel=`grep -l "IPADDR=${ip}$" \
			${VENET_DEV_CFG}:* 2>/dev/null`
		for file in ${filetodel}; do
			rm -f "${file}"
			aliasid=`echo ${file} | sed s/.*://g`
			if [ -n "${aliasid}" ]; then
				ifconfig  ${VENET_DEV}:${aliasid} down >/dev/null 2>&1
			fi
		done
	done
}

del_ip
exit 0
# end of script
