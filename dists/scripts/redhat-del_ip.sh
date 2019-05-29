#!/bin/bash
# Copyright (c) 1999-2017, Parallels International GmbH
# Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
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
# Our contact details: Virtuozzo International GmbH, Vordergasse 59, 8200
# Schaffhausen, Switzerland.
#
# This script deletes IP alias(es) inside VPS for RedHat like systems.
#
# Parameters are passed in environment variables.
# Required parameters:
#   IP_ADDR       - IPs to delete, several addresses should be divided by space
# Optional parameters:
#   IPDELALL      - delete all ip addresses
VENET_DEV=venet0
VENET_DEV_CFG=ifcfg-${VENET_DEV}
IFCFG_DIR=/etc/sysconfig/network-scripts/
IFCFG=${IFCFG_DIR}${VENET_DEV_CFG}

# Function to delete IP address for RedHat like systems
function del_ip()
{
	local ipm ip mask
	local filetodel
	local file
	local aliasid
	local restart_venet0

	[ -d ${IFCFG_DIR} ] || return 0
	cd ${IFCFG_DIR} || return 0
	if [ "x${IPDELALL}" = "xyes" ]; then
		ifdown ${VENET_DEV}
		rm -f ${VENET_DEV_CFG} ${VENET_DEV_CFG}:* 2>/dev/null
		return 0;
	fi
	for ipm in ${IP_ADDR}; do
		ip=${ipm%%/*}
		mask=
		if echo "${ipm}" | grep -q '/'; then
			mask=${ipm##*/}
		fi

		# IPV6 processing
		if is_ipv6 "${ip}"; then
			del_param ${IFCFG} IPV6ADDR_SECONDARIES "${ip}\\/[0-9]*"
			mask=`get_netmask "${VENET_DEV}" "${ip}"`
			if [ -x /sbin/ifconfig ]; then
				/sbin/ifconfig ${VENET_DEV} del "${ip}/${mask}" 2>/dev/null
			else
				/sbin/ip a del "${ip}/${mask}" dev ${VENET_DEV} 2>/dev/null
			fi
			continue
		fi

		# find and delete a file with this alias
		filetodel=`grep -l "IPADDR=${ip}$" \
			${VENET_DEV_CFG}:* 2>/dev/null`
		for file in ${filetodel}; do
			rm -f "${file}"
			aliasid=`echo ${file} | sed s/.*://g`
			if [ -n "${aliasid}" ]; then
				restart_venet0=true
			fi
		done
	done
	if [ "${restart_venet0}" = "true" ]; then
		# synchronyze config files & interfaces
		ifdown venet0 2>/dev/null
		ifup venet0 2>/dev/null
	fi
}

del_ip
exit 0
# end of script
