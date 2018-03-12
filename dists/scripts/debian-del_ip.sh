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
# This script deletes IP alias(es) inside VPS for Debian like distros.
# For usage info see ve-alias_del(5) man page.
#
# Parameters are passed in environment variables.
# Required parameters:
#   IP_ADDR       - IPs to delete, several addresses should be divided by space
# Optional parameters:
#   VE_STATE      - state of VPS; could be one of:
#                     starting | stopping | running | stopped
VENET_DEV=venet0
CFGFILE=/etc/network/interfaces

function del_ip()
{
	local ifname
	local ipm ip mask
	local restart_venet0

	if [ "x${IPDELALL}" = "xyes" ]; then
		ifdown ${VENET_DEV} 2>/dev/null
		ip a flush dev ${VENET_DEV}
		remove_debian_interface "${VENET_DEV}:[0-9]*" ${CFGFILE}
		remove_debian_interface "${VENET_DEV}" ${CFGFILE}
		return
	fi
	for ipm in ${IP_ADDR}; do
		ip=${ipm%%/*}
		if is_ipv6 "${ip}"; then
			sed -i "/${ip}\/[0-9]*/d" ${CFGFILE}
			mask=`get_netmask "${VENET_DEV}" "${ip}"`
			ifconfig ${VENET_DEV} del "${ip}/${mask}" 2>/dev/null
			continue
		fi
		ifname=`grep -B 1 -w "${ip}" ${CFGFILE} | \
			grep "${VENET_DEV}:" | cut -d' ' -f2`
		if [ -n "${ifname}" ]; then
			restart_venet0=true
			ifconfig ${ifname} down
			remove_debian_interface "${ifname}" ${CFGFILE}
		fi
	done
	if [ "${restart_venet0}" = "true" ]; then
		# synchronyze config files & interfaces
                /sbin/ifup -a --force #2>/dev/null
	fi
}

del_ip
exit 0
# end of script
