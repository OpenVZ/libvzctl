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
# This script deletes IP alias(es) inside VPS for SuSE-9.
# For usage info see ve-alias_del(5) man page.
#
# Parameters are passed in environment variables.
# Required parameters:
#   IP_ADDR       - IPs to delete, several addresses should be divided by space
# Optional parameters:
#   VE_STATE      - state of VPS; could be one of:
#                     starting | stopping | running | stopped
VENET_DEV=venet0
IFCFG_DIR=/etc/sysconfig/network/
IFCFG="${IFCFG_DIR}/ifcfg-${VENET_DEV}"
ROUTES=${IFCFG_DIR}/ifroute-${VENET_DEV}

function del_ip()
{
	local cfg="${IFCFG}"
	local ip ipm mask ids id restart_venet0

	[ -d ${IFCFG_DIR} ] || return 0
	[ -f ${cfg} ] || return 0
	cd ${IFCFG_DIR} || return 0
	# synchronyze config files & interfaces

	if [ "x${IPDELALL}" = "xyes" ]; then
		ifdown ${VENET_DEV} 2>/dev/null
		rm -rf ${IFCFG} 2>/dev/null
		rm -f ${ROUTES} 2>/dev/null
		return 0
	fi

	for ipm in ${IP_ADDR}; do
		ip=${ipm%%/*}
		ids=`grep -E "^IPADDR_.*=${ip}$" ${cfg} | \
			 sed 's/^IPADDR_\(.*\)=.*/\1/'`
		for id in ${ids}; do
			sed -e "/^IPADDR_${id}=/d" -e "/^LABEL_${id}=/d" \
				 -e "/^NETMASK_${id}=/d" -e "/^PREFIXLEN_${id}=/d" \
				< ${cfg} > ${cfg}.bak && mv -f ${cfg}.bak ${cfg}
			if is_ipv6 "${ip}"; then
				mask=`get_netmask "${VENET_DEV}" "${ip}"`
				ifconfig ${VENET_DEV} del "${ip}/${mask}" 2>/dev/null
			else
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
