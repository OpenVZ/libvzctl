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

function get_ip6_alias()
{
	local dev=$1

	awk '
		BEGIN {ip=""}
		NF == 0 {next}
		$1 == "iface" && $2 ~/'${dev}'$/ && $3 ~/inet6/ {
			while (1==1) {
				if (!getline) break;
				if ($0 ~ "\tup ip addr add") { ip = ip " " $5; }
				else if ($1 == "address" || $1 == "netmask" || $0 ~ "\tup ip") continue
				else break
			}
		}
		END {
			print ip
		}
	' < ${CFGFILE}
}

function rm_if_by_ip()
{
	local ip=$1
	local dev
	local

	dev=`grep -B 1 -w "${ip}" ${CFGFILE} 2>/dev/null | grep iface | \
		sed 's/^iface \(.*\) inet.*/\1/'`
	if [ -z "${dev}" ]; then
		sed -i "/${ip}\/[0-9]*/d" ${CFGFILE}
		return
	fi
	if is_ipv6 "${ip}"; then
		ips=`get_ip6_alias "${dev}"`
		remove_debian_interface_by_proto "$dev" inet6 ${CFGFILE}
		add_debian_ip6 "${ips}"
	else
		remove_debian_interface_by_proto "$dev" inet ${CFGFILE}
	fi
}

function del_ip()
{
	local ipm ip mask

	if [ "x${IPDELALL}" = "xyes" ]; then
		ifdown ${VENET_DEV} 2>/dev/null
		ip a flush dev ${VENET_DEV}
		remove_debian_interface "${VENET_DEV}:[0-9]*" ${CFGFILE}
		remove_debian_interface "${VENET_DEV}" ${CFGFILE}
		return
	fi
	for ipm in ${IP_ADDR}; do
		ip=${ipm%%/*}
		rm_if_by_ip "${ip}"
		mask=`get_netmask "${VENET_DEV}" "${ip}"`
		for m in $mask; do
			ip a d dev ${VENET_DEV} "${ip}/$m" 2>/dev/null
		done
	done
}

del_ip
exit 0
# end of script
