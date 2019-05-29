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
# This script configure IP alias(es) inside Gentoo like VPS.
#
# Parameters are passed in environment variables.
# Required parameters:
#   IP_ADDR       - IP address(es) to add
#                   (several addresses should be divided by space)
# Optional parameters:
#   VE_STATE      - state of VPS; could be one of:
#                     starting | stopping | running | stopped
#   IPDELALL	  - delete all old interfaces
#
DEV=

IFCFG_DIR=/etc/conf.d
IFCFG=${IFCFG_DIR}/net

function fix_net()
{
	[ -f "/etc/runlevels/default/net.${DEV}" ] && return 0
	rc-update add net.${DEV} default &>/dev/null
}

function setup_network()
{
	fix_net
	put_param3 ${IFCFG} "config_${DEV}" ""
	# add fake route
#	put_param3 ${IFCFG} "routes_${DEV}" \
#		"-net ${FAKEGATEWAYNET}/24" # dev ${VENET_DEV}
#	add_param3 ${IFCFG} "routes_${DEV}" "default via ${FAKEGATEWAY}"
}

function add_ip()
{
	local ip=$1
	local mask=$2

	[ -n "${mask}" ] && ip="${ip} netmask ${mask}"
	grep -qw "${ip}" ${IFCFG} || \
		add_param3 "${IFCFG}" "config_${DEV}" "${ip}"
}

function del_ip()
{
	local ips="$1"

	for ipm in ${ips}; do
		ip=${ipm%%/*}
		if [ "$ip" = "all" ]; then
			put_param3 "${IFCFG}" "config_${DEV}" ""
			break
		fi
		grep -qw "config_${DEV}=.*${ip}" ${IFCFG} && \
			sed -i 's/\("'${ip}'[^"]*\)"//' ${IFCFG}
	done
}

function setup_dev()
{
	local ips="$1"
	local ipm ip mask

	if [ "${ips}" = "dhcp" ]; then
		check_dhcp
		put_param3 ${IFCFG} "config_${DEV}" "dhcp"
		return
	elif grep -qw "config_${DEV}=.*dhcp" ${IFCFG} 2>/dev/null; then
		del_param3 ${IFCFG} "config_${DEV}" "dhcp"
	fi
	for ipm in ${ips}; do
		ip=${ipm%%/*}
		if echo "${ipm}" | grep -q '/'; then
			mask=${ipm##*/}
		else
			mask=
		fi
		add_ip "${ip}" "${mask}"
	done
}

function setup()
{
	local ips gw ips_del

	for DEV in ${DEVICE}; do
		if [ "${VE_STATE}" = "starting" ]; then
			setup_network
			setup_dev "${IPADD}"
		else
			del_ip "${IPDEL}"
			setup_dev "${IPADD}"
			/etc/init.d/net.${DEV} restart
		fi
#		setup_gw "${GW}"
	done
}

setup
exit 0
# end of script
