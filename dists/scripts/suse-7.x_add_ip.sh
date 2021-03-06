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
# This script configure IP alias(es) inside VPS.
#
# Parameters are passed in environment variables.
# Required parameters:
#   IP_ADDR       - IP address(es) to add
#                   (several addresses should be divided by space)
# Optional parameters:
#   VE_STATE      - state of VPS; could be one of:
#                     starting | stopping | running | stopped
#
VENET_DEV=venet0
FAKEGATEWAY=191.255.255.1
FAKEGATEWAYNET=191.255.255.0
CFGFILE=/etc/rc.config

function setup_network()
{
	NETCONFIG_ID=0
	[ -f $CFGFILE ] || return 0
	# Set up venet0 interface config file inside VE
	put_param "$CFGFILE" NETCONFIG "_${NETCONFIG_ID}"
	put_param "$CFGFILE" IPADDR_0 "127.0.0.1"
	put_param "$CFGFILE" NETDEV_0 venet0
	put_param "$CFGFILE" IFCONFIG_0 "127.0.0.1 netmask 255.255.255.255 up"
	put_param "$CFGFILE" IP_FORWARD yes

	# set default routes
	routefile=/etc/route.conf
	if ! grep -qE "127\.0\.0\.1.*255\.255\.255\.255[ 	]*lo" \
		$routefile 2>/dev/null
	then
		echo "127.0.0.1 *     255.255.255.255 lo" >> $routefile
	fi
	if ! grep -qE "default.*0\.0\.0\.0[ 	]*venet0" \
		$routefile 2>/dev/null
	then
		echo "default *       0.0.0.0 venet0" >> $routefile
	fi
}

function get_net_ids()
{

	NETCONFIG_ID=`grep -E "^NETCONFIG=" ${CFGFILE} | head -n1 | sed  -e 's/NETCONFIG=\(.*\)$/\1/' -e 's/["_]//g'`
	[ -z "${NETCONFIG_ID}" ] && NETCONFIG_ID=0
}

function add_ip()
{
	local id ipm ip netconfig aliasid

	# In case we are starting VE
	if [ "x$VE_STATE" = "xstarting" -o "${IPDELALL}" = "yes" ]; then
		setup_network
		[ -z "${IP_ADDR}" ] && return 0
	else
		get_net_ids
	fi
	# create NETCONFIG, IPADDR_x, NETDEV_x and IFCONFIG_x strings
	let IP_NUM=0
	# Get last id
	for id in ${NETCONFIG_ID}; do
		netconfig="${netconfig} _${id}"
		IP_NUM=${id}
	done
	# create appropriate records for each given IP addr
	for ipm in ${IP_ADDR}; do
		ip=${ipm%%/*}
		aliasid=${IP_NUM}
		let IP_NUM=IP_NUM+1
		# build 'IPADDR_x' records
		put_param ${CFGFILE} IPADDR_${IP_NUM} "${ip}"
		# build 'NETDEV_x' records
		put_param ${CFGFILE} NETDEV_${IP_NUM} "venet0:${aliasid}"
		# build 'IFCONFIG_x' records
		put_param ${CFGFILE} IFCONFIG_${IP_NUM} "${ip} up"
		netconfig="${netconfig} _${IP_NUM}"
	done
	put_param ${CFGFILE} NETCONFIG "${netconfig}"
	if [ "x$VE_STATE" = "xrunning" ]; then
		/etc/init.d/network restart
	fi
	chmod 644 $CFGFILE
}

add_ip

exit 0
# end of script
