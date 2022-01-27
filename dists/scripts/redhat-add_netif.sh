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
# This script configure IP alias(es) inside RedHat like VE.
#
# Parameters are passed in environment variables.
# Required parameters:
#   IP_ADDR       - IP address(es) to add
#                   (several addresses should be divided by space)
# Optional parameters:
#   VE_STATE        - state of VPS; could be one of:
#                     starting | stopping | running | stopped
#   DEVICE	    - device name
#   IPADD    	    - list of ip addresses in format <ip[/mask] | dhcp>
#   IPDEL    	    - list of ip addresses in format <ip | all>
#   GW	    	    - gateway ip
#
IFCFG_DIR=/etc/sysconfig/network-scripts
NETFILE=/etc/sysconfig/network
IFNUMLIST=
IFRMLIST=
IFNUM=

set_route()
{
	local dev=$1
	echo "default dev $dev" > $IFCFG_DIR/route-$dev || \
		error "Unable to create $IFCFG_DIR/route-$dev" ${VZ_FS_NO_DISK_SPACE}
}

set_route6()
{
	local dev=$1
	echo "fe80::ffff:1:1 dev $dev
default via fe80::ffff:1:1 dev $dev" > $IFCFG_DIR/route6-$dev || \
		error "Unable to create $IFCFG_DIR/route6-$dev" ${VZ_FS_NO_DISK_SPACE}
}

function create_config()
{
	local dev=$1
	local ifcfg=${IFCFG_DIR}/ifcfg-${dev}
	local cfg

	if [ "$NETWORK_TYPE" = "routed" ]; then
		set_route $dev
		set_route6 $dev
		cfg="# $ROUTED_UUID $dev
ARPUPDATE=no
ARPCHECK=no"
	fi

	cfg="$cfg
DEVICE=$dev
ONBOOT=yes
BOOTPROTO=static
NM_CONTROLLED=no"
	echo "${cfg}" > ${ifcfg} || error "Unable to create interface config file ${ifcfg}" ${VZ_FS_NO_DISK_SPACE}
}

function get_aliasid_by_ip()
{
	local ip=$1
	local idlist

	cd ${IFCFG_DIR} || return 1
	IFNUM=`grep -l -e "IPADDR=${ip}$" -e "IPADDR=\"${ip}\"" ifcfg-${DEVICE}:* 2>/dev/null | \
		head -n 1 | sed -e 's/.*:\([0-9]*\)$/\1/'`
	if [ -n "${IFNUM}" ]; then
		return
	fi
	grep -q "IPADDR=${ip}\$" ifcfg-${DEVICE} 2>/dev/null
	if [ $? -eq 0 ]; then
		IFNUM=
		return
	fi
	grep -q "IPADDR=" ifcfg-${DEVICE} 2>/dev/null
	if [ $? -eq 1 ]; then
		IFNUM=
		return
	fi

	get_free_aliasid
}

function reset_master()
{
	local f

	cd ${IFCFG_DIR} || return 1
	for f in `ls -1 ifcfg-${DEVICE}:* 2>/dev/null`; do
		mv -f ${f} ifcfg-${DEVICE} 2>/dev/null && \
			sed -i 's/DEVICE=.*/DEVICE='${DEVICE}'/' ifcfg-${DEVICE} 2>/dev/null
		break
	done
}

function rm_if_by_ip()
{
	local ip=$1
	local files

	cd ${IFCFG_DIR} 2>/dev/null || return 1
	files=`grep -l -e "IPADDR=${ip}$" -e "IPADDR=\"${ip}\"" ifcfg-${DEVICE}:* ifcfg-${DEVICE} 2>/dev/null | tr '\n' ' ' | sed -e 's/^\ *$//'`
	if [ -n "${files}" ]; then
		IFRMLIST="${IFRMLIST} ${files}"
	fi
}

function get_all_aliasid()
{
	cd ${IFCFG_DIR} || return 1
	IFNUMLIST=`ls -1 ifcfg-${DEVICE}:* 2>/dev/null | \
		sed "s/.*ifcfg-${DEVICE}://"`
}

function get_free_aliasid()
{
	local found=

	[ -z "${IFNUMLIST}" ] && get_all_aliasid
	[ -z "${IFNUM}" ] && IFNUM=-1
	while test -z ${found}; do
		let IFNUM=IFNUM+1
		echo "${IFNUMLIST}" | grep -q -E "^${IFNUM}$" 2>/dev/null || \
			found=1
	done
}

# Function to delete IP address for RedHat like systems
function del_ips()
{
	local ips="$1"
	local ip ipm mask
	local file

	[ -z "${ips}" ] && return 0
	cd ${IFCFG_DIR} >/dev/null 2>&1 || return 0
	# synchronyze config files & interfaces
	for ipm in ${ips}; do
		ip=${ipm%%/*}
		if [ "${ip}" = "all" ]; then
			IFRMLIST="ifcfg-${DEVICE}:* ifcfg-${DEVICE}"
			del_param "${IFCFG_DIR}/ifcfg-${DEVICE}" IPV6ADDR_SECONDARIES
		else
			if is_ipv6 "${ip}"; then
				del_param "${IFCFG_DIR}/ifcfg-${DEVICE}" IPV6ADDR_SECONDARIES "${ip}\\/[0-9]*"
			else
				rm_if_by_ip "${ip}"
			fi
		fi
	done
	if [ -n "${IFRMLIST}" ]; then
		cd ${IFCFG_DIR} 2>/dev/null
		for cfg in ${IFRMLIST}; do
			if [ "${cfg}" = "ifcfg-${DEVICE}" ]; then
				del_param ${IFCFG_DIR}/${cfg} IPADDR
				del_param ${IFCFG_DIR}/${cfg} NETMASK
			else
				rm -f ${cfg} 2>/dev/null
			fi
		done
		if [ ! -f ifcfg-${DEVICE} ]; then
			reset_master
		fi
		ifup ${DEVICE} 2>/dev/null
		IFRMLIST=
	fi
}

function update_dev()
{
	local ips="$1"
	local ifcfg=${IFCFG_DIR}/ifcfg-${DEVICE}
	local ipm ip mask dev

	if [ "${VE_STATE}" != "starting" ]; then
		ifdown ${DEVICE} 2>/dev/null
	fi
	if [ "$DHCP4" = "yes" ]; then
		check_dhcp
		put_param ${ifcfg} DEVICE "${DEVICE}"
		put_param ${ifcfg} ONBOOT yes
		put_param ${ifcfg} BOOTPROTO "dhcp"
		del_param ${ifcfg} IPADDR
		del_param ${ifcfg} NETMASK
		del_param ${ifcfg} GATEWAY
		rm -f ${IFCFG_DIR}/ifcfg-${DEVICE}:* 2>/dev/null
		setup_default_route 'remove'
	elif [ "$DHCP4" = "no" ]; then
		put_param ${ifcfg} BOOTPROTO "static"
	fi
	if [ "$DHCP6" = "yes" ]; then
		check_dhcp_ipv6
		put_param ${ifcfg} DEVICE "${DEVICE}"
		put_param ${ifcfg} ONBOOT yes
		put_param ${ifcfg} DHCPV6C "yes"
		del_param ${ifcfg} IPV6ADDR_SECONDARIES
		del_param ${ifcfg} IPV6_DEFAULTGW
		setup_default_route 'remove' '-6'
	elif [ "$DHCP6" = "no" ]; then
		put_param ${ifcfg} DHCPV6C "no"
	fi

	# synchronyze config files & interfaces
	for ipm in ${ips}; do
		ip=${ipm%%/*}
		mask=${ipm##*/}

		[ "$mask" = "$ipm" ] && mask=

		if is_ipv6 "${ip}"; then
			add_ipv6 "$ip" "$mask"
		else
			dev=${DEVICE}
			[ -z "$mask" ] && mask=255.255.255.0
			get_aliasid_by_ip ${ip}
			if [ -n "${IFNUM}" ]; then
				if [ -f ${IFCFG_DIR}/ifcfg-${DEVICE} ]; then
					dev=${DEVICE}:${IFNUM}
					IFNUMLIST="${IFNUMLIST}
${IFNUM}"
				fi
				create_config "${dev}"
			fi
			ifcfg=${IFCFG_DIR}/ifcfg-$dev
			put_param ${ifcfg} DEVICE $dev
			put_param ${ifcfg} IPADDR $ip
			put_param ${ifcfg} NETMASK $mask
		fi
	done

	if [ "${VE_STATE}" != "starting" ]; then
		ifup ${DEVICE}
	fi
}

function add_ipv6()
{
	local ifcfg="${IFCFG_DIR}/ifcfg-${DEVICE}"
	local ip=$1
	local mask=$2

	put_param ${NETFILE} NETWORKING_IPV6 yes
	put_param ${ifcfg} DEVICE "${DEVICE}"
	put_param ${ifcfg} ONBOOT yes
	put_param ${ifcfg} IPV6INIT yes
	[ "$NETWORK_TYPE" = "routed" ] && mask=128
	if ! grep -qw "${ip}" ${ifcfg} 2>/dev/null; then
		[ -z "$mask" ] && mask=64
		add_param ${ifcfg} IPV6ADDR_SECONDARIES "$ip/$mask"
		if_restart=yes
	fi
}

setup_default_route()
{
	local proto=$2
	local dev

	dev=$(get_routed_default_dev)
	[ -z $dev ] && return

	case "$1" in
	"remove")
		if [ "$proto" == "-6" ]; then
			rm  -f $IFCFG_DIR/route6-$dev
		else
			rm  -f $IFCFG_DIR/route-$dev
		fi
		;;
	"restore")
		if [ "$proto" == "-6" ]; then
			set_route6 $dev
		else
			set_route $dev
		fi
		ip $proto r r default dev $dev 2>/dev/null
		;;
	esac
}

function setup_gw()
{
	local cfg=
	local changed=
	local cfg=${IFCFG_DIR}/ifcfg-${DEVICE}

	if [ -n "${GWDEL}" ]; then
		setup_default_route 'restore'
		del_param $cfg GATEWAY
		changed=yes
	fi
	if [ -n "${GW6DEL}" ]; then
		setup_default_route 'restore' '-6'
		del_param $cfg IPV6_DEFAULTGW
		changed=yes
	fi
	if [ -n "${DEFAULT_GW}" ]; then
		if is_ipv6 "${DEFAULT_GW}"; then
			put_param $NETFILE IPV6_DEFAULTGW ${DEFAULT_GW}
		else
			put_param $NETFILE GATEWAY ${DEFAULT_GW}
		fi
		changed=yes
	fi
	if [ -n "${GW}" ]; then
		setup_default_route 'remove'
		put_param ${cfg} GATEWAY ${GW}
		changed=yes
	fi
	if [ -n "${GW6}" ]; then
		setup_default_route 'remove' '-6'
		put_param $cfg IPV6_DEFAULTGW ${GW6}
		changed=yes
	fi

	if [ -n "${changed}" ]; then
		if [ "${VE_STATE}" != "starting" ]; then
			/etc/init.d/network restart
		fi
	fi
}

function setup()
{
	local cfg=${IFCFG_DIR}/ifcfg-${DEVICE}

	mkdir -p ${IFCFG_DIR} 2>/dev/null
	if [ "${VE_STATE}" = "starting" ]; then
		rm -f ${cfg}:* ${cfg} >/dev/null 2>&1
		put_param $NETFILE NETWORKING yes
	fi

	[ ! -e "$cfg" ] && create_config $DEVICE

	del_ips "${IPDEL}"
	update_dev "${IPADD}"
	setup_gw
}

setup
exit 0
# end of script
