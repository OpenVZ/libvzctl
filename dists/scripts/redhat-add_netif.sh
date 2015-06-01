#!/bin/bash
# Copyright (C) 1999-2015 Parallels IP Holdings GmbH
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
# Our contact details: Parallels IP Holdings GmbH, Vordergasse 59, 8200
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

function create_config()
{
	local dev=$1
	local ip=$2
	local mask=$3
	local ifcfg=${IFCFG_DIR}/ifcfg-${dev}
	local cfg

	cfg="DEVICE=${dev}
ONBOOT=yes
BOOTPROTO=static
IPADDR=\"$ip\""
	if [ -n "${mask}" ]; then
		cfg="$cfg
NETMASK=\"${mask}\""
	fi

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

function get_gw_ip()
{
	grep -m 1 -e '^GATEWAY=' $1 2>/dev/null | sed 's/^GATEWAY="\(.*\)"/\1/'
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
	[ -d ${IFCFG_DIR} ] || return 0
	cd ${IFCFG_DIR} || return 0
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
		setup_default_venet_route 'remove'
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
		setup_default_venet_route 'remove' '-6'
	elif [ "$DHCP6" = "no" ]; then
		put_param ${ifcfg} DHCPV6C "no"
	fi

	# synchronyze config files & interfaces
	for ipm in ${ips}; do
		ip=${ipm%%/*}
		if echo "${ipm}" | grep -q '/'; then
			mask=${ipm##*/}
		else
			mask=
		fi
		if is_ipv6 "${ip}"; then
			add_ipv6 "${ip}" "${mask}"
		else
			dev=${DEVICE}
			get_aliasid_by_ip ${ip}
			if [ -n "${IFNUM}" ]; then
				if [ -f ${IFCFG_DIR}/ifcfg-${DEVICE} ]; then
					dev=${DEVICE}:${IFNUM}
					IFNUMLIST="${IFNUMLIST}
${IFNUM}"
				fi
				create_config "${dev}" "${ip}" "${mask}"
			else
				put_param ${ifcfg} DEVICE "${DEVICE}"
				put_param ${ifcfg} ONBOOT yes
				put_param ${ifcfg} IPADDR "${ip}"
				put_param ${ifcfg} NETMASK "${mask}"
			fi
		fi
	done

	if [ "${VE_STATE}" != "starting" ]; then
		ifup ${DEVICE} 2>/dev/null
	fi
}

function add_ipv6()
{
	local ifcfg="${IFCFG_DIR}/ifcfg-${DEVICE}"
	local ip=$1
	local mask=$2
	local ipm

	put_param ${NETFILE} NETWORKING_IPV6 yes
	put_param ${ifcfg} DEVICE "${DEVICE}"
	put_param ${ifcfg} ONBOOT yes
	put_param ${ifcfg} IPV6INIT yes
	if ! grep -qw "${ip}" ${ifcfg} 2>/dev/null; then
		if [ -n "${mask}" ]; then
			ipm="${ip}/${mask}"
		else
			ipm="${ip}/64"
		fi
		add_param ${ifcfg} IPV6ADDR_SECONDARIES "${ipm}"
		if_restart=yes
	fi
}

setup_default_venet_route()
{
	local cfg=${IFCFG_DIR}/ifcfg-venet0
	local proto=$2
	local param_nm param_venet0_nm

	if [ "$proto" == "-6" ]; then
		param_nm=IPV6_DEFAULTGW
		param_venet0_nm=IPV6_DEFAULTDEV
	else
		param_nm=GATEWAY
		param_venet0_nm=GATEWAYDEV
		fi

	case "$1" in
	"remove")
		del_param "$cfg" "$param_venet0_nm"
		ip $proto r d default dev venet0 2>/dev/null
		;;
	"restore")
		if grep -q "$param_nm" ${IFCFG_DIR}/ifcfg-${DEVICE} 2>/dev/null; then
			put_param "$cfg" "$param_venet0_nm" venet0
			ip $proto r r default dev venet0 2>/dev/null
		fi
		;;
	esac
}

function setup_gw()
{
	local cfg=
	local changed=
	local cfg=${IFCFG_DIR}/ifcfg-${DEVICE}

	if [ -n "${GWDEL}" ]; then
		setup_default_venet_route 'restore'
		del_param $cfg GATEWAY
		changed=yes
	fi
	if [ -n "${GW6DEL}" ]; then
		setup_default_venet_route 'restore' '-6'
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
		setup_default_venet_route 'remove'
		put_param ${cfg} GATEWAY ${GW}
		changed=yes
	fi
	if [ -n "${GW6}" ]; then
		setup_default_venet_route 'remove' '-6'
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

	if [ ! -d "${IFCFG_DIR}" ]; then
		mkdir -p ${IFCFG_DIR} 2>/dev/null
	fi
	if [ -n  "${DEVICE}" ]; then
		if [ "${VE_STATE}" = "starting" ]; then
			rm -f ${IFCFG_DIR}/ifcfg-${DEVICE}:* ${IFCFG_DIR}/ifcfg-${DEVICE} >/dev/null 2>&1
			put_param $NETFILE NETWORKING yes
			if [ "${IPV6}" = "yes" ]; then
				put_param ${NETFILE} NETWORKING_IPV6 yes
			fi
		fi
		del_ips "${IPDEL}"
		update_dev "${IPADD}"
		setup_gw
	fi
}

setup
exit 0
# end of script
