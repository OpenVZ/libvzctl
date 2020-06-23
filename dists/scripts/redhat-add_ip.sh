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
# This script configure IP alias(es) inside RedHat like VPS.
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
VENET_DEV=venet0
VENET_DEV_CFG=ifcfg-$VENET_DEV

IFCFG_DIR=/etc/sysconfig/network-scripts
IFCFG=${IFCFG_DIR}/ifcfg-${VENET_DEV}
NETFILE=/etc/sysconfig/network
HOSTFILE=/etc/hosts

function fix_ifup()
{
	file="/sbin/ifup"

	[ -f "${file}" ] || return 0
	[ "x${VE_STATE}" != "xstarting" ] && return 0

	if grep -q 'if \[ "\${DEVICE}" = "lo" \]; then' ${file} 2>/dev/null
	then
		${CP} ${file} ${file}.$$ || return 1
		/bin/sed -e 's/if \[ "\${DEVICE}" = "lo" \]; then/if \[ "${IPADDR}" = "127.0.0.1" \]; then/g' < ${file} > ${file}.$$ && \
			mv -f ${file}.$$ ${file}
		rm -f ${file}.$$ 2>/dev/null
	fi
}

function init_config()
{
	# Set up venet0 main interface as 127.0.0.1
	mkdir -p ${IFCFG_DIR}
	echo "DEVICE=${VENET_DEV}
BOOTPROTO=static
ONBOOT=yes
IPADDR=127.0.0.1
NETMASK=255.255.255.255
BROADCAST=0.0.0.0
NM_CONTROLLED=\"no\"
ARPUPDATE=\"no\"
ARPCHECK=\"no\"" > $IFCFG || error "Can't write to file $IFCFG" $VZ_FS_NO_DISK_SPACE

	if_restart=yes

	# Set default route to venet0
	if [ "x${VE_STATE}" = "xstarting" -o "$(is_default_route_configured)" = "no" ]; then
		put_param ${IFCFG} GATEWAYDEV ${VENET_DEV}
	fi

	if [ "${IPV6}" = "yes" ]; then
		put_param ${NETFILE} NETWORKING_IPV6 yes
		put_param ${IFCFG} IPV6INIT yes
		if [ "x${VE_STATE}" = "xstarting" -o "$(is_default_route_configured '' '-6')" = "no" ]; then
			put_param ${IFCFG} IPV6_DEFAULTDEV ${VENET_DEV}
		fi
	fi
}

function rm_fake_gw()
{
	local routecfg=${IFCFG_DIR}/route-venet0
	if grep -q 'GATEWAY="191.255.255.1"' $NETFILE; then
		del_param $NETFILE GATEWAY
	fi
	if grep -q '191.255.255' $routecfg 2>/dev/null; then
		/bin/sed -e '/^191.255.255.0\/24 dev venet0.*/d' -e '/^default via 191.255.255.1.*/d' < ${routecfg} > ${routecfg}.$$ && \
				mv -f ${routecfg}.$$  ${routecfg}
	fi
}

function setup_network()
{
	# Remove all VENET config files
	rm -f ${IFCFG_DIR}/${VENET_DEV_CFG} ${IFCFG_DIR}/${VENET_DEV_CFG}:* >/dev/null 2>&1

	# Set /etc/sysconfig/network
	put_param $NETFILE NETWORKING yes

	# remove old fake route
	rm_fake_gw

	# Set up /etc/hosts
	if [ ! -f ${HOSTFILE} ]; then
		echo "127.0.0.1 localhost.localdomain localhost" > $HOSTFILE
	fi
	fix_ifup
}

function create_config()
{
	local ip=$1
	local mask=$2
	local ifnum=$3
	local file=${IFCFG_DIR}/bak/${VENET_DEV_CFG}:${ifnum}

	if [ -z "${mask}" ];  then
		mask="255.255.255.255"
	fi

	echo "DEVICE=${VENET_DEV}:${ifnum}
ONBOOT=yes
IPADDR=${ip}
ARPCHECK=\"no\"
NM_CONTROLLED=\"no\"
NETMASK=${mask}" > $file || \
	error "Can't write to file $file" ${VZ_FS_NO_DISK_SPACE}
}

function add_ip6()
{
	local ip=$1
	local mask=$2

	if [ -n "${mask}" ]; then
		ipm="${ip}/${mask}"
	else
		ipm="${ip}/128"
	fi

	if ! grep -qw "$1" ${IFCFG} 2>/dev/null; then
		add_param ${IFCFG} IPV6ADDR_SECONDARIES "${ipm}"
		if_restart=yes
	fi
}

function get_all_aliasid()
{
	IFNUM=-1

	cd ${IFCFG_DIR} || return 1
	IFNUMLIST=`ls -1 bak/${VENET_DEV_CFG}:* 2>/dev/null | \
		sed "s/.*${VENET_DEV_CFG}://"`
}

function get_aliasid_by_ip()
{
	local ip=$1
	local idlist

	cd ${IFCFG_DIR} || return 1
	IFNUM=`grep -l "IPADDR=${ip}$" ${VENET_DEV_CFG}:* 2>/dev/null | \
		head -n 1 | sed -e 's/.*:\([0-9]*\)$/\1/'`
}

function get_free_aliasid()
{
	local found=

	[ -z "${IFNUMLIST}" ] && get_all_aliasid
	while test -z ${found}; do
		let IFNUM=IFNUM+1
		echo "${IFNUMLIST}" | grep -q -E "^${IFNUM}$" 2>/dev/null || \
			found=1
	done
}

function backup_configs()
{
	local delall=$1

	rm -rf ${IFCFG_DIR}/bak/ >/dev/null 2>&1
	mkdir -p ${IFCFG_DIR}/bak
	[ -n "${delall}" ] && return 0

	cd ${IFCFG_DIR} || return 1
	if ls ${VENET_DEV_CFG}:* > /dev/null 2>&1; then
		${CP} ${VENET_DEV_CFG}:* ${IFCFG_DIR}/bak/ || \
			error "Unable to backup interface config files" ${VZ_FS_NO_DISK_SPACE}
	fi
}

function move_configs()
{
	cd ${IFCFG_DIR} || return 1
	rm -rf ${VENET_DEV_CFG}:*
	mv -f bak/* ${IFCFG_DIR}/ >/dev/null 2>&1
	rm -rf ${IFCFG_DIR}/bak
}

function check_running()
{
	if [ -x /sbin/ifconfig ]; then
		if /sbin/ifconfig ${VENET_DEV} | grep -q RUNNING 2>/dev/null; then
			return 1
		fi
	elif [ -x /sbin/ip ]; then
		if /sbin/ip l | grep ${VENET_DEV} | grep -q UP 2>/dev/null; then
			return 1
		fi
	fi

	return 0
}

function add_ip()
{
	local ip ipm mask
	local new_ips

	# In case we are starting VPS
	if [ "x${VE_STATE}" = "xstarting" ]; then
		setup_network
		[ -z "${IP_ADDR}" ] && return 0
		init_config
	fi

	[ ! -f "${IFCFG}" ] && init_config

	backup_configs ${IPDELALL}
	new_ips="${IP_ADDR}"
	if [ "x${IPDELALL}" = "xyes" ]; then
		new_ips=
		if_restart=yes
		del_param ${IFCFG} IPV6ADDR_SECONDARIES ""
		for ipm in ${IP_ADDR}; do
			ip=${ipm%%/*}
			mask=
			if echo "${ipm}" | grep -q '/'; then
				mask=${ipm##*/}
			fi

			get_aliasid_by_ip "${ip}"
			if [ -n "${IFNUM}" ]; then
				# ip already exists just create it in bak
				create_config "${ip}" "${mask}" "${IFNUM}"
			else
				new_ips="${new_ips} ${ipm}"
			fi
		done
	fi
	for ipm in ${new_ips}; do
		ip=${ipm%%/*}
		mask=
		if echo "${ipm}" | grep -q '/'; then
			mask=${ipm##*/}
		fi

		if is_ipv6 ${ip}; then
			add_ip6 "${ip}" "${mask}"
		else
			get_free_aliasid
			create_config "${ip}" "${mask}" "${IFNUM}"
		fi
	done
	move_configs
	if [ "x${VE_STATE}" = "xrunning" ]; then
		if [ -n "${if_restart}" ]; then
			ifdown ${VENET_DEV}
			ifup ${VENET_DEV}
		elif check_running; then
			# check_running return 0; so not running; restart
			/etc/init.d/network restart
		else
			# synchronyze config files & interfaces
			cd /etc/sysconfig/network-scripts && \
				./ifup-aliases ${VENET_DEV}
		fi
	fi

	# firewall-cmd will wait for all previous firewalld configuration tasks if any
	[ -x /usr/bin/firewall-cmd ] && /usr/bin/firewall-cmd --state >/dev/null 2>&1
}

add_ip

exit 0
# end of script
