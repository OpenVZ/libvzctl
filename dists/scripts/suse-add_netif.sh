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
# This script configure IP alias(es) inside SuSE like VE.
#
# Parameters are passed in environment variables.
# Required parameters:
#   IP_ADDR       - IP address(es) to add
#                   (several addresses should be divided by space)
# Optional parameters:
#   VE_STATE        - state of VPS; could be one of:
#                     starting | stopping | running | stopped
#   DEVICE	    - device name
#   IPADD           - list of ip addresses in format <ip[/mask] | dhcp>
#   IPDEL           - list of ip addresses in format <ip | all>
#   GW_${DEV}	    - gateway ip for specified dev
#   DEFAULT_GW	    - default gateway
#
IFCFG_DIR=/etc/sysconfig/network
ROUTES=${IFCFG_DIR}/routes
DEV=
IFNUMLIST=
IFRMLIST=
IFNUM=
WAIT_TIMEOUT=5
MAX_RETRIES=5

function wait_service()
{
	local service=$1
	local action=$2

	retry=0
	while ! systemctl is-active -q $service && [[ $retry < $MAX_RETRIES ]]; do
		sleep $WAIT_TIMEOUT
		(( retry=$retry+1 ))
	done

	if ! systemctl is-active -q $service && [ ! -z "$action" ]; then
		systemctl $action $service
	fi
}

function restart_network()
{
	local dev

	if is_wicked; then
		systemctl stop wickedd
		systemctl start wickedd
		# It is possble that we called wickedd restart too quickly and it refused to start
		wait_service "wickedd" "start"

		# Just for case - let's wait a little for all dependent services to start
		for service in wickedd-nanny wickedd-dhcp6 wickedd-dhcp4 wickedd-auto4; do
			if systemctl is-enabled -q $service; then
				wait_service $service
			fi
		done

		# Flush all devices, wicked don't clean DHCP addresses
		for dev in `ip a l 2>/dev/null | grep ^[0-9] | sed -e "s,^[0-9]*: ,,g" -e "s,[:@].*,,g"`; do
			ip addr flush $dev
			ip link set down $dev > /dev/null 2>&1
			wicked ifup $dev > /dev/null 2>&1
		done
		systemctl reload wicked
	else
		/etc/init.d/network restart
	fi
}

function create_config()
{
	local dev=$1
	local ip=$2
	local mask=$3
	local ifcfg=${IFCFG_DIR}/ifcfg-${dev}
	local cfg

	cfg="STARTMODE=onboot
BOOTPROTO=static
IPADDR=$ip"
	if [ -n "${mask}" ]; then
		if is_ipv6 ${ip}; then
			cfg="$cfg
PREFIXLEN=${mask}"
		else
			cfg="$cfg
NETMASK=${mask}"
		fi
	fi

	echo "${cfg}" > ${ifcfg} || error "Unable to create interface config file ${ifcfg}" ${VZ_FS_NO_DISK_SPACE}
}

function add_alias()
{
	local dev=$1
	local ifnum=$2
	local ip=$3
	local mask=$4
	local ifcfg=${IFCFG_DIR}/ifcfg-${dev}
	local cfg

	if [ ! -f ${ifcfg} ]; then
		create_config $dev "$ip" "$mask"
		return
	fi
	cfg="IPADDR_${ifnum}=${ip}
LABEL_${ifnum}=${ifnum}"
	if [ -n "${mask}" ]; then
		if is_ipv6 ${ip}; then
			cfg="$cfg
PREFIXLEN_${ifnum}=${mask}"
		else
			cfg="$cfg
NETMASK_${ifnum}=${mask}"
		fi
	fi
	echo "${cfg}" >> ${ifcfg} || error "Unable to create interface config file ${ifcfg}" ${VZ_FS_NO_DISK_SPACE}
}

function get_aliases()
{
	IFNUMLIST=

	if [ ! -f ${IFCFG_DIR}/ifcfg-${DEV} ]; then
		return
	fi
	IFNUMLIST=`grep -e "^LABEL_" ${IFCFG_DIR}/ifcfg-${DEV} | \
		sed 's/^LABEL_\(.*\)=.*/\1/'`
}

function reset_master()
{
	local cfg=${IFCFG_DIR}/ifcfg-${DEV}
	local id

	get_aliases
	for id in ${IFNUMLIST}; do
		sed -e "s/^IPADDR_${id}=/IPADDR=/" \
			-e "s/^NETMASK_${id}=/NETMASK=/" \
			-e "s/^PREFIXLEN_${id}=/PREFIXLEN=/" \
			-e "/^LABEL_${id}=/d" \
			< ${cfg} > ${cfg}.bak && mv -f ${cfg}.bak ${cfg}
		break;
	done
}

# Function to delete IP address for RedHat like systems
function del_ips()
{
	local ips="$1"
	local cfg=${IFCFG_DIR}/ifcfg-${DEV}
	local ip ipm mask ids id
	local file

	[ -z "${ips}" ] && return 0
	[ -d ${IFCFG_DIR} ] || return 0
	[ -f ${cfg} ] || return 0
	cd ${IFCFG_DIR} || return 0
	# synchronyze config files & interfaces

	for ipm in ${ips}; do
		ip=${ipm%%/*}
		if [ "$ip" = "all" ]; then
			ifconfig ${DEV} down
			grep -e "^STARTMODE=" -e "^BOOTPROTO=" ${cfg} > ${cfg}.tmp && mv -f ${cfg}.tmp ${cfg}
			break
		fi
		ids=`grep -E "^IPADDR_.*=${ip}$" ${cfg} 2>/dev/null | \
			 sed 's/^IPADDR_\(.*\)=.*/\1/'`
		for id in ${ids}; do
			sed -e "/^IPADDR_${id}=/d" -e "/^LABEL_${id}=/d" \
				 -e "/^NETMASK_${id}=/d" -e "/^PREFIXLEN_${id}=/d" \
				< ${cfg} > ${cfg}.bak && mv -f ${cfg}.bak ${cfg}
			if is_ipv6 "${ip}"; then
				mask=`get_netmask "$DEV" "${ip}"`
				ifconfig ${DEV} del "${ip}/${mask}" 2>/dev/null
			else
				ifconfig ${DEV}:${id} down 2>/dev/null
			fi
		done
		if grep -q -E "^IPADDR=${ip}$" ${cfg}; then
			sed -e "/^IPADDR=/d" -e "/^NETMASK=/d" -e "/^PREFIXLEN=/d" \
				< ${cfg} > ${cfg}.bak && mv -f ${cfg}.bak ${cfg}
			if is_ipv6 "${ip}"; then
				mask=`get_netmask "$DEV" "${ip}"`
				ifconfig ${DEV} del "${ip}/${mask}" 2>/dev/null
			else
				ifdown ${DEV} 2>/dev/null
			fi
			reset_master
			ifup ${DEV} 2>/dev/null
		fi
	done
}

function del_ips_by_proto()
{
	local proto="$1"
	local cfg=${IFCFG_DIR}/ifcfg-${DEV}

	[ -z "${proto}" ] && return 0
	[ -f ${cfg} ] || return 0

	${CP} ${cfg} ${cfg}.$$ || \
		error "Can't copy file ${cfg}" $VZ_FS_NO_DISK_SPACE

	awk -v proto=$proto '$1 ~/^IPADDR/ {
		skip=0;
		ip6=match($1, ":");
		if ((ip6 && proto == "6") || (!ip6 && proto != "6")) { skip=1; next; }
	}
	skip && ($1 ~/^LABEL/ || $1 ~/^PREFIXLEN/ || $1 ~/^NETMASK/) { next }
	{ print $0 }' $cfg > $cfg.$$ && mv -f ${cfg}.$$ ${cfg}

	rm -f ${cfg}.$$ 2>/dev/null

	if ! grep -q -E "^IPADDR=" ${cfg}; then
		reset_master
	fi
}


function get_param()
{
	local file="$1"
	local name="$2"

	grep -e "^$name=" $file 2>/dev/null | /bin/sed -e 's/"//g' -e "s|^$name=\(.*\)|\1|"
}

function set_dhcp()
{
	local dhcp_mode=
	local dhcp4="$DHCP4"
	local dhcp6="$DHCP6"
	local cfg=${IFCFG_DIR}/ifcfg-${DEV}

	[ -n "$DHCP4" ] && check_dhcp
	[ -n "$DHCP6" ] && check_dhcp_ipv6

	if [ -z "$dhcp4" ]; then
		if [ "$ORIG_BOOTPROTO" = "dhcp" -o "$ORIG_BOOTPROTO" = "dhcp4" ]; then
			dhcp4=yes
		fi
	fi
	if [ -z "$dhcp6" ]; then
		if [ "$ORIG_BOOTPROTO" = "dhcp" -o "$ORIG_BOOTPROTO" = "dhcp6" ]; then
			dhcp6=yes
		fi
	fi

	if [ "$dhcp4" = "yes" -a "$dhcp6" = "yes" ]; then
		dhcp_mode=dhcp
	elif [ "$dhcp4" = "yes" -a "$dhcp6" = "no" ]; then
		dhcp_mode=dhcp4
	elif [ "$dhcp6" = "yes" -a "$dhcp4" = "no" ]; then
		dhcp_mode=dhcp6
	elif [ "$dhcp4" = "no" -a "$dhcp6" = "no" ]; then
		dhcp_mode=static
	elif [ "$dhcp4" = "no" -a "$ORIG_BOOTPROTO" = "dhcp4" ]; then
		dhcp_mode=static
	elif [ "$dhcp6" = "no" -a "$ORIG_BOOTPROTO" = "dhcp6" ]; then
		dhcp_mode=static
	elif [ "$dhcp4" = "yes" ]; then
		dhcp_mode=dhcp4
	elif [ "$dhcp6" = "yes" ]; then
		dhcp_mode=dhcp6
	fi

	if [ -n "$dhcp_mode" ]; then
		put_param ${cfg} STARTMODE onboot
		put_param ${cfg} BOOTPROTO ${dhcp_mode}
		if [ "$dhcp_mode" = "dhcp" ]; then
			del_ips all
			setup_default_venet_route 'remove'
			setup_default_venet_route 'remove' '-6'
			remove_default_gw
			remove_default_gw6
		elif [ "$dhcp_mode" = "dhcp4" ]; then
			del_ips_by_proto 4
			setup_default_venet_route 'remove'
			remove_default_gw
		elif [ "$dhcp_mode" = "dhcp6" ]; then
			del_ips_by_proto 6
			setup_default_venet_route 'remove' '-6'
			remove_default_gw6
		fi
	fi
}

function update_dev()
{
	local ips="$1"
	local cfg=${IFCFG_DIR}/ifcfg-${DEV}
	local ipm ip mask dev found
	local ifnum=0
	local has_ip4=
	local has_ip6=

	ORIG_BOOTPROTO=`get_param $cfg BOOTPROTO`
	# synchronize config files & interfaces
	get_aliases
	for ipm in ${ips}; do
		ip=${ipm%%/*}
		mask=
		if echo "${ipm}" | grep -q '/'; then
			mask=${ipm##*/}
		fi
		found=
		if grep -q -w "${ip}" ${cfg} 2>/dev/null; then
			continue
		fi

		if is_ipv6 ${ip}; then
			has_ip4=yes
		else
			has_ip4=yes
		fi
		if ! grep -q "^IPADDR=" ${IFCFG_DIR}/ifcfg-${DEV}; then
			create_config "${DEV}" "${ip}" "${mask}"
			continue
		fi
		while test -z ${found}; do
			let ifnum++
			if ! echo "${IFNUMLIST}" | grep -w -q "${ifnum}"; then
				found=1
			fi
		done
		add_alias "${DEV}" "${ifnum}" "${ip}" "${mask}"
	done

	if [ -n "${DHCP4}" -o -n "${DHCP6}" ]; then
		set_dhcp
	elif [ -n "$ORIG_BOOTPROTO" -a "$ORIG_BOOTPROTO" != "static" ]; then
		if [ -n "$has_ip6" -o -n "$has_ip4" ]; then
			[ -n "$has_ip4" ] && DHCP4=no
			[ -n "$has_ip6" ] && DHCP6=no
			set_dhcp
		fi
	fi

	if [ "${VE_STATE}" != "starting" ]; then
		restart_network
	fi
}

remove_default_gw()
{
	local cfg=$1

	[ -z "$cfg" ] && cfg=${ROUTES}

	if grep -qe '^default .*\..* - -$' ${cfg} 2>/dev/null; then
		sed -i -e '/^default .*\..* - -$/d' ${cfg}
		return 0
	fi
	return 1
}

remove_default_gw6()
{
	local cfg=$1

	[ -z "$cfg" ] && cfg=${ROUTES}

	if grep -qe '^default .*:.* - -$' ${cfg} 2>/dev/null; then
		sed -i -e '/^default .*:.* - -$/d' ${cfg}
		return 0
	fi
	return 1
}

add_gw()
{
	remove_default_gw
	echo "default ${1} - -" >> $ROUTES || \
		error "Can't change file $ROUTES" $VZ_FS_NO_DISK_SPACE
}

add_gw6()
{
	remove_default_gw6
	echo "default ${1} - -" >> $ROUTES || \
		error "Can't change file $ROUTES" $VZ_FS_NO_DISK_SPACE
}

setup_default_venet_route()
{
	local cfg=${IFCFG_DIR}/ifroute-venet0
	local proto=$2

	case "$1" in
	"remove")
		if [ "$proto" = "-6" ]; then
		        if grep -qe '^default :: -' $cfg 2>/dev/null; then
                		sed -i -e '/^default :: -/d' $cfg
        		fi
		else
		        if grep -qe '^default - -' $cfg 2>/dev/null; then
                		sed -i -e '/^default - -/d' $cfg
        		fi
		fi
		ip $proto r d default dev venet0 2>/dev/null
		;;
	"restore")
		if [ "$proto" = "-6" ]; then
			if ! grep -qe '^default ::' ${IFCFG_DIR}/ifroute-venet0 2>/dev/null; then
				echo "default :: - venet0" >> ${IFCFG_DIR}/ifroute-venet0
				ip $proto r r default dev venet0 2>/dev/null
			fi
		else
			if ! grep -qe '^default -' ${IFCFG_DIR}/ifroute-venet0 2>/dev/null; then
				echo "default - - venet0" >> ${IFCFG_DIR}/ifroute-venet0
				ip $proto r r default dev venet0 2>/dev/null
			fi
		fi
		;;
	esac
}

function setup_gw()
{
	local $dev=$1
	local changed=

	if [ -n "${GWDEL}" ]; then
		if remove_default_gw; then
			setup_default_venet_route 'restore'
		fi
		changed=yes
	fi
	if [ -n "${GW6DEL}" ]; then
		if remove_default_gw6; then
			setup_default_venet_route 'restore' '-6'
		fi
		changed=yes
	fi
	if [ -n "${DEFAULT_GW}" ]; then
		put_param2 ${ROUTES} default "${DEFAULT_GW} - -"
		changed=yes
	fi
	if [ -n "${GW}" ]; then
		add_gw "${GW}"
		setup_default_venet_route 'remove'
		changed=yes
	fi
	if [ -n "${GW6}" ]; then
		add_gw6 "${GW6}"
		setup_default_venet_route 'remove' '-6'
		changed=yes
	fi

	if [ -n "${changed}" ]; then
		if [ "${VE_STATE}" != "starting" ]; then
			restart_network
		fi
	fi
}

function setup()
{
	local dev ips gw ips_del

	if [ ! -d "${IFCFG_DIR}" ]; then
		mkdir -p ${IFCFG_DIR} 2>/dev/null
	fi
	for dev in ${DEVICE}; do
		DEV=$dev
		if [ "${VE_STATE}" = "starting" ]; then
			rm -f ${IFCFG_DIR}/ifcfg-${DEV} >/dev/null 2>&1
		fi
		del_ips "${IPDEL}"
		update_dev "${IPADD}"
		setup_gw "$dev"
	done
}

setup
exit 0
# end of script
