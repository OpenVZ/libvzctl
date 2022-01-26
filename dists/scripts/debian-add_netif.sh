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
# This script configure IP alias(es) inside Debian like VE.
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
#   GW	    	    - gateway ip
#
CFGFILE=/etc/network/interfaces
WIDE_DHCP6_CLIENT_CFG=/etc/default/wide-dhcpv6-client
WIDE_DHCP6_CFG=/etc/wide-dhcpv6/dhcp6c.conf
DEV=
IFNUMLIST=
IFRMLIST=
IFNUM=-1

configure_dhcpv6_client()
{
	local dev=$1
	local op=$2
	local cfg=$WIDE_DHCP6_CLIENT_CFG

	INTERFACES=`grep -m 1 INTERFACES $cfg`
	eval $INTERFACES
	for iface in $INTERFACES; do
		if [ "x$iface" != "x$dev" ]; then
			ifaces="$iface "
		fi
	done
	ifaces=`echo $ifaces | sed "s, $,,g"`
	if [ "$op" = "add" ]; then
		echo "INTERFACES=\"$ifaces $dev\"" > $cfg
	else
		echo "INTERFACES=\"$ifaces\"" > $cfg
	fi
}

remove_dhcpv6_iface()
{
	local cfg=$WIDE_DHCP6_CFG
		local dev=$1

	[ -f ${cfg} ] || return

	${CP} ${cfg} ${cfg}.$$ || \
		error "Can't copy file ${cfg}" $VZ_FS_NO_DISK_SPACE

	awk '
		NF == 0 {next}
		$1 == "interface" && $2 ~/'${dev}' / {skip=2; next}
		/^};/ && skip {skip--; next}
		skip {next}
	{print}
	' < ${cfg} > ${cfg}.$$ && mv -f ${cfg}.$$ ${cfg}

	rm -f ${cfg}.$$ 2>/dev/null
}

add_dhcpv6_iface()
{
	local dev=$1
	local id

	id=`echo $dev | sed 's/[a-zA-Z]*//'`
	[ -z "$id" ] && id=0

	echo "interface $dev {
  send ia-na $id;
  request domain-name-servers;
  request domain-name;
};
id-assoc na $id {
};" >> $WIDE_DHCP6_CFG
}

configure_wide_dhcpv6()
{
	local dev=$1
	local op=$2

	if [ ! -f $WIDE_DHCP6_CLIENT_CFG ]; then
		return
	fi
	check_dhcp_ipv6
	configure_dhcpv6_client $dev $op
	remove_dhcpv6_iface $dev
	if [ "$op" = "add" ]; then
		add_dhcpv6_iface $dev
	fi
	if [ "${VE_STATE}" != "starting" ]; then
		/etc/init.d/wide-dhcpv6-client start >/dev/null 2>&1
	fi
	/usr/sbin/update-rc.d -f wide-dhcpv6-client defaults >/dev/null 2>&1
}

function configure_dhcp()
{
	local dev=$1

	if [ "$DHCP4" = "yes" ]; then
		check_dhcp
		remove_debian_interface_by_proto ${dev} inet ${CFGFILE}
		remove_default_route
		if ! grep -qe "auto $dev$" ${CFGFILE} 2>/dev/null; then
			echo "auto $dev" >> ${CFGFILE}
		fi
		echo "iface $dev inet dhcp
" >> ${CFGFILE}
	elif [ "$DHCP4" = "no" ]; then
		if grep -q "${dev} inet dhcp" ${CFGFILE} 2>/dev/null; then
			remove_debian_interface_by_proto ${dev} inet ${CFGFILE}
		fi
	fi

	if [ "$DHCP6" = "yes" ]; then
		if ! grep "iface ${dev} inet" ${CFGFILE}; then
			echo "auto $dev
iface $dev inet manual
	up ifconfig $dev 0.0.0.0 up
" >> ${CFGFILE}
		fi
		remove_debian_interface_by_proto ${dev} inet6 ${CFGFILE}
		remove_default_route6
		configure_wide_dhcpv6 $dev add
	elif [ "$DHCP6" = "no" ]; then
		configure_wide_dhcpv6 $dev del
	fi
}

function add_ip()
{
	local dev=$1
	local ip=$2
	local mask=$3
	local proto=$4
	local cfg

	if [ "$proto" == "inet6" ]; then
		[ "$NETWORK_TYPE" = "routed" ] && mask=128
		[ -z "${mask}" ] && mask=64
	else
		[ -z "${mask}" ] && mask=255.255.255.0
	fi

	if ! grep -qe "auto $dev$" ${CFGFILE} 2>/dev/null; then
		cfg="auto ${dev}"
	fi
	cfg="$cfg
iface ${dev} ${proto} static
	address ${ip}
	netmask ${mask}"

	if [ "${dev%:*}" = "$dev" -a "$NETWORK_TYPE" = "routed" ]; then
		cfg="$cfg
	#$ROUTED_UUID $dev"

		if [ "$proto" == "inet6" ]; then
			cfg="$cfg
	up ip -6 route add fe80::ffff:1:1 dev $dev
	up ip -6 route add default via fe80::ffff:1:1 dev $dev"
		else
			cfg="$cfg
	up ip route add default dev $dev"
		fi
	fi

	echo -e "${cfg}\n" >> ${CFGFILE}
}

function add_ip6_alias()
{
	local dev=$1
	local ip=$2
	local mask=$3

	if [ -n "${mask}" ]; then
		ip="${ip}/${mask}"
	else
		ip="${ip}/64"
	fi

	awk '
		BEGIN {found = 0}
		NF == 0 {next}
		!found && $1 == "iface" && $2 ~/'${dev}'$/ && $3 == "inet6" {
			found = 1;
			print;
			next;
		}
		found == 1 && !/^\t/{
			print "\tup ip addr add '$ip' dev '${dev}'";
			found++;
		}
		{print}
		END {
			if (found == 1) {
				print "\tup ip addr add '$ip' dev '${dev}'";
			}
		}
	' < ${CFGFILE} > ${CFGFILE}.$$ && mv -f ${CFGFILE}.$$ ${CFGFILE}
	rm -f ${CFGFILE}.$$ 2>/dev/null
}

function get_iface_ips()
{
	local dev=$1
	local skip=$2
	awk '
		BEGIN {ip=""}
		NF == 0 {next}
		$1 == "iface" && ($2 ~/'${dev}'$/ || $2 ~/'${dev}':/) {
			while (1==1) {
				if (!getline) break;
				if ($1 == "address") {
				       	if ($2 != "'${skip}'")
						ip = ip " " $2;
					else
						getline
				}
				else if ($1 == "netmask") { ip = ip "/" $2; }
				else if ($0 ~ "\tup ip addr add") { ip = ip " " $5; }
				else if ($0 ~ "\t") {}
				else {break;}
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

	dev=`grep -B 1 -w "${ip}" ${CFGFILE} 2>/dev/null | grep iface | \
		sed 's/^iface \(.*\) inet.*/\1/'`
	[ -z "${dev}" ] && return 0
	if ! echo "${dev}" | grep -q ":"; then
		# reset master
		ifdown $dev
		/bin/ip addr flush dev $dev
		ips=`get_iface_ips "${dev}" "${ip}"`
		remove_debian_interface "${dev}:[0-9]+" ${CFGFILE}
		remove_debian_interface ${dev} ${CFGFILE}
		setup_dev "${dev}" "${ips}"
	else
		ifconfig ${dev} down
		remove_debian_interface "${dev}" ${CFGFILE}
	fi
}

function del_ips()
{
	local dev=$1
	local ips="$2"
	local ipm ip

	for ipm in ${ips}; do
		ip=${ipm%%/*}
		if [ "${ip}" = "all" ]; then
			ifdown ${dev}
			/bin/ip addr flush dev ${dev} 2>/dev/null
			remove_debian_interface "${dev}:[0-9]+" ${CFGFILE}
			remove_debian_interface "${dev}" ${CFGFILE}
			return
		fi

		if is_ipv6 "${ip}"; then
			sed -i "/${ip}\/[0-9]*/d" ${CFGFILE}
			mask=`get_netmask "$dev" "${ip}"`
			ifconfig ${dev} del "${ip}/${mask}" 2>/dev/null
		fi
		rm_if_by_ip "${ip}"
	done
}

function get_all_aliasid()
{
	IFNUMLIST=`grep -e '^auto '${DEV}':.*$' ${CFGFILE} 2>/dev/null | \
		 sed 's/^auto '${DEV}'://'`
}

function get_free_aliasid()
{
	local found=

	# no main iface
	grep -qe "^iface ${DEV} inet " ${CFGFILE} >/dev/null || return 0

	# remove helper dhcp6 entry
	if grep -qe "^iface ${DEV} inet manual" ${CFGFILE} >/dev/null; then
		remove_debian_interface_by_proto ${DEV} inet ${CFGFILE}
		return 0
	fi

	[ -z "${IFNUMLIST}" ] && get_all_aliasid
	if [ -z "${IFNUMLIST}" ]; then
		IFNUMLIST="-1"
	fi
	while test -z ${found}; do
		let IFNUM++
		echo "${IFNUMLIST}" | grep -qw "${IFNUM}" || found=1
	done
	return 1
}

remove_default_route()
{
	local dev=`get_routed_default_dev $CFGFILE`

	[ -z "$dev" ] && return

	ip r d default dev $dev 2>/dev/null
	sed '/up ip route add default dev '$dev'$/d' ${CFGFILE} > ${CFGFILE}.$$
	if [ $? -ne 0 ]; then
		rm -f ${CFGFILE}.$$ 2>/dev/null
		return
	fi
	mv -f ${CFGFILE}.$$ ${CFGFILE}
}

remove_default_route6()
{
	local dev=`get_routed_default_dev $CFGFILE`

	[ -z "$dev" ] && return

	ip -6 r d default dev $dev 2>/dev/null
	sed '/up ip -6 route add default via fe80::ffff:1:1 dev '$dev'$/d' ${CFGFILE} > ${CFGFILE}.$$
	if [ $? -ne 0 ]; then
		rm -f ${CFGFILE}.$$ 2>/dev/null
		return
	fi
	mv -f ${CFGFILE}.$$ ${CFGFILE}
}

remove_route()
{
	local dev=$1
	local proto=$2
	local cfg=$CFGFILE
	local cmd iproto

	if [ "$proto" = '-6' ]; then
		iproto=inet6
		cmd="up ip -6 route add default via"
	else
		iproto=inet
		cmd="up ip route add default via"
	fi

	${CP} ${cfg} ${cfg}.$$ || \
		error "Can't copy file ${cfg}" $VZ_FS_NO_DISK_SPACE

	awk '
		$1 == "iface" { skip = 0 }
		$1 == "iface" && $2 == "'${dev}'" && $3 == "'$iproto'" { skip = 1 }
		/route add default via/ && skip {next}
		{ print }
	' < ${cfg} > ${cfg}.$$ && mv -f ${cfg}.$$ ${cfg}

	rm -f ${cfg}.$$ 2>/dev/null

	if ! grep -q "$cmd" ${cfg}; then
		ip $proto r d default dev $dev
		restore_debian_default_route "$proto"
	fi
}

function setup_dev()
{
	local dev=$1
	local ips="$2"
	local ipm ip mask
	local dev gw

	if [ -n "${DHCP4}" -o -n "${DHCP6}" ]; then
		if [ "${VE_STATE}" != "starting" ]; then
			ifdown ${dev} 2>/dev/null
			/bin/ip addr flush dev ${dev} 2>/dev/null
		fi
		configure_dhcp ${dev}
	fi

	for ipm in ${ips}; do
		ip=${ipm%%/*}
		mask=${ipm##*/}

		[ -z "${ip}" ] && continue
		[ "$mask" = "$ipm" ] && mask=

		if grep -qw -e "^[[:space:]]*address $ip" -e "^[[:space:]]*up ip addr add $ip" ${CFGFILE} 2>/dev/null; then
			continue
		fi

		if is_ipv6 "${ip}"; then
			if grep -q "iface ${dev} inet6" ${CFGFILE} 2>/dev/null; then
				add_ip6_alias "${dev}" "${ip}" "${mask}"
			else
				add_ip "${dev}" "${ip}" "${mask}" inet6
			fi
		else
			get_free_aliasid
			if [ $? -ne 0 ]; then
				add_ip "${dev}:${IFNUM}" "${ip}" "${mask}" inet
			else
				add_ip "${dev}" "${ip}" "${mask}" inet
			fi
		fi
	done
}

function setup_gw()
{
	local dev=$1
	local gw=$2
	local iproto proto
	local cmd='\tup ip route add default via'

	[ -z "${gw}" ] && return 0

	if is_ipv6 "${gw}"; then
		proto=inet6
		iproto="-6"
		cmd='\tup ip -6 route add default via'
		remove_default_route6
	else
		proto=inet
		remove_default_route
	fi
	awk '
		BEGIN {addgw = 0}
		/^'"$cmd"'/ { next; }
		/^\taddress/ { print; next ;}
		/^\tnetmask/ { print; next ;}
		/^\tup/ { print; next ;}
		addgw { print "'"${cmd} ${gw}"'"; addgw=0 }
		$1 == "iface" && $2 == "'${dev}'" && $3 == "'${proto}'" { addgw=1 }
		{ print }
		END {
			if (addgw) { print "'"${cmd} ${gw}"'" }
		}
	' < ${CFGFILE} > ${CFGFILE}.$$ && mv -f ${CFGFILE}.$$ ${CFGFILE}
	rm -f ${CFGFILE}.$$ 2>/dev/null
	ip $iproto r r default via $gw
}

function setup()
{
	local ips gw ips_del

	# IPv6 is not supported for ubuntu-8.04
	if grep -q "lenny" /etc/debian_version 2>/dev/null; then
		IPV6=no
	fi

	DEV=$DEVICE
	if [ "${VE_STATE}" = "starting" ]; then
		> $WIDE_DHCP6_CFG
	fi
	if [ "${VE_STATE}" = "starting" ]; then
		remove_debian_interface "${DEVICE}:[0-9]+" ${CFGFILE}
		remove_debian_interface "${DEVICE}" ${CFGFILE}
	else
		del_ips "$DEVICE" "${IPDEL}"
	fi
	setup_dev "${DEVICE}" "${IPADD}"

	if [ -n "${GWDEL}" ]; then
		remove_route $DEVICE
	fi
	if [ -n "${GW6DEL}" ]; then
		remove_route "$DEVICE" '-6'
	fi
	if [ -n "${GW}" ]; then
		setup_gw ${DEVICE} "${GW}"
	fi

	if [ -n "${GW6}" ]; then
		setup_gw ${DEVICE} "${GW6}"
	fi

	if [ "${VE_STATE}" != "starting" ]; then
		ifdown -a --force >/dev/null
		ifup -a --force
	fi
}

setup
exit 0
