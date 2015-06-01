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
# This script configure IP alias(es) inside VPS for SuSE-9
#
# Parameters are passed in environment variables.
# Required parameters:
#   IP_ADDR       - IP address(es) to add
#                   (several addresses should be divided by space)
# Optional parameters:
#   VE_STATE      - state of VPS; could be one of:
#                     starting | stopping | running | stopped
#
# this should set up networking for SuSE-based VPS

VENET_DEV=venet0
IFCFG_DIR=/etc/sysconfig/network/
IFCFG=${IFCFG_DIR}/ifcfg-${VENET_DEV}
ROUTES=${IFCFG_DIR}/ifroute-${VENET_DEV}
HOSTFILE=/etc/hosts

function get_aliases()
{
	IFNUMLIST=

	[ -f ${IFCFG} ] || return
	IFNUMLIST=`grep -e "^LABEL_" ${IFCFG} 2>/dev/null | \
		sed 's/^LABEL_\(.*\)=.*/\1/'`
}

function fix_wicked_route()
{
	local wickedfile=/etc/wicked/extensions/netconfig
	local venet_route_file=/etc/wicked/extensions/venet_route

	[ ! -f ${wickedfile} ] && return

	if ! grep -q 'venet_route' ${wickedfile} >/dev/null; then
		sed -i -e "/info)/ a\
			$venet_route_file \$ifname add
		" -e "/remove)/ a\
			$venet_route_file \$ifname del
		" ${wickedfile}
	fi

	cat > $venet_route_file << EOL
#!/bin/bash

DEVICE=\$1
ACTION=\$2
PROTO=""
VENET="venet0"
VENET_CONF="/etc/sysconfig/network/ifroute-\$VENET"

[ "x\$DEVICE" != "x\$VENET" ] && exit 0
[ "x\$ACTION" != "xadd" -a "x\$ACTION" != "xdel" ] && exit 0


fgrep "default - - \$VENET" \$VENET_CONF > /dev/null 2>&1
[ \$? -eq 0 ] && PROTO="-4"
fgrep "default :: - \$VENET" \$VENET_CONF > /dev/null 2>&1
[ \$? -eq 0 ] && PROTO="\$PROTO -6"

for proto in \$PROTO; do
	ip \$proto route \$ACTION default dev \$VENET > /dev/null 2>&1
done

exit 0
EOL
	chmod 0755 $venet_route_file
}

function fix_ifup_route()
{
	local file=/etc/sysconfig/network/scripts/ifup-route

	[ is_wicked ] && fix_wicked_route

	[ ! -f ${file} ] && return
	if grep -q 'run_iproute $ACTION to $TYPE $DEST via $GWAY $IFACE $IPOPTS' ${file} >/dev/null; then
		/bin/cp -a ${file} ${file}.$$ || return
		/bin/sed -e 's|run_iproute $ACTION to $TYPE $DEST via $GWAY $IFACE $IPOPTS|run_iproute $ACTION to $TYPE $DEST ${GWAY:+via $GWAY} $IFACE $IPOPTS|' < ${file} > ${file}.$$
		if [ $? -ne 0 ]; then
			rm -f ${file}.$$ 2>/dev/null
		fi
		mv -f ${file}.$$ ${file}
	fi
}

function init_config()
{

	mkdir -p ${IFCFG_DIR}
	echo "STARTMODE=onboot
BOOTPROTO=static
BROADCAST=0.0.0.0
NETMASK=255.255.255.255
IPADDR=127.0.0.1" > ${IFCFG} || \
	error "Can't write to file ${IFCFG}" ${VZ_FS_NO_DISK_SPACE}

	# Set up /etc/hosts
	if [ ! -f ${HOSTFILE} ]; then
		echo "127.0.0.1 localhost.localdomain localhost" > $HOSTFILE
	fi
	fix_ifup_route
}

function add_alias()
{
	local ip=$1
	local mask=$2
	local ifnum=$3
	local cfg

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
	echo "${cfg}" >> ${IFCFG} || error "Can't write to file ${IFCFG}" ${VZ_FS_NO_DISK_SPACE}
}

function add_ip()
{
	local ipm ip mask found
	local ifnum=-1

	if [ "x${VE_STATE}" = "xstarting" ]; then
		init_config
		echo "default - - ${VENET_DEV}" > ${ROUTES}
		if [ "${IPV6}" = "yes" ]; then
			echo "default :: - ${VENET_DEV}" >> ${ROUTES}
		fi
	elif [ ! -f "${IFCFG}" ]; then
		init_config
	fi
	if [ "x${IPDELALL}" = "xyes" ]; then
		init_config
	fi
	get_aliases
	for ipm in ${IP_ADDR}; do
		ip=${ipm%%/*}
		mask=
		if echo "${ipm}" | grep -q '/'; then
			mask=${ipm##*/}
		fi
		found=
		if grep -q -w "${ip}" ${IFCFG}; then
			continue
		fi
		while test -z ${found}; do
			let ifnum++
			if ! echo "${IFNUMLIST}" | grep -w -q "${ifnum}"; then
				found=1
			fi
		done
		add_alias "${ip}" "${mask}" "${ifnum}"
	done
	if [ "x${VE_STATE}" = "xrunning" ]; then
		ifdown $VENET_DEV >/dev/null 2>&1
		ifup $VENET_DEV >/dev/null 2>&1
	fi
}

add_ip

exit 0
# end of script
