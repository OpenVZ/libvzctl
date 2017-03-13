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
# This script configure IP alias(es) inside VPS for SuSE-8 like distros.
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
VENET_DEV_CFG=ifcfg-$VENET_DEV

FAKEGATEWAY=191.255.255.1
FAKEGATEWAYNET=191.255.255.0

IFCFG_DIR=/etc/sysconfig/network/
IFCFG=${IFCFG_DIR}/ifcfg-${VENET_DEV}
ROUTES=${IFCFG_DIR}/ifroute-${VENET_DEV}
HOSTFILE=/etc/hosts

function setup_network()
{
	mkdir -p ${IFCFG_DIR}
	echo "STARTMODE=onboot
IPADDR=127.0.0.1
NETMASK=255.255.255.255
BROADCAST=0.0.0.0" > $IFCFG || error "Can't write to file $IFCFG" $VZ_FS_NO_DISK_SPACE

	echo "${FAKEGATEWAY}	0.0.0.0 255.255.255.255	${VENET_DEV}
default	${FAKEGATEWAY}	0.0.0.0	${VENET_DEV}" > ${ROUTES} || error "Can't write to file $ROUTES" $VZ_FS_NO_DISK_SPACE
	# Set up /etc/hosts
	if [ ! -f ${HOSTFILE} ]; then
		echo "127.0.0.1 localhost.localdomain localhost" > $HOSTFILE
	fi
}

function create_config()
{
	local ip=$1
	local mask=$2
	local ifnum=$3
	local file=${IFCFG_DIR}/bak/${VENET_DEV_CFG}:${ifnum}

	echo "STARTMODE=onboot
IPADDR=${ip}" > $file || \
	error "Can't write to file $file" ${VZ_FS_NO_DISK_SPACE}
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
	IFNUM=`grep -l "IPADDR=${ip}$" ${VENET_DEV_CFG}:* | head -n 1 | \
		sed -e 's/.*:\([0-9]*\)$/\1/'`
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
		cp -rf ${VENET_DEV_CFG}:* ${IFCFG_DIR}/bak/ || \
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

function add_ip()
{
	local ipm ip mask
	local new_ips
	local if_restart=

	# In case we are starting VPS
	if [ "x${VE_STATE}" = "xstarting" ]; then
		# Remove all VENET config files
		rm -f ${IFCFG_DIR}/${VENET_DEV_CFG}:* >/dev/null 2>&1
		[ -z "${IP_ADDR}" ] && return 0
	fi
	if [ ! -f "${IFCFG}" ]; then
		setup_network
		if_restart=1
	fi
	backup_configs ${IPDELALL}
	new_ips="${IP_ADDR}"
	if [ "x${IPDELALL}" = "xyes" ]; then
		new_ips=
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
		get_free_aliasid
		create_config "${ip}" "${mask}" "${IFNUM}"
	done
	move_configs
	if [ "x${VE_STATE}" = "xrunning" ]; then
		/etc/init.d/network restart >/dev/null 2>&1
	fi
}

add_ip

exit 0
