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
# This script deletes IP alias(es) inside VPS for SuSE-7.3 like systems.
#
# Parameters are passed in environment variables.
# Required parameters:
#   IP_ADDR       - IPs to delete, several addresses should be divided by space
# Optional parameters:
#   IPDELALL      - delete all ip addresses
VENET_DEV=venet0
CFGFILE=/etc/rc.config

function del_ip()
{
	local ip=$1
	local ids id

	ids=`grep -E "^IPADDR_[0-9]+=\"${ip}\"" ${CFGFILE} | sed  -e 's/IPADDR_\([0-9]*\)=.*\"/\1/'`
	[ -z "${ids}" ] && return

	for id in ${ids}; do
		sed -e 's/IPADDR_'${id}'=.*/IPADDR_'${id}'=""/' \
			-e 's/IFCONFIG_'${id}'=.*/IFCONFIG_'${id}'=""/' \
			-e 's/NETDEV_'${id}'=.*/NETDEV_'${id}'=""/' < ${CFGFILE} > ${CFGFILE}.tmp
		if [ $? -eq 0 ]; then
			mv -f ${CFGFILE}.tmp ${CFGFILE}
		fi
		rm -f ${CFGFILE}.tmp 2>/dev/null

		sed '/NETCONFIG=/{s/_'${id}'//;}' < ${CFGFILE} > ${CFGFILE}.tmp
		if [ $? -eq 0 ]; then
			mv -f ${CFGFILE}.tmp ${CFGFILE}
		fi
		rm -f ${CFGFILE}.tmp 2>/dev/null
	done
}

function del()
{
	local ip

	[ -f ${IFCFG_DIR} ] || return 0
	if [ "${IPDELALL}" = "yes" ]; then
		put_param ${CFGFILE} NETCONFIG "_0"
		return 0;
	fi
	for ip in ${IP_ADDR}; do
		del_ip ${ip}
	done
	/etc/init.d/network restart
}

del
exit 0
# end of script
