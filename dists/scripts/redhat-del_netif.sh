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
# This script deletes IP alias(es) inside VPS for RedHat like systems.
#
# Parameters are passed in environment variables.
# Required parameters:
#   DEVICE	- device name
IFCFG_DIR=/etc/sysconfig/network-scripts/
function del_dev()
{
	if [ -n "${DEVICE}" ]; then
		dev=$(get_routed_default_dev)
		[ -z $dev ] && return

		if grep 'GATEWAY=' ${IFCFG_DIR}/ifcfg-${DEVICE} 2>/dev/null; then
		        echo "default dev $dev" > $IFCFG_DIR/route-$dev
			ip r r default dev $dev
		fi
		if grep 'IPV6_DEFAULTDEV=' ${IFCFG_DIR}/ifcfg-${DEVICE} 2>/dev/null; then
			echo "default dev $dev" > $IFCFG_DIR/route6-$dev 
			ip -6 r r default dev $dev
		fi

		ifdown ${DEVICE} 2>/dev/null
		rm -f ${IFCFG_DIR}/ifcfg-${DEVICE} ${IFCFG_DIR}/ifcfg-${DEVICE}:* 2>/dev/null
	fi
}

del_dev
exit 0
