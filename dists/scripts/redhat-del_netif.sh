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
	local dev

	if [ -n "${DEVICE}" ]; then
		if grep 'GATEWAY=' ${IFCFG_DIR}/ifcfg-${DEVICE} 2>/dev/null; then
			put_param "${IFCFG_DIR}/ifcfg-venet0" GATEWAY venet0
			ip r r default dev venet0
		fi
		if grep 'IPV6_DEFAULTDEV=' ${IFCFG_DIR}/ifcfg-${DEVICE} 2>/dev/null; then
			put_param "${IFCFG_DIR}/ifcfg-venet0" IPV6_DEFAULTDEV venet0
			ip -6 r r default dev venet0
		fi

		ifdown ${DEVICE} 2>/dev/null
		rm -f ${IFCFG_DIR}/ifcfg-${DEVICE} ${IFCFG_DIR}/ifcfg-${DEVICE}:* 2>/dev/null
	fi
}

del_dev
exit 0
