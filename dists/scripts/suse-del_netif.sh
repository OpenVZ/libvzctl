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
# This script deletes device inside VE for SuSE like systems.
#
# Parameters are passed in environment variables.
# Required parameters:
#   DEVICE	- device name
IFCFG_DIR=/etc/sysconfig/network/
ROUTES=${IFCFG_DIR}/routes

setup_default_route()
{
	local dev=$1
	local cfg=${IFCFG_DIR}/ifroute-venet0

	if [ "$(is_default_route_configured "$dev" '-6')" = "yes" ]; then
		if ! grep -q 'default :: -' $cfg 2>/dev/null; then
			echo "default :: - venet0" >> $cfg
		fi
		[ -f ${ROUTES} ] && sed -i -e '/^default .*:.* - -$/d' ${ROUTES}
		ip -6 r r default dev venet0 2>/dev/null
	fi
	if [ "$(is_default_route_configured "$dev")" = "yes" ]; then
		if ! grep -q 'default - -' $cfg 2>/dev/null; then
			echo "default - - venet0" >> ${IFCFG_DIR}/ifroute-venet0
		fi
		[ -f ${ROUTES} ] && sed -i -e '/^default .*\..* - -$/d' ${ROUTES}
		ip r r default dev venet0 2>/dev/null
	fi
}

function del_dev()
{
	local dev

	for dev in ${DEVICE}; do
		setup_default_route $dev
		ifdown ${dev} 2>/dev/null
		rm -f ${IFCFG_DIR}/ifcfg-${dev} 2>/dev/null
	done
}

del_dev
exit 0
# end of script
