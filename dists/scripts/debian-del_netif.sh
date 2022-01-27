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
# This script deletes device inside VE for Debian like systems.
#
# Parameters are passed in environment variables.
# Required parameters:
#   DEVICE	- device name
CFGFILE=/etc/network/interfaces

function del_dev()
{
	local dev

	for dev in ${DEVICE}; do
		ifdown ${dev} 2>/dev/null
		/bin/ip addr flush dev ${dev} 2>/dev/null
		remove_debian_interface "${dev}:[0-9]+" ${CFGFILE}
		remove_debian_interface "${dev}" ${CFGFILE}
		if [ x$IPV6 = xyes ]; then
			local config="/etc/default/wide-dhcpv6-client"

			if [ -f $config ]; then
				. $config
				for iface in $INTERFACES; do
					if [ "x$iface" != "x$dev" ]; then
						ifaces="$iface "
					fi
				done
				ifaces=`echo $ifaces | sed "s, $,,g"`
				echo "INTERFACES=\"$ifaces\"" > $config
			fi
		fi

		if ! grep -qe 'ip route add default via' $CFGFILE 2>/dev/null; then
			restore_debian_default_route
		fi
		if ! grep -qe 'ip -6 route add default via' $CFGFILE 2>/dev/null; then
			restore_debian_default_route '-6'
		fi
	done
}

del_dev
exit 0
# end of script
