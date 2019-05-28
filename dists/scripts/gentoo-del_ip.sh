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
# This script deletes IP alias(es) inside VPS for Gentoo like distros.
# For usage info see ve-alias_del(5) man page.
#
# Parameters are passed in environment variables.
# Required parameters:
#   IP_ADDR       - IPs to delete, several addresses should be divided by space
# Optional parameters:
#   VE_STATE      - state of VPS; could be one of:
#                     starting | stopping | running | stopped
VENET_DEV=venet0
CFGFILE=/etc/conf.d/net

# Function to delete IP address for Debian template
function del_ip()
{
	local found=
	local ip ipm

	for ipm in ${IP_ADDR}; do
		ip=${ipm%%/*}
		grep -qw "${ip}" ${CFGFILE} && found=true && \
			del_param3 "${CFGFILE}" "config_${VENET_DEV}" "${ip}/32"
	done
	if [ -n "${found}" ]; then
		/etc/init.d/net.${VENET_DEV} restart 2>/dev/null 1>/dev/null
	fi
}

del_ip
exit 0
# end of script
