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
# This script sets hostname inside VPS for Debian like distros
# For usage info see vz-veconfig(5) man page.
#
# Some parameters are passed in environment variables.
# Required parameters:
# Optional parameters:
#   HOSTNM
#       Sets host name for this VE.

function set_hostname()
{
	local cfgfile=$1
	local hostname=$2

	[ -z "${hostname}" ] && return 0
	echo "${hostname}" > /etc/hostname
	hostname ${hostname}
}

[ -z "${HOSTNM}" ] && exit 0
change_hostname /etc/hosts "${HOSTNM}" "${IP_ADDR}"
set_hostname /etc/hostname "${HOSTNM}"

exit 0
