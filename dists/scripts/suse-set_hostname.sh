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
# This script sets up various files inside VE for SuSE like distros
#
# Some parameters are passed in environment variables.
# Required parameters:
#   HOSTNM  - Sets host name for this VE. Modifies /etc/hosts

function set_hostname()
{
	local cfgfile="$1"
	local hostname=$2

	[ -z "${hostname}" ] && return 0
	echo "${hostname}" > ${cfgfile}
	hostname "${hostname%%.*}"
}

function set_domainname()
{
	local cfgfile="$1"
	local domain=${2#*.}

	echo "${domain}" > ${cfgfile}
}

[ -z "${HOSTNM}" ] && exit 0
change_hostname /etc/hosts "${HOSTNM}" "${IP_ADDR}"
set_hostname /etc/HOSTNAME "${HOSTNM}"

exit 0
