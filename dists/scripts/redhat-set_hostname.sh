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
# This script sets up hostname inside VPS for RedHat like system
# For usage info see vz-veconfig(5) man page.
#
# Some parameters are passed in environment variables.
# Required parameters:
#   HOSTNM
#       Sets host name for this VPS. Modifies /etc/hosts and
#       /etc/sysconfig/network (in RedHat) or /etc/rc.config (in SuSE)
# Optional parameters:
#   IP_ADDR
#	ip address

function set_hostname()
{
	local cfg=$1
	local var=$2
	local val=$3

	put_param "${cfg}" "${var}" "${val}"
	echo "${val}" > /etc/hostname

	hostname "${val}"
}

[ -z "${HOSTNM}" ] && exit 0
change_hostname /etc/hosts "${HOSTNM}" "${IP_ADDR}"
set_hostname /etc/sysconfig/network HOSTNAME "${HOSTNM}"
if is_nm_enabled; then
	nm_set_hostname "${HOSTNM}"
fi
exit 0
