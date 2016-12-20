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
# This script sets user:passwd inside VPS
#
# Some parameters are passed in environment variables.
# Required parameters:
#   USERPW  - Sets password for user, adding this user if it doesn't exist.
# Optional parameters:
#   IS_CRYPTED  - Set it if the password is crypted.
CFGFILE="/etc/passwd"

function set_serrpasswd()
{
	local userpw="$1"
	local is_crypted="$2"
	local user=${userpw/:*/}
	local passwd=${userpw:${#user}+1}

	if [ -z "${user}" -o  -z "${passwd}" ]; then
		exit $VZ_CHANGEPASS
	fi

	if [ ! -c /dev/urandom ]; then
		mknod /dev/urandom c 1 9 > /dev/null 2>&1
	fi

	if [ -z "${is_crypted}" ]; then
		local command="chpasswd"
	else
		local command="chpasswd -e"
	fi

	if ! grep -E "^${user}:" ${CFGFILE} 2>&1 >/dev/null; then
		useradd -m "${user}" 2>&1 || exit $VZ_CHANGEPASS
	fi
	echo "${passwd}" | passwd --stdin "${user}" 2>/dev/null
	if [ $? -ne 0 ] || [ ! -z "${is_crypted}" ]; then
		echo "${user}:${passwd}" | $command --md5 >/dev/null 2>&1 || \
			echo "${user}:${passwd}" | $command 2>&1 || exit $VZ_CHANGEPASS
	fi
}

function set_screenrc()
{
	local userpw="$1"
	local user=${userpw/:*/}
	local file="/home/${user}/.screenrc"

	[ -f "$file" ] && return 0

	echo "defshell -/bin/bash" > "$file"
}

[ -z "${USERPW}" ] && exit 1
set_serrpasswd "${USERPW}" "${IS_CRYPTED}"
set_screenrc "${USERPW}"

exit 0
