#!/bin/bash
# Copyright (c) 2015-2017, Parallels International GmbH
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

base_excl='/proc/
/boot/
/lib/modules/
/etc/fstab
/etc/mtab
/etc/inittab
/etc/sysctl.conf
/etc/init.d/syslog
/etc/grub.conf
/etc/lilo.conf
/etc/init.d/vzquota
/etc/rc.d/rc6.d/S00vzreboot'

net_excl='/etc/rc.d//rc.inet1.conf
/etc/rc.d/rc.inet1'

echo "${base_excl}"
echo "${net_excl}"
