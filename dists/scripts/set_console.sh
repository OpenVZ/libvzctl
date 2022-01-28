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

if [ -x /lib/systemd//systemd ]; then
	SYSTEMD_DIR=/lib/systemd/system
else
	SYSTEMD_DIR=/usr/lib/systemd/system
fi
ETC_SYSTEMD_DIR="/etc/systemd/system"

SYSTEMD_GETTY_SERVICE=$SYSTEMD_DIR/getty@.service

create_dev()
{
	local dev=$1
	local major=$2
	local minor=$3

	if [ ! -c /dev/$dev -o -L /dev/$dev ]; then
		rm -f /dev/$dev 2>/dev/null
		mknod /dev/$dev c $major $minor
	fi
}

fix_shell_console()
{
	[ -f $SYSTEMD_DIR/console-getty.service ] &&
		return

	echo '#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.

[Unit]
Description=Console Shell
After=systemd-user-sessions.service plymouth-quit-wait.service
Before=getty.target

[Service]
Environment=HOME=/root
WorkingDirectory=/root
ExecStart=-/sbin/agetty --noclear -s console 115200,38400,9600
Restart=always
RestartSec=0
UtmpIdentifier=cons
TTYPath=/dev/console
TTYReset=yes
TTYVHangup=yes
StandardInput=tty-force
StandardOutput=inherit
StandardError=inherit
KillMode=process

# Bash ignores SIGTERM, so we send SIGHUP instead, to ensure that bash
# terminates cleanly.
KillSignal=SIGHUP

[Install]
WantedBy=getty.target' > $SYSTEMD_DIR/console-getty.service


	rm -f $SYSTEMD_DIR/console-shell.service
}

setup_systemd_console()
{
	if grep -q -e 'ConditionPathExists=!/run/openvz' \
			-e 'ConditionPathExists=!/proc/vz' $SYSTEMD_GETTY_SERVICE 2>/dev/null; then
		sed -i -e '/ConditionPathExists=!\/run\/openvz/d' \
			-e '/ConditionPathExists=!\/proc\/vz/d' $SYSTEMD_GETTY_SERVICE
	fi

	[ -L  $SYSTEMD_DIR/getty.target.wants/getty@tty1.service ] && \
		rm -f $SYSTEMD_DIR/getty.target.wants/getty@tty1.service
	[ -L  $SYSTEMD_DIR/getty.target.wants/getty-static.service ] && \
		rm -f $SYSTEMD_DIR/getty.target.wants/getty-static.service
	[ -L  $ETC_SYSTEMD_DIR/getty.target.wants/getty@tty1.service ] && \
		rm -f $ETC_SYSTEMD_DIR/getty.target.wants/getty@tty1.service
	[ -L  $SYSTEMD_DIR/getty.target.wants/getty@tty2.service ] || \
		ln -sf $SYSTEMD_DIR/getty@.service $ETC_SYSTEMD_DIR/getty.target.wants/getty@tty2.service

	[ -f $SYSTEMD_DIR/console-shell.service ] &&
		fix_shell_console
}

setup_upstart_console()
{
	local file=/etc/init/$1.conf
	local getty

	if [ -x /sbin/mingetty ]; then
		getty='exec /sbin/mingetty'
	elif [ -x /sbin/getty ]; then
		getty='exec /sbin/getty 38400'
	else
		echo "Unable to find suitable getty, console setup is skipped"
		return
	fi

	echo "start on stopped rc RUNLEVEL=[2345]
stop on runlevel [!2345]
respawn
$getty $1" > $file

}

setup_upstart_event_console()
{
	local file=/etc/init.d/$1
	local getty

	if [ -x /sbin/mingetty ]; then
		getty='exec /sbin/mingetty'
	elif [ -x /sbin/getty ]; then
		getty='exec /sbin/getty 38400'
	else
		echo "Unable to find suitable getty console setup is skipped"
		return
	fi

	echo "start on stopped rc2
start on stopped rc3
start on stopped rc4
stop on runlevel 0
stop on runlevel 1
stop on runlevel 6
$getty $1" > $file
}

setup_inittab()
{
	local line
	local getty1
	local getty2

	if [ -x /sbin/mingetty ]; then
		getty1='/sbin/mingetty console'
		getty2='/sbin/mingetty tty2'
	elif [ -x /sbin/getty ]; then
		getty1='/sbin/getty 38400 console'
		getty2='/sbin/getty 38400 tty2'
	elif [ -x /sbin/agetty ]; then
		getty1='/sbin/agetty console 38400'
		getty2='/sbin/agetty tty2 38400'
	else
		echo "Unable to find suitable getty, console setup is skipped"
		return
	fi
	line="1:2345:respawn:$getty1"
	if ! grep -q "$line" /etc/inittab; then
		echo $line >> /etc/inittab
	fi
	line="2:2345:respawn:$getty2"
	if ! grep -q "$line" /etc/inittab; then
		echo $line >> /etc/inittab
	fi

}

setup_console()
{
	if [ -f "$SYSTEMD_GETTY_SERVICE" ]; then
		setup_systemd_console
	elif [ -d '/etc/init' ]; then
		setup_upstart_console console
		setup_upstart_console tty2
	elif [ -d "/etc/event.d" ]; then
		setup_upstart_event_console console
		setup_upstart_event_console tty2
	elif [ -f "/etc/inittab" ]; then
		setup_inittab
	fi

	create_dev console 5 1
	create_dev tty2 4 2
}

start_console()
{
	local cmd
	local tty=tty$START_CONSOLE_ON_TTY

	if [ -x /sbin/agetty ]; then
		cmd="/sbin/agetty $tty 38400 $TERM"
	elif [ -x /sbin/mingetty ]; then
		cmd="/sbin/mingetty $tty"
	elif [ -x /sbin/getty ]; then
		cmd="/sbin/getty 38400 $tty"
	else
		echo "No getty found."
		exit 1
	fi

	create_dev $tty 4 $START_CONSOLE_ON_TTY

	nohup setsid $cmd &
}

if [ -n "${START_CONSOLE_ON_TTY}" ]; then
	start_console
else
	setup_console
fi

# Randomize timers on CT start
randtimer
exit 0
