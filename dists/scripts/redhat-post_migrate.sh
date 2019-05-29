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

EXT='.migsave'

function backup()
{
	local file=$1
	echo "redhat-post_migrate: modifying ${file}"
	[ -f "${file}${EXT}" ] || cp -fp "${file}" "${file}${EXT}"
}

function make_dev()
{
	[ -d /dev ] || mkdir -p /dev
	if [ -d /etc/udev/makedev.d ]; then
		echo -e 'null\nstd\nurandom\npty\nconsole\nptmx' > \
			/etc/udev/makedev.d/51-ptyudev.nodes
	else
		cd /dev
		MAKEDEV null std urandom pty console ptmx
	fi
}

fix_init()
{
	if [ -d /etc/init ]; then
		mkdir -p /etc/init.removed
		mv -f /etc/init/*tty*.conf /etc/init.removed
		mv -f /etc/init/serial.conf /etc/init.removed
		mv -f /etc/init/*plymouth*.conf /etc/init.removed
		mv -f /etc/init/prefdm.conf /etc/init.removed

		for f in `ls -1 /etc/init/*.conf`; do
			sed -i "s,^console output,#console output,g" $f
		done
	fi

	# tune services on
	/sbin/chkconfig haldaemon off
	/sbin/chkconfig NetworkManager off
	/sbin/chkconfig network on

	# Fix sshd_config
	CFG_FILE=/etc/ssh/sshd_config
	if [ -f $CFG_FILE ]; then
	    sed -ie "s/^X11Forwarding yes/X11Forwarding no/" $CFG_FILE
	fi
}


function fix_plesk()
{
	conf="/etc/psa/psa.conf"

	if [ ! -r "$conf" ]; then
		return
	fi
	PRODUCT_ROOT_D=`egrep '^PRODUCT_ROOT_D' ${conf} | awk '{ print $2; }'`
	if [ -z "$PRODUCT_ROOT_D" ]; then
		return
	fi
	ADMIN_ROOT="$PRODUCT_ROOT_D/admin"
	admin_httpsd_conf="$ADMIN_ROOT/conf/httpsd.conf"
	if [ ! -f "${admin_httpsd_conf}" ]; then
		return
	fi
	if egrep -q '^[[:space:]]*Listen[[:space:]]*8880[[:space:]]*$' "$admin_httpsd_conf"; then
		return
	fi
	cat >> "$admin_httpsd_conf" << EOF

Listen 8880
<VirtualHost _default_:8880>
	UseCanonicalName off
	SSLEngine off
	RewriteEngine On
	RewriteCond %{REQUEST_URI} ^\/sitepreview\/(.{0,})$
	RewriteRule ^\/sitepreview\/(.{0,})$ /sitepreview.php?\$1 [L]
	ErrorDocument 301 /vzcp_redirect.php?rc=301
	ErrorDocument 403 /vzcp_redirect.php?rc=403
	ErrorDocument 404 /vzcp_redirect.php?rc=404
	<Directory "${PRODUCT_ROOT_D}/admin/htdocs/sshterm">
		ErrorDocument 404 "
	</Directory>
</VirtualHost>
EOF
}


[ -e /etc/mtab ] && rm -f /etc/mtab
ln -sf /proc/mounts /etc/mtab

# Do not launch mingetty on tty devices - they are not accessible from
# VPS
CFG_FILE=/etc/inittab
if [ -f ${CFG_FILE} ]; then
	backup ${CFG_FILE}
	cp -fp  ${CFG_FILE} ${CFG_FILE}.$$
	sed '/^.*getty.*$/d' < ${CFG_FILE} > ${CFG_FILE}.$$ \
		&& mv -f ${CFG_FILE}.$$ ${CFG_FILE}
	if [ $? -ne 0 ]; then
		rm -f ${CFG_FILE}.$$ 2>/dev/null
	fi
fi

# Disable klogd
CFG_FILE=/etc/init.d/syslog
if [ -f ${CFG_FILE} ]; then
	backup ${CFG_FILE}
	cp -fp  ${CFG_FILE} ${CFG_FILE}.$$
	sed -e 's/daemon klogd/passed klogd skipped #&/' \
		-e 's/killproc klogd/passed klogd skipped #&/' \
		< ${CFG_FILE} > ${CFG_FILE}.$$ \
		&& mv -f ${CFG_FILE}.$$ ${CFG_FILE}
	if [ $? -ne 0 ]; then
		rm -f ${CFG_FILE}.$$ 2>/dev/null
	fi
fi

# Fix kernel in sysctl.conf
CFG_FILE=/etc/sysctl.conf
cat ${CFG_FILE} | grep "^kernel" >/dev/null 2>&1
if [ $? -eq 0 ]; then
	backup ${CFG_FILE}
	cp -fp ${CFG_FILE} ${CFG_FILE}.$$
	cat ${CFG_FILE} | sed "s,^kernel.sysrq,# kernel.sysrq,g" | \
		sed "s,^kernel.core_uses_pid,# kernel.core_uses_pid,g" \
		> ${CFG_FILE}.$$
	[ $? -eq 0 ] && mv -f ${CFG_FILE}.$$ ${CFG_FILE}
fi

# Fix /etc/fstab
CFG_FILE=/etc/fstab
backup ${CFG_FILE}
sed -e '/^\s*$\|^\s*\#\|devpts\|proc/! {s/\(.*\)/#mig# \1/;}' < ${CFG_FILE} > \
	${CFG_FILE}.$$ && mv ${CFG_FILE}.$$ ${CFG_FILE}

# Fix /etc/syslog.conf
CFG_FILE=/etc/syslog.conf
if [ -f ${CFG_FILE} ]; then
	backup ${CFG_FILE}
	cp -fp  ${CFG_FILE} ${CFG_FILE}.$$
	sed -e 's/\([[:space:]]\)\(\/var\/log\/\)/\1-\2/g' \
		< ${CFG_FILE} > ${CFG_FILE}.$$ \
		&& mv -f ${CFG_FILE}.$$ ${CFG_FILE}
	if [ $? -ne 0 ]; then
		rm -f ${CFG_FILE}.$$ 2>/dev/null
	fi
fi

# Remove network interfaces
if [ -d /etc/sysconfig/network-scripts ]; then
	cd /etc/sysconfig/network-scripts
	for cfg in `ls -1 ifcfg-*`; do
		if [ "$cfg" != "ifcfg-lo" ]; then
			rm -f  $cfg
		fi
	done
	rm -f ifup-venet
fi

chkconfig --del kudzu 2>&1 >/dev/null
#for mandrake
chkconfig --del harddrake 2>&1 >/dev/null

make_dev
fix_init
fix_plesk
exit 0
