#  Copyright (c) 2000-2017, Parallels International GmbH. All rights reserved.
# Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

include $(top_srcdir)/pathsubst.am

script_SCRIPTS = \
		 cgroup-props.conf \
		 vz-announce_ips \
		 vz-cpt-action \
		 vz-cpt \
		 vz-create_prvt \
		 vz-functions \
		 vznetcfg \
		 vz-netns_dev_add \
		 vz-netns_dev_del \
		 vz-pci_configure \
		 vz-postinst \
		 vz-rst-action \
		 vz-rst \
		 vz-setrate \
		 vz-start \
		 vz-stop


scriptd_DATA = README

EXTRA_DIST = \
	$(script_SCRIPTS:%=%.in) \
	$(scriptd_DATA)

CLEANFILES = \
	$(script_SCRIPTS)
