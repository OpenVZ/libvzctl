#  Copyright (C) 2000-2010, Parallels, Inc. All rights reserved.
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

include $(top_srcdir)/paths.am

nobase_distconf_SCRIPTS = \
	$(wildcard scripts/*.sh) \
	scripts/functions

distconf_DATA = \
	default

EXTRA_DIST = \
	$(nobase_distconf_SCRIPTS) \
	$(distconf_DATA) \
	$(wildcard *.conf)

# Some older versions of distros require specific conf files
REDHAT_7x_VER = 6.2 7.0 7.1 7.2 7.3 as21
REDHAT_VER = 8.0 9
CENTOS_VER = 3 4 5 6
RHEL_VER = 3 4 5
FC_VER = 1 2 3 4 5 6 7 8 9 11 12 13
SUSE_7x_VER = 7.3
SUSE_8x_VER = 8.0 8.1 8.2
SUSE_VER = 9.0 9.1 9.2 9.3 10.0 10.1 10.2 10.3 11.0 11.1 11.2 11.3
DEBIAN_VER = 3.0 3.1 4.0 5.0 6.0
UBUNTU_VER = 5.04 5.10 6.06 6.10 7.04 7.10 8.04 8.10 9.04 9.10 10.04 10.10
SLACK_9x_VER = 9.0 9.1
SLACK_VER = 10.0 10.1
SLES_VER = 9 10 11

centos:
	$(INSTALL_DATA) $(srcdir)/redhat.conf \
		$(DESTDIR)$(distconfdir)/centos.conf
	for ver in $(CENTOS_VER); do \
		$(INSTALL_DATA) $(srcdir)/redhat.conf \
			$(DESTDIR)$(distconfdir)/centos-$$ver.conf; \
	done
debian:
	$(INSTALL_DATA) $(srcdir)/debian.conf \
		$(DESTDIR)$(distconfdir)/debian.conf
	for ver in $(DEBIAN_VER); do \
		$(INSTALL_DATA) $(srcdir)/debian.conf \
		    $(DESTDIR)$(distconfdir)/debian-$$ver.conf; \
	done
fedora:
	$(INSTALL_DATA) $(srcdir)/fedora-core.conf \
		$(DESTDIR)$(distconfdir)/fedora-core.conf
	for ver in $(FC_VER); do \
		$(INSTALL_DATA) $(srcdir)/fedora-core.conf \
		    $(DESTDIR)$(distconfdir)/fedora-core-$$ver.conf; \
	done
gentoo:
	$(INSTALL_DATA) $(srcdir)/gentoo.conf \
		$(DESTDIR)$(distconfdir)/gentoo.conf
mandrake:
	$(INSTALL_DATA) $(srcdir)/mandrake.conf \
		$(DESTDIR)$(distconfdir)/mandrake.conf
redhat:
	$(INSTALL_DATA) $(srcdir)/redhat.conf \
		$(DESTDIR)$(distconfdir)/redhat.conf
	for ver in $(REDHAT_7x_VER); do \
		$(INSTALL_DATA) $(srcdir)/redhat-7.3.conf \
			$(DESTDIR)$(distconfdir)/redhat-$$ver.conf; \
	done
	for ver in $(REDHAT_VER); do \
		$(INSTALL_DATA) $(srcdir)/redhat.conf \
			$(DESTDIR)$(distconfdir)/redhat-$$ver.conf; \
	done
	for ver in $(RHEL_VER); do \
		$(INSTALL_DATA) $(srcdir)/rhel-3.conf \
			$(DESTDIR)$(distconfdir)/rhel-$$ver.conf; \
	done
	$(INSTALL_DATA) $(srcdir)/redhat.conf \
		$(DESTDIR)$(distconfdir)/rhel.conf

scientific:
	$(INSTALL_DATA) $(srcdir)/redhat.conf \
		$(DESTDIR)$(distconfdir)/scientific.conf

slack:
	$(INSTALL_DATA) $(srcdir)/slackware.conf \
		$(DESTDIR)$(distconfdir)/slackware.conf
	for ver in $(SLACK_9x_VER); do \
		$(INSTALL_DATA) $(srcdir)/slackware-9.0.conf \
			$(DESTDIR)$(distconfdir)/slackware-$$ver.conf; \
	done
	for ver in $(SLACK_VER); do \
		$(INSTALL_DATA) $(srcdir)/slackware.conf \
			$(DESTDIR)$(distconfdir)/slackware-$$ver.conf; \
	done
suse:
	$(INSTALL_DATA) $(srcdir)/suse.conf \
		$(DESTDIR)$(distconfdir)/suse.conf
	$(INSTALL_DATA) $(srcdir)/suse.conf \
		$(DESTDIR)$(distconfdir)/opensuse.conf
	$(INSTALL_DATA) $(srcdir)/suse.conf \
		$(DESTDIR)$(distconfdir)/sles.conf
	for ver in $(SUSE_7x_VER); do \
		$(INSTALL_DATA) $(srcdir)/suse-7.3.conf \
		    $(DESTDIR)$(distconfdir)/suse-$$ver.conf; \
	done
	for ver in $(SUSE_8x_VER); do \
		$(INSTALL_DATA) $(srcdir)/suse-8.0.conf \
		    $(DESTDIR)$(distconfdir)/suse-$$ver.conf; \
	done
	for ver in $(SUSE_VER); do \
		$(INSTALL_DATA) $(srcdir)/suse.conf \
		    $(DESTDIR)$(distconfdir)/suse-$$ver.conf; \
	done
	for ver in $(SLES_VER); do \
		$(INSTALL_DATA) $(srcdir)/sles.conf \
		    $(DESTDIR)$(distconfdir)/sles-$$ver.conf; \
	done
	$(INSTALL_DATA) $(srcdir)/sles.conf \
		$(DESTDIR)$(distconfdir)/sles.conf
ubuntu:
	for ver in $(DEBIAN_VER); do \
		$(INSTALL_DATA) $(srcdir)/debian.conf \
		    $(DESTDIR)$(distconfdir)/debian-$$ver.conf; \
	done
	$(INSTALL_DATA) $(srcdir)/debian.conf \
		$(DESTDIR)$(distconfdir)/debian.conf
ubuntu:
	for ver in $(UBUNTU_VER); do \
		$(INSTALL_DATA) $(srcdir)/debian.conf \
		    $(DESTDIR)$(distconfdir)/ubuntu-$$ver.conf; \
	done
	$(INSTALL_DATA) $(srcdir)/debian.conf \
		$(DESTDIR)$(distconfdir)/ubuntu.conf

install-data-hook:\
                   centos \
                   debian \
                   fedora \
                   gentoo \
                   mandrake \
                   redhat \
                   slack \
                   suse \
                   ubuntu
