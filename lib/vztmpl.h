/*
 * Copyright (c) 2015-2017, Parallels International GmbH
 * Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 * This file is part of OpenVZ libraries. OpenVZ is free software; you can
 * redistribute it and/or modify it under the terms of the GNU Lesser General
 * Public License as published by the Free Software Foundation; either version
 * 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/> or write to Free Software Foundation,
 * 51 Franklin Street, Fifth Floor Boston, MA 02110, USA.
 *
 * Our contact details: Virtuozzo International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#ifndef _VZCTL_VZTMPL_H_
#define _VZCTL_VZTMPL_H_

int vztmpl_get_ostmpl_name(const char *ostmpl, char *out, int len);
int vztmpl_get_technologies(const char *name, unsigned long long *tech);
int vztmpl_get_distribution(const char *ostmpl, char *out, int len);
int vztmpl_get_osrelease(const char *ostmpl, char *buf, int size);
int vztmpl_is_jquota_supported(const char *ostmpl);
int vztmpl_install_app(const char *ctid, const char *apps, int force);
int vztmpl_get_cache_tarball(const char *cache_config, char **ostmpl,
		const char *fstype, char **applist, int use_ostmpl,
		char *tarball, int len, unsigned int timeout);
int vztmpl_get_applist(ctid_t ctid, list_head_t *head, const char *ostmpl);
#endif
