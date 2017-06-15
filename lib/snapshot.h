/*
 * Copyright (c) 2015-2017, Parallels International GmbH
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
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#ifndef __SNAPSHOT_H__
#define __SNAPSHOT_H__

#define SNAPSHOT_XML    "Snapshots.xml"
#define GET_SNAPSHOT_XML(buf, ve_private) \
	snprintf(buf, sizeof(buf), "%s/" SNAPSHOT_XML, ve_private);

struct vzctl_env_handle;

int vzctl_read_snapshot_tree(const char *fname, struct vzctl_snapshot_tree *tree);
int vzctl_store_snapshot_tree(const char *fname, struct vzctl_snapshot_tree *tree);
int vzctl_add_snapshot_tree_entry(struct vzctl_snapshot_tree *tree, int current,
		const char *guid, const char *parent_guid, const char *name,
		const char *date, const char *desc);
int vzctl_env_switch_snapshot(struct vzctl_env_handle *h,
		struct vzctl_switch_snapshot_param *param);
int vzctl_env_delete_snapshot(struct vzctl_env_handle *h, const char *guid);
int vzctl_env_create_snapshot(struct vzctl_env_handle *h,
		struct vzctl_snapshot_param *param);
#endif
