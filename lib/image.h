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

#ifndef _IMAGE_H_
#define _IMAGE_H_

#include <ploop/libploop.h>

struct vzctl_env_handle;
struct vzctl_mount_param;
struct vzctl_create_image_param;
struct vzctl_disk;
struct vzctl_compact_param;

const char *get_root_disk_path(const char *ve_private, char *buf, int len);
int open_dd(const char *path, struct ploop_disk_images_data **di);
int read_dd(struct ploop_disk_images_data *di);
int get_ploop_type(const char *type);
int vzctl2_get_ploop_devs(const char *path, char **out[]);
int vzctl2_switch_snapshot(struct vzctl_env_handle *h, const char *guid,
		const char *guid_old);
int resize_disk_image(const char *path, unsigned long long newsize,
		int offline, pid_t mntns_pid);
int vzctl_encrypt_disk_image(const char *path, const char *keyid, int flags);
int vzctl_compact_disk_image(struct vzctl_disk *disk, struct vzctl_compact_param *param);
int mount_ploop_image(struct vzctl_env_handle *h, struct vzctl_disk *disk,
		struct vzctl_mount_param *param);
int vzctl_create_image(struct vzctl_env_handle *h, const char *path,
		struct vzctl_create_image_param *param);
int fsck_flags2mode(int flags);
int get_ploop_quota_type(int mode);
#endif
