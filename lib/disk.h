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

#ifndef __DISK_H__
#define __DISK_H__

#include "list.h"
#include "libvzctl.h"

#define DISK_ROOT_UUID	"{00000000-0000-0000-0000-000000000000}"


typedef int (*disk_mount)(struct vzctl_env_handle *h, struct vzctl_disk *d, int flags);
typedef int (*disk_umount)(struct vzctl_disk *d);

struct vzctl_disk {
	list_elem_t list;
	char uuid[39];
	int enabled;
	unsigned long size;
	char *path;
	char *mnt;
	char *mnt_opts;
	int mnt_flags;
	int user_quota;
	int autocompact;
	char fsuuid[39];
	char *storage_url;
	int use_device;
	char *devname;
	dev_t dev;
	char *partname;
	dev_t part_dev;
	char *dmname;
	dev_t dm_dev;
	char *enc_keyid;
	disk_mount mount;
	disk_umount umount;
};

struct vzctl_env_disk {
	list_head_t disks;
	int root;		/* is root disk configured */
};

int is_root_disk(struct vzctl_disk *disk);
const char *get_fs_partname(struct vzctl_disk *disk);
dev_t get_fs_partdev(struct vzctl_disk *disk);
int configure_mount_opts(struct vzctl_env_handle *h, struct vzctl_disk *disk);
int configure_disk(struct vzctl_env_handle *h, struct vzctl_disk *disk,
		int flags, int automount);
void free_disk_param(struct vzctl_disk_param *disk);
void free_disk(struct vzctl_disk *disk);
void free_env_disk(struct vzctl_env_disk *env_disk);
int configure_disk_perm(struct vzctl_env_handle *h, struct vzctl_disk *disk,
		int del);
int update_disk_info(struct vzctl_disk *disk);
struct vzctl_env_disk *alloc_env_disk(void);
struct vzctl_disk *find_root_disk(const struct vzctl_env_disk *env_disk);
int is_secondary_disk_present(const struct vzctl_env_disk *env_disk);
const char *get_root_disk(struct vzctl_env_handle *h);
int set_disk_param(struct vzctl_env_param *env, int flags);
int parse_disk(struct vzctl_env_disk *env_disk, const char *str);
char *disk2str(struct vzctl_env_handle *h, struct vzctl_env_disk *env_disk);
int vzctl2_mount_disk(struct vzctl_env_handle *h,
		const struct vzctl_env_disk *env_disk, int flags);
int vzctl2_umount_disk(const struct vzctl_env_disk *env_disk);
int vzctl2_add_disk(struct vzctl_env_handle *h, struct vzctl_disk_param *param, int flags);
int vzctl2_del_disk(struct vzctl_env_handle *h, const char *guid, int flags);
int vzctl2_set_disk(struct vzctl_env_handle *h, struct vzctl_disk_param *param);
int vzctl2_resize_disk(struct vzctl_env_handle *h, const char *guid,
		unsigned long size, int offline);
int vzctl_setup_disk(struct vzctl_env_handle *h, struct vzctl_env_disk *env_disk, int flags);
int get_fs_uuid(const char *device, char *uuid);
int env_fin_configure_disk(struct vzctl_env_disk *disk);
int fin_configure_disk(struct vzctl_env_handle *h, struct vzctl_env_disk *disk);
void get_partition_dev_name(dev_t dev, char *out, int len);
int is_external_disk(const char *path);
int check_external_disk(const char *basedir, struct vzctl_env_disk *env_disk);
unsigned long get_disk_size(unsigned long size);
int set_max_diskspace(struct vzctl_2UL_res **diskspace);
#endif
