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

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ploop/libploop.h>
#include <unistd.h>
#include <sys/mount.h>

#include "vzerror.h"
#include "disk.h"
#include "util.h"
#include "logger.h"
#include "exec.h"

static char *get_disk_id(struct vzctl_env_handle *h,
		struct vzctl_disk *disk, char *out, int len)
{
	char u[34];

	vzctl2_get_normalized_ctid(disk->uuid, u, sizeof(u));
	snprintf(out, len, "disk_%s_%s", EID(h), u);

	return out;
}

int get_qcow2_info(struct vzctl_env_handle *h, struct vzctl_disk *disk,
		char *out, int len)
{
	int ret;
	char buf[STR_SIZE];
	char id[STR_SIZE];
	char *a[] = {"/usr/libexec/vzqtctl", "-c", "info",
		 "-d", get_disk_id(h, disk, id, sizeof(id)), NULL};

	ret = get_last_line(a, buf, sizeof(buf));
	if (ret)
		return ret;

	if (sscanf(buf, "\"device\": \"%[^\"]\"", out) != 1)
		return vzctl_err(VZCTL_E_SYSTEM, 0, "Can not parse device %s",
				buf);

	return ret;
}

static int qemu_tcmu_ctl(struct vzctl_env_handle *h,
	struct vzctl_disk *disk, const char *cmd)
{
	char id[STR_SIZE];
	char *a[] = {"/usr/libexec/vzqtctl", "-c", (char *)cmd,
		"-d", get_disk_id(h, disk, id, sizeof(id)),
		"-i", disk->path, NULL};

	logger(0, 0, "%s qemu TCMU %s", cmd, id);
	return vzctl2_wrap_exec_script(a, NULL, 0);
}

static int mount_device(struct vzctl_env_handle *h, struct vzctl_disk *disk,
		struct vzctl_mount_param *param)
{
	struct ploop_mount_param mount_param = {};

	if (param->target == NULL)
		return 0;

	mount_param.ro = param->ro;
	mount_param.target = param->target;
	mount_param.mount_data = param->mount_data;
	mount_param.fsck = (!param->ro && param->fsck != VZCTL_PARAM_OFF);

        logger(0, 0, "Mount root disk device %s %s",
                        disk->partname, param->target?:"");

	if (ploop_mount_fs(NULL, disk->partname, &mount_param, 0))
		return vzctl_err(VZCTL_E_MOUNT_IMAGE, 0,
				"Failed to mount image %s: %s ",
				disk->path, ploop_get_last_error());
        return 0;
}

int mount_qcow2_image(struct vzctl_env_handle *h, struct vzctl_disk *disk,
		struct vzctl_mount_param *param)
{
	int ret;

	ret = qemu_tcmu_ctl(h, disk, "add");
	if (ret)
		return ret;

	ret = update_disk_info(h, disk);
	if (ret)
		goto err;

	ret = mount_device(h, disk, param);
	if (ret)
		goto err;

	return 0;
err:
	qemu_tcmu_ctl(h, disk, "del");

	return ret;
}

int umount_qcow2_image(struct vzctl_env_handle *h, struct vzctl_disk *disk)
{
	int ret;
	char dev[STR_SIZE];
	char target[PATH_MAX];

	logger(0, 0, "Umount qcow image: %s", disk->path);
	ret = get_qcow2_info(h, disk, dev, sizeof(dev));
	if (ret)
		return ret;

	ret = get_mnt_by_dev(dev, target, sizeof(target));
	if (ret == -1)
                return vzctl_err(VZCTL_E_UMOUNT_IMAGE, 0,
                                "Unable to get mount point by %s: %s",
                                dev, ploop_get_last_error());
	if (ret == 0) {
                logger(0, 0, "Unmount device=%s mnt=%s", dev, target);
                if (umount(target))
                        return vzctl_err(VZCTL_E_UMOUNT_IMAGE, errno,
                                        "Failed to unmount %s", target);
	}

	return qemu_tcmu_ctl(h, disk, "del");
}

int create_qcow_image(struct vzctl_env_handle *h, const char *fname,
		struct vzctl_create_image_param *param)
{
	int ret;
	char s[12];
	struct vzctl_mount_param mount_param = {
		.fsck = VZCTL_PARAM_OFF
	};
	struct ploop_create_param p = {.fstype = "ext4"};
	struct vzctl_disk *d;
	char *a[] = {"/usr/bin/qemu-img", "create", "-f", "qcow2",
			(char *) fname, s, NULL};

	snprintf(s, sizeof(s), "%luK", param->size);
	ret = vzctl2_wrap_exec_script(a, NULL, 0);
	if (ret)
		return ret;

	d = calloc(1, sizeof(struct vzctl_disk));
	strcpy(d->uuid, DISK_ROOT_UUID);
	d->path = strdup(fname);
	ret = mount_qcow2_image(h, d, &mount_param);
	if (ret)
		goto err;

	if (ploop_init_device(d->devname, &p))
		ret = vzctl_err(VZCTL_E_SYSTEM, 0, "ploop_init_device: %s",
			ploop_get_last_error());
		
	umount_qcow2_image(h, d);

err:
	if (ret)
		unlink(fname);
	
	free_disk(d);

	return ret;
}
