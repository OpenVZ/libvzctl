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

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <ploop/libploop.h>

#include "vzctl.h"
#include "image.h"
#include "logger.h"
#include "list.h"
#include "util.h"
#include "vzerror.h"
#include "vzctl.h"
#include "disk.h"
#include "cluster.h"
#include "config.h"

#define DEFAULT_FSTYPE		"ext4"
#define SNAPSHOT_MOUNT_ID	"snap"
#define FS_CORRECTED_MARK	".fs_corrected"

const char *get_root_disk_path(const char *ve_private, char *buf, int len)
{
	snprintf(buf, len, "%s/"VZCTL_VE_ROOTHDD_DIR, ve_private);
	return buf;
}

int open_dd(const char *path, struct ploop_disk_images_data **di)
{
	char fname[PATH_MAX];

	snprintf(fname, sizeof(fname), "%s/" DISKDESCRIPTOR_XML, path);
	if (ploop_open_dd(di, fname))
		return vzctl_err(VZCTL_E_PARSE_DD, 0, "Failed to read %s: %s",
				fname, ploop_get_last_error());
	return 0;
}

int read_dd(struct ploop_disk_images_data *di)
{
	if (ploop_read_dd(di))
		return vzctl_err(VZCTL_E_PARSE_DD, 0, "Failed to read %s : %s",
				DISKDESCRIPTOR_XML, ploop_get_last_error());
	return 0;
}
static int read_root_dd(const char *ve_private, struct ploop_disk_images_data **di)
{
	char fname[PATH_MAX];

	return open_dd(get_root_disk_path(ve_private, fname, sizeof(fname)), di);
}

int get_ploop_type(const char *type)
{
	if (type == NULL)
		return -1;
	if (!strcmp(type, "expanded"))
		return PLOOP_EXPANDED_MODE;
	else if (!strcmp(type, "plain"))
		return PLOOP_EXPANDED_PREALLOCATED_MODE;
	else if (!strcmp(type, "raw"))
		return PLOOP_RAW_MODE;

	return -1;
}

int vzctl2_is_image_mounted(const char *path)
{
	int ret;
	struct ploop_disk_images_data *di;
	char fname[PATH_MAX];
	struct stat st;

	snprintf(fname, sizeof(fname), "%s/" DISKDESCRIPTOR_XML, path);
	if (stat(fname, &st) && errno == ENOENT)
		return 0;

	ret = open_dd(path, &di);
	if (ret)
		return -1;

	ret = ploop_is_mounted(di);
	ploop_close_dd(di);

	return ret;
}


int fsck_flags2mode(int flags)
{
	return (flags & VZCTL_SKIP_FSCK ? VZCTL_PARAM_OFF :
		(flags & VZCTL_FORCE_REPAIR ? VZCTL_PARAM_FORCE_REPAIR : 0));
	
}

static int fsck_mode2flags(int mode)
{
	switch (mode) {
	case VZCTL_PARAM_OFF:
		return 0;
	case VZCTL_PARAM_FORCE_REPAIR:
		return E2FSCK_FORCE_REPAIR;
	default:
		return E2FSCK_PREEN;
	}
}

int mount_ploop_image(struct vzctl_env_handle *h, struct vzctl_disk *disk,
		 struct vzctl_mount_param *param)
{
	char fname[PATH_MAX];
	int ret;
	struct ploop_mount_param mount_param = {};
	struct ploop_disk_images_data *di;
	char *guid = param->guid;

	logger(0, 0, "Mount image: %s %s", disk->path, param->ro ? "ro" : "");

	ret = open_dd(disk->path, &di);
	if (ret)
		return ret;

	mount_param.ro = param->ro;
	mount_param.guid = guid;
	mount_param.fstype = DEFAULT_FSTYPE;
	mount_param.target = param->target;
	mount_param.mount_data = param->mount_data;
	if (!param->ro)
		mount_param.fsck_flags = fsck_mode2flags(param->fsck);
	mount_param.fsck_rc = 0;
	mount_param.flags = MS_REMOUNT;

	if (param->component_name != NULL)
		ploop_set_component_name(di, param->component_name);

	ret = ploop_mount_image(di, &mount_param);
	ploop_close_dd(di);
	if (ret && ret != SYSEXIT_NOSNAP)
		return vzctl_err(VZCTL_E_MOUNT_IMAGE, 0,
				"Failed to mount image %s: %s [%d]",
				disk->path, ploop_get_last_error(), ret);

	snprintf(fname, sizeof(fname), "%s/" FS_CORRECTED_MARK,
			param->target);
	if (mount_param.fsck_rc) {
		int fd;

		logger(0, 0, "File system errors were corrected for image=%s",
				disk->path);
		fd = open(fname, O_CREAT | O_RDONLY, 0644);
		if (fd != -1)
			close(fd);
	} else
		unlink(fname);

	snprintf(param->device, sizeof(param->device), "%s", mount_param.device);

	return 0;
}

int vzctl2_mount_disk_image(const char *path, struct vzctl_mount_param *param)
{
	struct vzctl_disk d = {.path = (char *)path};

	switch (get_disk_type(&d)) {
	case DISK_PLOOP:
		return mount_ploop_image(NULL, &d, param);
	default:
		return VZCTL_E_INVAL;
	}
}

int vzctl2_mount_image(const char *ve_private, struct vzctl_mount_param *param)
{
	char path[PATH_MAX];

	return vzctl2_mount_disk_image(get_root_disk_path(ve_private, path, sizeof(path)), param);
}

int vzctl2_umount_disk_image(const char *path)
{
	int ret;
	char val[12];
	int timeout = 190;
	struct ploop_disk_images_data *di;

	ret = open_dd(path, &di);
	if (ret)
		return ret;

	if (get_global_param("UMOUNT_TIMEOUT", val, sizeof(val)) == 0)
		parse_int(val, &timeout);

	ploop_set_umount_timeout(di, timeout);

	logger(0, 0, "Unmount image: %s (%d)", path, timeout);
	ret = ploop_umount_image(di);
	ploop_close_dd(di);
	if (ret && ret != SYSEXIT_DEV_NOT_MOUNTED)
		return vzctl_err(ret == SYSEXIT_UMOUNT_BUSY ?
					VZCTL_E_UMOUNT_BUSY :
					VZCTL_E_UMOUNT_IMAGE,
				0, "Failed to umount image: %s [%d]",
				ploop_get_last_error(), ret);
	return 0;
}

int vzctl2_umount_image(const char *ve_private)
{
	char path[PATH_MAX];

	return vzctl2_umount_disk_image(get_root_disk_path(ve_private, path, sizeof(path)));
}


int vzctl2_umount_image_by_dev(const char *dev)
{
	int ret;

	ret = ploop_umount(dev, NULL);
	if (ret)
		return vzctl_err(VZCTL_E_UMOUNT_IMAGE, 0,
				"Failed to umount device %s: %s [%d]",
				dev, ploop_get_last_error(), ret);
	return 0;
}

static int create_ploop_image(const char *path,
		struct vzctl_create_image_param *param)
{
	int ret = 0;
	struct ploop_create_param create_param = {};
	char image[PATH_MAX];

	if (mkdir(path, 0700) && errno != EEXIST)
		return vzctl_err(VZCTL_E_CREATE_IMAGE, errno,
				"Unable to create directory '%s'", path);
	snprintf(image, sizeof(image), "%s/root.hds", path);

	logger(0, 0, "Creating image: %s size=%luK", image, param->size);
	create_param.mode = param->mode;
	create_param.fstype = DEFAULT_FSTYPE;
	create_param.size = param->size * 2; /* 1K to sectors */
	create_param.image = image;
	create_param.keyid = param->enc_keyid;

	ret = ploop_create_image(&create_param);
	if (ret)
		return vzctl_err(VZCTL_E_CREATE_IMAGE, 0,
				"Failed to create image: %s [%d]",
				ploop_get_last_error(), ret);
	return 0;
}

int vzctl_create_image(struct vzctl_env_handle *h, const char *path,
		struct vzctl_create_image_param *param)
{
	return create_ploop_image(path, param);;
}

int vzctl2_create_disk_image(const char *path,
		struct vzctl_create_image_param *param)
{
	return vzctl_create_image(NULL, path, param);
}

int vzctl2_create_root_image(const char *ve_private, struct vzctl_create_image_param *param)
{
	char path[PATH_MAX];

	return vzctl2_create_disk_image(get_root_disk_path(ve_private, path, sizeof(path)), param);
}

int vzctl2_create_image(const char *ve_private, struct vzctl_create_image_param *param)
{
	return vzctl2_create_root_image(ve_private, param);
}

int vzctl2_convert_image(const char *ve_private, int mode)
{
	int ret;
	struct ploop_disk_images_data *di;

	ret = read_root_dd(ve_private, &di);
	if (ret)
		return ret;

	ret = ploop_convert_image(di, mode, 0);
	ploop_close_dd(di);
	if (ret)
		return vzctl_err(VZCTL_E_CONVERT_IMAGE, 0,
				"Failed to convert image: %s [%d]",
				ploop_get_last_error(), ret);
	return 0;
}

int resize_disk_image(const char *path, unsigned long long newsize, 
		int offline, pid_t mntns_pid)
{
	int ret;
	char dev[64];
	struct ploop_disk_images_data *di;
	struct ploop_resize_param param = {
		.offline_resize = offline,
		.mntns_pid = mntns_pid,
	};

	if (path == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0,
				"Failed to resize image: the image path is not specified");

	logger(0, 0, "Resize the image %s to %lluK", path, newsize);
	ret = open_dd(path, &di);
	if (ret)
		return ret;

	if (offline) {
		ret = ploop_get_dev(di, dev, sizeof(dev));
		if (ret == -1) {
			ret = vzctl_err(VZCTL_E_RESIZE_IMAGE, 0,
					"Failed to detect the state of image '%s': %s",
					path, ploop_get_last_error());
			goto err;
		}
		if (ret == 0) {
			ret = vzctl_err(VZCTL_E_RESIZE_IMAGE, 0,
					"Unable to use offline resize for the mounted image %s",
					path);
			goto err;
		}
	}

	param.size = newsize * 2; //1k -> 512

	ret = ploop_resize_image(di, &param);
	if (ret)
		ret = vzctl_err(VZCTL_E_RESIZE_IMAGE, 0,
				"Failed to resize image: %s [%d]",
				ploop_get_last_error(), ret);
err:
	ploop_close_dd(di);
	return ret;
}

int vzctl2_resize_disk_image(const char *path, unsigned long long newsize,
		int offline)
{
	return resize_disk_image(path, newsize, offline, 0);
}

int vzctl2_resize_image(const char *ve_private, unsigned long long newsize, int offline)
{
	char path[PATH_MAX];

	return vzctl2_resize_disk_image(get_root_disk_path(ve_private, path,
			sizeof(path)), newsize, offline);
}

int vzctl2_get_ploop_dev_by_mnt(const char *mnt, char *out, int len)
{
	if (mnt == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0, "Container mount point is not specified");
	return ploop_get_partition_by_mnt(mnt, out, len);
}

/* Find device by base delta and return name
 * Return:
 *  -1 on error
 *   0 found
 *   1 not found
 */
int vzctl2_get_ploop_dev(const char *path, char *dev, int len)
{
	struct ploop_disk_images_data *di;
	int ret;

	if (path == NULL)
		return vzctl_err(-1, 0, "Failed to get ploop device: "
				"the image path is not specified");

	if (open_dd(path, &di))
		return -1;

	ret = ploop_get_dev(di, dev, len);
	if (ret == -1)
		vzctl_err(-1, 0, "ploop_get_dev path=%s: %s",
				path, ploop_get_last_error());

	ploop_close_dd(di);

	return ret;
}

int vzctl2_get_ploop_dev2(const char *path, char *dev, int dlen, char *part,
		int plen)
{
	struct ploop_disk_images_data *di;
	int ret;

	if (path == NULL)
		return vzctl_err(-1, 0, "Failed to get ploop device: "
				"the image path is not specified");

	if (open_dd(path, &di))
		return -1;

	ret = ploop_get_dev(di, dev, dlen);
	if (ret) {
		if (ret == -1)
			vzctl_err(-1, 0, "ploop_get_dev path=%s: %s",
				path, ploop_get_last_error());
		goto err;
	}

	if (ploop_get_part(di, dev, part, plen)) {
		ret = vzctl_err(-1, 0, "loop_get_part devs: %s: %s",
				dev, ploop_get_last_error());
		goto err;
	}

err:
	ploop_close_dd(di);

	return ret;
}

int vzctl2_get_ploop_devs(const char *path, char **out[])
{
	struct ploop_disk_images_data *di;
	int ret;

	if (path == NULL)
		return vzctl_err(-1, 0, "Failed to get ploop device: "
				"the image path is not specified");

	ret = open_dd(path, &di);
	if (ret)
		return ret;

	ret = ploop_get_devs(di, out);
	if (ret == -1)
		ret = vzctl_err(VZCTL_E_SYSTEM, 0, "ploop_get_dev path=%s: %s",
				path, ploop_get_last_error());

	ploop_close_dd(di);

	return ret;
}

int vzctl2_get_top_image_fname(char *ve_private, char *out, int len)
{
	struct ploop_disk_images_data *di;
	int ret;

	if (ve_private == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0, "Failed to get top image name: "
				"CT private is not specified");

	ret = read_root_dd(ve_private, &di);
	if (ret)
		return ret;

	ret = ploop_get_top_delta_fname(di, out, len);
	if (ret)
		ret = vzctl_err(VZCTL_E_SYSTEM, 0, "ploop_get_top_delta_fname path=%s: %s",
				ve_private, ploop_get_last_error());

	ploop_close_dd(di);

	return ret;
}

int vzctl2_delete_disk_snapshot(const char *path, const char *guid)
{
	int ret;
	struct ploop_disk_images_data *di;

	if (path == NULL)
		return vzctl_err(VZCTL_E_DELETE_SNAPSHOT, 0,
				"Failed to delete snapshot: the image path is not specified");

	logger(0, 0, "Delete image snapshot uuid=%s image=%s", guid, path);
	ret = open_dd(path, &di);
	if (ret)
		return ret;

	ret = ploop_delete_snapshot(di, guid);
	if (ret == SYSEXIT_NOSNAP)
		ret = 0;

	ploop_close_dd(di);
	if (ret)
		return vzctl_err(VZCTL_E_DELETE_SNAPSHOT, 0,
				"Failed to delete snapshot: %s [%d]",
				ploop_get_last_error(), ret);
	return 0;
}

int vzctl2_delete_snapshot(struct vzctl_env_handle *h, const char *guid)
{
	struct vzctl_disk *disk;
	struct vzctl_env_disk *env_disk = h->env_param->disk;
	int ret = 0;

	list_for_each(disk, &env_disk->disks, list) {
		ret = vzctl2_delete_disk_snapshot(disk->path, guid);
		if (ret)
			return ret;
	}

	return ret;
}

void vzctl2_env_drop_cbt(struct vzctl_env_handle *h)
{
	struct ploop_disk_images_data *di;
	struct vzctl_disk *d;
	struct vzctl_env_disk *env_disk = h->env_param->disk;

	if (env_disk == NULL)
		return;

	list_for_each(d, &env_disk->disks, list) {
		if (d->use_device)
			continue;

		if (open_dd(d->path, &di))
			continue;

		ploop_drop_cbt(di);

		ploop_close_dd(di);
	}
}

int vzctl2_merge_disk_snapshot(const char *path, const char *guid)
{
	struct ploop_disk_images_data *di;
	int ret;
	struct ploop_merge_param param = {};

	if (guid == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0, "guid is not specified");

	if (path == NULL)
		return vzctl_err(VZCTL_E_MERGE_SNAPSHOT, 0,
				"Failed to merge snapshot: the image path is not specified");

	logger(0, 0, "Merge image snapshot uuid=%s image=%s", guid, path);
	ret = open_dd(path, &di);
	if (ret)
		return ret;

	param.guid = guid;

	ret = ploop_merge_snapshot(di, &param);
	ploop_close_dd(di);
	if (ret)
		return vzctl_err(VZCTL_E_MERGE_SNAPSHOT, 0,
				"Failed to merge snapshot %s: %s [%d]",
				guid, ploop_get_last_error(), ret);
	return 0;
}

int vzctl2_merge_snapshot(struct vzctl_env_handle *h, const char *guid)
{
	int ret;
	struct vzctl_disk *disk;
	struct vzctl_env_disk *env_disk = h->env_param->disk;

	list_for_each(disk, &env_disk->disks, list) {
		/* FIXME: skip if guid not exist */
		ret = vzctl2_merge_disk_snapshot(disk->path, guid);
		if (ret)
			return ret;
	}
	return 0;
}

void vzctl2_release_snap_holder(struct vzctl_snap_holder *holder)
{
	int i;

	if (holder == NULL)
		return;

	for (i = 0; i < holder->n; i++)
		close(holder->fds[i]);

	free(holder->fds);
	holder->n = 0;
	holder->fds = NULL;
}

static int *get_snap_holder_fd(struct vzctl_snap_holder *holder)
{
	int *tmp;

	if (holder == NULL)
		return NULL;

	tmp = realloc(holder->fds, sizeof(int) * (++holder->n));
	if (tmp == NULL) {
		vzctl_err(VZCTL_E_NOMEM, ENOMEM, "realloc failed");
		return NULL;
	}
	holder->fds = tmp;

	holder->fds[holder->n - 1] = -1;

	return &holder->fds[holder->n - 1];
}

static int create_disk_snapshot(const char *path, const char *guid,
		struct vzctl_tsnapshot_param *tsnap, struct vzctl_snap_holder *holder)
{
	int ret;
	struct ploop_disk_images_data *di;

	if (path == NULL)
		return vzctl_err(VZCTL_E_CREATE_SNAPSHOT, 0,
				"Failed to create snapshot: image path is not specified");

	logger(0, 0, "Creating image snapshot uuid=%s image=%s", guid, path);
	ret = open_dd(path, &di);
	if (ret)
		return ret;

	if (tsnap != NULL) {
		char cbt_uuid[STR_SIZE];
		struct ploop_tsnapshot_param snap = {
			.guid = (char *) guid,
			.component_name = tsnap->component_name,
			.snap_dir = tsnap->snap_dir,
		};

		if (tsnap->cbt_uuid != NULL) {
			vzctl_get_guid_str(tsnap->cbt_uuid, cbt_uuid);
			snap.cbt_uuid = cbt_uuid;
		}

		ret = ploop_create_temporary_snapshot(di, &snap,
				get_snap_holder_fd(holder));
		if (ret)
			vzctl2_release_snap_holder(holder);
	} else {
		struct ploop_snapshot_param snap = {
			.guid = (char *) guid,
		};

		ret = ploop_create_snapshot(di, &snap);
	}

	ploop_close_dd(di);
	if (ret)
		return vzctl_err(VZCTL_E_CREATE_SNAPSHOT, 0,
				"Failed to create image %s snapshot: %s [%d]",
				path, ploop_get_last_error(), ret);
	return 0;
}

int vzctl2_create_disk_snapshot(const char *path, const char *guid)
{
	return create_disk_snapshot(path, guid, NULL, NULL);
}

static int env_create_disk_snapshot(struct vzctl_env_handle *h,
		const char *guid, struct vzctl_tsnapshot_param *tsnap,
		struct vzctl_snap_holder *holder)
{
	int ret;
	struct vzctl_disk *disk, *entry;
	struct vzctl_env_disk *env_disk = h->env_param->disk;

	list_for_each(disk, &env_disk->disks, list) {
		if (!is_permanent_disk(disk))
			continue;
		ret = create_disk_snapshot(disk->path, guid, tsnap, holder);
		if (ret)
			goto err;
	}
	return 0;

err:
	/* rollback */
	for (entry = list_entry(disk->list.prev, typeof(*entry), list);
			&entry->list != (list_elem_t*)(&env_disk->disks);
			entry = list_entry(entry->list.prev, typeof(*entry), list))
		vzctl2_delete_disk_snapshot(entry->path, guid);


	return ret;
}

int vzctl2_env_create_disk_snapshot(struct vzctl_env_handle *h, const char *guid)
{
	return env_create_disk_snapshot(h, guid, NULL, NULL);
}

int vzctl2_create_snapshot(struct vzctl_env_handle *h, const char *guid)
{
	return vzctl2_env_create_disk_snapshot(h, guid);
}

int vzctl2_env_create_temporary_snapshot(struct vzctl_env_handle *h,
		const char *guid, struct vzctl_tsnapshot_param *param,
		struct vzctl_snap_holder *holder)
{
	int ret;
	char buf[39] = "";
	const char *snap_guid = guid;

	if (snap_guid == NULL) {
		ploop_uuid_generate(buf, sizeof(buf));
		snap_guid = buf;
	}

	ret = env_create_disk_snapshot(h, snap_guid, param, holder);
	if (ret)
		return ret;

	logger(0, 0, "Temporary snapshot %s has been successfully created",
			snap_guid);

	return 0;
}

int vzctl2_switch_disk_snapshot(const char *path, const char *guid, const char *guid_old, int flags)
{
	int ret;
	struct ploop_disk_images_data *di;
	struct ploop_snapshot_switch_param param = {};

	if (path == NULL)
		return vzctl_err(VZCTL_E_SWITCH_SNAPSHOT, 0,
				"Failed to switch to snapshot: image path is not specified");

	logger(0, 0, "Switching to image snapshot uuid=%s image=%s %s",
			guid, path, guid_old ? guid_old : "");
	ret = open_dd(path, &di);
	if (ret)
		return ret;

	param.guid = (char *)guid;
	param.guid_old = (char *)guid_old;
	param.flags = flags;

	ret = ploop_switch_snapshot_ex(di, &param);
	ploop_close_dd(di);
	if (ret)
		return vzctl_err(VZCTL_E_SWITCH_SNAPSHOT, 0,
				"Failed to switch to snapshot %s image %s: %s [%d]",
				guid, path, ploop_get_last_error(), ret);
	return 0;
}

int vzctl2_switch_snapshot(struct vzctl_env_handle *h, const char *guid,
		const char *guid_old)
{
	int ret;
	struct vzctl_disk *disk, *entry;
	struct vzctl_env_disk *env_disk = h->env_param->disk;
	int flags = guid_old ? PLOOP_SNAP_SKIP_TOPDELTA_DESTROY : 0;

	list_for_each(disk, &env_disk->disks, list) {
		/* FIXME: skip if guid not exist */
		ret = vzctl2_switch_disk_snapshot(disk->path, guid, guid_old, flags);
		if (ret)
			goto err;
	}

	return 0;
err:
	if (guid_old == NULL)
		return ret;

	/* rollback */
	flags = PLOOP_SNAP_SKIP_TOPDELTA_CREATE;
	for (entry = list_entry(disk->list.prev, typeof(*entry), list);
			&entry->list != (list_elem_t*)(&env_disk->disks);
			entry = list_entry(entry->list.prev, typeof(*entry), list))
		vzctl2_switch_disk_snapshot(entry->path, guid_old, NULL, flags);

	return ret;
}


static const char *generate_snapshot_component_name(const char *guid,
		char *buf, int len)
{
	char u[37];

	if (vzctl2_get_normalized_uuid(guid, u, sizeof(u)))
		snprintf(u, sizeof(u), "%s", guid);

	/* length limited by 'PLOOP_COOKIE_SIZE 64' */
	snprintf(buf, len, SNAPSHOT_MOUNT_ID"-%s", u);

	return buf;
}

int vzctl2_mount_disk_snapshot(const char *path, struct vzctl_mount_param *param)
{
	if (path == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0,
				"Failed to mount snapshot: image path is not specified");
	if (param->guid == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0,
				"Failed to mount snapshot: snapshot guid is not specified");

	return vzctl2_mount_disk_image(path, param);
}

static const char *get_snap_target(struct vzctl_disk *disk, const char *target,
		char *out, int size)
{
	if (target == NULL)
		return NULL;
			
	if (is_root_disk(disk))
		return target;

	if (disk->mnt == NULL)
		return NULL;

	snprintf(out, size, "%s/%s", target, disk->mnt);

	return out;
}

int vzctl2_mount_snap(struct vzctl_env_handle *h, const char *mnt, const char *guid,
		const char *component_name)
{
	int ret;
	struct vzctl_disk *disk, *entry;
	struct vzctl_env_disk *env_disk = h->env_param->disk;
	char mnt_opts[PATH_MAX] = "";
	char target[PATH_MAX];
	char cn[1024];
	struct vzctl_mount_param param = {
		.ro = 1,
		.guid = (char*)guid,
		.mount_data = mnt_opts,
		.fsck = VZCTL_PARAM_OFF,
	};

	if (find_root_disk(env_disk) == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0,
				"Failed to mount snapshot: root image is not configured");

	if (component_name == NULL) {
		generate_snapshot_component_name(guid, cn, sizeof(cn));
		component_name = cn;
	}

	param.component_name = (char*)component_name;

	list_for_each(disk, &env_disk->disks, list) {
		param.target = (char *)get_snap_target(disk, mnt, target, sizeof(target));
		vzctl_get_mount_opts(disk, mnt_opts, sizeof(mnt_opts));
		ret = vzctl2_mount_disk_snapshot(disk->path, &param);
		if (ret)
			goto err;
	}

	return 0;
err:
	/* rollback */
	for (entry = list_entry(disk->list.prev, typeof(*entry), list);
			&entry->list != (list_elem_t*)(&env_disk->disks);
			entry = list_entry(entry->list.prev, typeof(*entry), list))
		vzctl2_umount_disk_snapshot(entry->path, guid, component_name);

	return ret;
}

int vzctl2_mount_snapshot(struct vzctl_env_handle *h, struct vzctl_mount_param *param)
{
	char mnt_opts[PATH_MAX];
	char cn[1024];
	struct vzctl_disk *root;

	root = find_root_disk(h->env_param->disk);
	if (root == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0,
				"Failed to mount snapshot: root image is not configured");

	param->ro = 1;
	param->fsck = VZCTL_PARAM_OFF;

	if (param->component_name == NULL) {
		generate_snapshot_component_name(param->guid, cn, sizeof(cn));
		param->component_name = cn;
	}

	vzctl2_get_mount_opts(root->mnt_opts, root->user_quota, mnt_opts, sizeof(mnt_opts));

	return vzctl2_mount_disk_snapshot(root->path, param);
}

int vzctl2_umount_disk_snapshot(const char *path, const char *guid, const char *component_name)
{
	int ret;
	struct ploop_disk_images_data *di;

	if (path == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0,
				"Failed to umount snapshot: image path is not specified");

	if (guid == NULL && component_name == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0,
				"Failed to umount snapshot: snapshot guid is not specified");

	ret = open_dd(path, &di);
	if (ret)
		return ret;

	if (component_name != NULL)
		ploop_set_component_name(di, component_name);

	ret = ploop_umount_image(di);
	ploop_close_dd(di);
	if (ret && ret != SYSEXIT_DEV_NOT_MOUNTED)
		return vzctl_err(VZCTL_E_UMOUNT_SNAPSHOT, 0,
				"Failed to umount snapshot %s: %s [%d]",
				guid ? guid : component_name, ploop_get_last_error(), ret);
	return 0;
}

int vzctl2_umount_snapshot(struct vzctl_env_handle *h, const char *guid, const char *component_name)
{
	int ret;
	char cn[1024];
	struct vzctl_disk *disk;

	if (component_name == NULL)
		generate_snapshot_component_name(guid, cn, sizeof(cn));
	else
		snprintf(cn, sizeof(cn), "%s", component_name);

	list_for_each_prev(disk, &h->env_param->disk->disks, list) {
		ret = vzctl2_umount_disk_snapshot(disk->path, guid, cn);
		if (ret)
			return ret;
	}

	return 0;
}

int vzctl_encrypt_disk_image(const char *path, const char *keyid, int flags)
{
	int ret;
	struct ploop_disk_images_data *di;
	struct ploop_encrypt_param enc_param = {
		.keyid = keyid,
	};

	if (flags & VZCTL_ENC_REENCRYPT)
		enc_param.flags |= PLOOP_ENC_REENCRYPT;
	if (flags & VZCTL_ENC_WIPE)
		enc_param.flags |= PLOOP_ENC_WIPE;

	ret = open_dd(path, &di);
	if (ret)
		return ret;

	ret = ploop_encrypt_image(di, &enc_param);
	if (ret)
		ret = vzctl_err(VZCTL_E_ENCRYPT, 0, "ploop_encrypt_image: %s",
				ploop_get_last_error());

	ploop_close_dd(di);

	return ret;
}

int vzctl_compact_disk_image(struct vzctl_disk *disk,
		struct vzctl_compact_param *param)
{
	int ret;
	struct ploop_disk_images_data *di;
	struct ploop_discard_param p = {
		.automount = 1,
		.defrag = param->defrag,
	};

	if (disk->use_device || !is_permanent_disk(disk))
		return 0;

	logger(0, 0, "Compact %s", disk->path);
	ret = open_dd(disk->path, &di);
	if (ret)
		return ret;

	if (ploop_discard(di, &p))
		ret = vzctl_err(VZCTL_E_PLOOP, 0, "ploop_discard(%s): %s",
				disk->path, ploop_get_last_error());

	ploop_close_dd(di);

	return ret;
}
