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

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <errno.h>
#include <ploop/libploop.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <libgen.h>
#include <dirent.h>
#include <string.h>
#include <sys/sysmacros.h>

#include "libvzctl.h"
#include "vzerror.h"
#include "image.h"
#include "disk.h"
#include "util.h"
#include "logger.h"
#include "vzctl.h"
#include "vztypes.h"
#include "env.h"
#include "vzctl.h"
#include "vz.h"
#include "image.h"
#include "dev.h"
#include "env_ops.h"
#include "ha.h"
#include "cluster.h"
#include "cgroup.h"
#include "sysfs_perm.h"
#include "exec.h"
#include "disk.h"

static int umount_disk_device(struct vzctl_disk *d);

disk_type get_disk_type(struct vzctl_disk *disk)
{
	return disk->use_device ? DISK_DEVICE : DISK_PLOOP;
}

void free_disk_param(struct vzctl_disk_param *disk)
{
	free(disk->path);
	free(disk->mnt);
	free(disk->storage_url);
	free(disk);
}

void free_disk(struct vzctl_disk *disk)
{
	free(disk->path);
	free(disk->mnt);
	free(disk->mnt_opts);
	free(disk->storage_url);
	free(disk->devname);
	free(disk->sys_devname);
	free(disk->partname);
	free(disk->sys_partname);
	free(disk->enc_keyid);
	free(disk);
}

void free_env_disk(struct vzctl_env_disk *env_disk)
{
	struct vzctl_disk *d, *tmp;

	list_for_each_safe(d, tmp, &env_disk->disks, list)
		free_disk(d);
	free(env_disk);
}

struct vzctl_env_disk *alloc_env_disk(void)
{
	struct vzctl_env_disk *d;

	d = calloc(1, sizeof(struct vzctl_env_disk));
	if (d == NULL)
		return NULL;

	list_head_init(&d->disks);

	return d;
}

void add_disk(struct vzctl_env_disk *env_disk, struct vzctl_disk *disk)
{
	list_add_tail(&disk->list, &env_disk->disks);
}

static int is_root_mnt(const char *mnt)
{
	return (mnt != NULL && strcmp(mnt, "/") == 0);
}

int is_root_disk(struct vzctl_disk *disk)
{
	return is_root_mnt(disk->mnt);
}

struct vzctl_disk *find_root_disk(const struct vzctl_env_disk *env_disk)
{
	struct vzctl_disk *disk;

	if (env_disk == NULL)
		return NULL;

	list_for_each(disk, &env_disk->disks, list)
		if (is_root_disk(disk))
			return disk;

	return NULL;
}

int is_secondary_disk_present(const struct vzctl_env_disk *env_disk)
{
	struct vzctl_disk *disk;

	list_for_each(disk, &env_disk->disks, list)
		if (!is_root_disk(disk))
			return 1;

	return 0;
}

char *get_rel_path(const char *basedir, const char *fname, char *buf, int len)
{
	const char *p;
	int n;

	p = fname;

	if (basedir != NULL) {
		n = strlen(basedir);
		if (basedir[n - 1] == '/')
			n--;
		if (strncmp(fname, basedir, n) == 0 && fname[n] == '/')
			p += n + 1;
	}

	snprintf(buf, len, "%s", p);

	return buf;
}

char *get_abs_path(const char *basedir, const char *fname, char *buf, int len)
{
	if (basedir == NULL || fname[0] == '/')
		snprintf(buf, len, "%s", fname);
	else
		snprintf(buf, len, "%s/%s", basedir, fname);

	return buf;
}

struct vzctl_disk *disk_param2disk(struct vzctl_env_handle *h,
		struct vzctl_disk_param *param)
{
	struct vzctl_disk *d;
	char path[PATH_MAX];

	d = calloc(1, sizeof(struct vzctl_disk));
	if (d == NULL)
		goto err;

	memcpy(d->uuid, param->uuid, sizeof(d->uuid));
	d->enabled = param->enabled;
	d->size = param->size;
	d->use_device = param->use_device;

	if (param->path != NULL) {
		if (param->path[0] == '\0')
			path[0] = '\0';
		else
			get_abs_path(h->env_param->fs->ve_private, param->path, path, sizeof(path));
	} else {
		if (h->env_param->fs->ve_private)
			snprintf(path, sizeof(path), "%s/disk-%s.hdd",
					h->env_param->fs->ve_private, param->uuid);
		else
			snprintf(path, sizeof(path), "disk-%s.hdd",
					param->uuid);
	}

	if (xstrdup(&d->path, path))
		goto err;

	if (param->mnt && xstrdup(&d->mnt, param->mnt))
		goto err;

	if (param->mnt_opts && xstrdup(&d->mnt_opts, param->mnt_opts))
		goto err;

	if (param->storage_url && xstrdup(&d->storage_url, param->storage_url))
		goto err;

	if (param->enc_keyid != NULL && xstrdup(&d->enc_keyid, param->enc_keyid))
		goto err;

	return d;

err:
	vzctl_err(-1, ENOMEM, "disk_param2disk");
	if (d)
		free_disk(d);
	return NULL;
}

struct vzctl_disk *find_disk(struct vzctl_env_disk *env_disk, const char *uuid)
{
	struct vzctl_disk *disk;

	list_for_each(disk, &env_disk->disks, list) {
		if (!strcmp(disk->uuid, uuid))
			return disk;
	}

	return NULL;
}

static int check_new_disk(struct vzctl_env_disk *env_disk,
		struct vzctl_disk_param *param)
{
	struct vzctl_disk *disk;

	list_for_each(disk, &env_disk->disks, list) {
		if (param->path && disk->path && !strcmp(disk->path, param->path))
			return vzctl_err(-1, 0, "Failed to add ploop image:"
					" the image %s already registerd",
					param->path);
		if (param->mnt && disk->mnt && !strcmp(disk->mnt, param->mnt))
			return vzctl_err(-1, 0, "Failed to add ploop image:"
					" the image with mnt=%s already registerd",
					param->mnt);
		if (param->uuid[0] != '\0' && !strcmp(disk->uuid, param->uuid))
			return vzctl_err(-1, 0, "Failed to add ploop image:"
					" the image with uuid=%s already used",
					param->uuid);
	}

	return 0;
}

static int load_disk_info(struct vzctl_env_param *env)
{
	struct vzctl_disk *disk;
	struct ploop_disk_images_data *di = NULL;
	int ret = 0;
	char path[PATH_MAX];

	if (env->fs->layout < VZCTL_LAYOUT_5)
		return 0;

	list_for_each(disk, &env->disk->disks, list) {
		if (disk->use_device)
			continue;

		get_abs_path(env->fs->ve_private, disk->path, path, sizeof(path));
		if ((ret = open_dd(path, &di)) ||	(ret = read_dd(di))) {
			if (!is_permanent_disk(disk))
				break;

			if (di != NULL) {
				ploop_close_dd(di);
				di = NULL;
			}
			continue;
		}

		if (di->enc != NULL && di->enc->keyid != NULL) {
			ret = xstrdup(&disk->enc_keyid, di->enc->keyid);
			if (ret)
				break;
		}

		ploop_close_dd(di);
		di = NULL;
	}

	if (di)
		ploop_close_dd(di);

	return ret;
}

int set_disk_param(struct vzctl_env_param *env, int flags)
{
	int ret;
	char path[PATH_MAX];
	struct vzctl_disk *disk, *root = NULL;

	if (env->fs->ve_private == NULL)
		return 0;

	if (env->fs->layout < VZCTL_LAYOUT_5) {
		snprintf(path, sizeof(path), "%s%s",
				env->fs->ve_private,
				env->fs->layout == VZCTL_LAYOUT_4 ? VZCTL_VE_FS_DIR : "");
		ret = xstrdup(&env->fs->ve_private_fs, path);
		if (ret)
			return ret;
	} else if (env->disk->root != VZCTL_PARAM_OFF &&
			find_root_disk(env->disk) == NULL)
	{
		/* build default root disk: VE_PRIVATE/root.hdd */
		root = calloc(1, sizeof(struct vzctl_disk));
		if (root == NULL)
			return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "set_disk_param");

		strncpy(root->uuid, DISK_ROOT_UUID, sizeof(root->uuid));
		root->enabled = VZCTL_PARAM_ON;

		if (env->dq->diskspace != NULL)
			root->size = env->dq->diskspace->l;

		ret = xstrdup(&root->path, VZCTL_VE_ROOTHDD_DIR);
		if (ret)
			goto err;

		ret = xstrdup(&root->mnt, "/");
		if (ret)
			goto err;

		ret = xstrdup(&root->mnt_opts, env->fs->mount_opts);
		if (ret)
			goto err;

		if (env->fs->noatime == VZCTL_PARAM_ON)
			root->mnt_flags = MS_NOATIME;

		/* add to the head */
		list_add(&root->list, &env->disk->disks);
	}

	root = find_root_disk(env->disk);
	if (root != NULL)
		root->user_quota = get_user_quota_mode(env->dq);

	if (flags & VZCTL_CONF_LOAD_DISK_INFO) {
		ret = load_disk_info(env);
		if (ret)
			return ret;
	}

	if (!(flags & VZCTL_CONF_USE_RELATIVE_PATH)) {
		list_for_each(disk, &env->disk->disks, list) {
			if (disk->use_device || disk->path[0] == '\0')
				continue;
			get_abs_path(env->fs->ve_private, disk->path, path, sizeof(path));
			ret = xstrdup(&disk->path, path);
			if (ret)
				return ret;
		}
	}
	return 0;

err:
	if (root != NULL)
		free_disk(root);
	return ret;
}

/*
DISK="enabled=yes,size=102400,path=/tmp/$VEID/hdd.73a0af3e-5cfb-4276-a594-9358d01a49f7.mnt=home;enabled=yes,size=102400,path=hdd.7e567842-3068-47f8-8d7b-824b84e1ad2d"
*/
static int parse_disk_str(const char *str, struct vzctl_disk *disk)
{
	int ret;
	const char *p, *next, *ep;
	int len;
	char tmp[PATH_MAX];

#define GET_PARAM_VAL(p, name) \
{ \
	p += sizeof(name)-1; \
	len = next - p; \
	if (len == 0) \
		continue; \
	if (len >= sizeof(tmp)) \
		return VZCTL_E_INVAL; \
	strncpy(tmp, p, len); \
	tmp[len] = 0; \
}

	next = p = str;
	ep = p + strlen(str);
	do {
		while (*next != '\0' && *next != ',') next++;
		if (!strncmp("uuid=", p, 5)) {
			GET_PARAM_VAL(p, "uuid=")
			if (vzctl2_get_normalized_guid(tmp, disk->uuid, sizeof(disk->uuid))) {
				logger(-1, 0, "Incorrect uuid=%s", tmp);
				return VZCTL_E_INVAL;
			}
		} else if (!strncmp("enabled=", p, 8)) {
			GET_PARAM_VAL(p, "enabled=")
			disk->enabled = yesno2id(tmp);
			if (disk->enabled == -1) {
				logger(-1, 0, "Incorrect enabled=%s", tmp);
				return VZCTL_E_INVAL;
			}
		} else if (!strncmp("size=", p, 5)) {
			GET_PARAM_VAL(p, "size=")
			if (parse_ul(tmp, &disk->size)) {
				logger(-1, 0, "Incorrect size=%s", tmp);
				return VZCTL_E_INVAL;
			}
		} else if (!strncmp("image=", p, 6)) {
			p += sizeof("image=")-1;
			len = next - p;
			if (len >= sizeof(tmp))
				return VZCTL_E_INVAL;
			strncpy(tmp, p, len);
			tmp[len] = '\0';
			ret = xstrdup(&disk->path, tmp);
			if (ret)
				return ret;
			disk->use_device = 0;
		} else if (!strncmp("device=", p, 7)) {
			GET_PARAM_VAL(p, "device=")
				ret = xstrdup(&disk->path, tmp);
			if (ret)
				return ret;
			disk->use_device = 1;
		} else if (!strncmp("mnt=", p, 4)) {
			GET_PARAM_VAL(p, "mnt=")
			ret = xstrdup(&disk->mnt, tmp);
			if (ret)
				return ret;
		} else if (!strncmp("mnt_opts=", p, 9)) {
			GET_PARAM_VAL(p, "mnt_opts=")
			ret = xstrdup(&disk->mnt_opts, tmp);
			if (ret)
				return ret;
		} else if (!strncmp("autocompact=", p, 12)) {
			GET_PARAM_VAL(p, "autocompact=")
			disk->autocompact = yesno2id(tmp);
			if (disk->autocompact == -1)
				logger(-1, 0, "Incorrect autocompact=%s", tmp);
		} else if (!strncmp("storage_url=", p, 12)) {
			GET_PARAM_VAL(p, "storage_url=")
			ret = xstrdup(&disk->storage_url, tmp);
			if (ret)
				return ret;
		} else {
			GET_PARAM_VAL(p, "")
			logger(-1, 0, "skip unknown parameter %s", tmp);
		}
	} while ((p = ++next) < ep);
#undef GET_PARAM_VAL

	if (disk->path == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0,
				"The path parameter is not specified");

	if (disk->uuid[0] == '\0')
		return vzctl_err(VZCTL_E_INVAL, 0, "The uuid parameter is not specified");

	return 0;
}

int parse_disk(struct vzctl_env_disk *env_disk, const char *str)
{
	int ret;
	char *token, *saveptr;
	char *tmp;

	if (*str == '\0')
		return 0;

	tmp = strdup(str);
	if (tmp == NULL)
		return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "parse_disk");

	token = strtok_r(tmp, ";", &saveptr);
	if (token == NULL) {
		free(tmp);
		return 0;
	}

	do {
		struct vzctl_disk *disk;

		disk = calloc(1, sizeof(struct vzctl_disk));
		if (disk == NULL) {
			ret = vzctl_err(VZCTL_E_NOMEM, ENOMEM, "parse_disk");
			break;
		}
		ret = parse_disk_str(token, disk);
		if (ret) {
			char *p;

			if ((p = strchr(token, ';')) != NULL)
				*p = 0;
			logger(-1, 0, "Incorrect DISK parameter (%s)",
					token);
			free_disk(disk);
			break;
		}
		add_disk(env_disk, disk);
	} while ((token = strtok_r(NULL, ";", &saveptr)) != NULL);

	free(tmp);

	return ret;
}

char *disk2str(struct vzctl_env_handle *h, struct vzctl_env_disk *env_disk)
{
	char buf[4096];
	char path[PATH_MAX];
	struct vzctl_disk *it;
	char *sp, *ep;

	if (list_empty(&env_disk->disks))
		return NULL;

	buf[0] = '\0';
	sp = buf;
	ep = sp + sizeof(buf) -1;

	list_for_each(it, &env_disk->disks, list) {
		if (strcmp(it->uuid, DISK_ROOT_UUID) == 0 && !it->updated)
			continue;

		assert(it->uuid[0]);
		sp += snprintf(sp, ep - sp, "uuid=%s,", it->uuid);
		if (sp >= ep)
			break;

		sp += snprintf(sp, ep - sp, "size=%lu,", it->size);
		if (sp >= ep)
			break;

		if (it->enabled > 0) {
			sp += snprintf(sp, ep - sp, "enabled=%s,",
					id2yesno(it->enabled));
			if (sp >= ep)
				break;
		}

		if (it->mnt != NULL) {
			sp += snprintf(sp, ep - sp, "mnt=%s,",
					it->mnt);
			if (sp >= ep)
				break;
		}

		if (it->mnt_opts != NULL) {
			sp += snprintf(sp, ep - sp, "mnt_opts=%s,",
					it->mnt_opts);
			if (sp >= ep)
				break;
		}

		if (it->autocompact > 0) {
			sp += snprintf(sp, ep - sp, "autocompact=%s,",
					id2yesno(it->autocompact));
			if (sp >= ep)
				break;
		}

		if (it->storage_url != NULL) {
			sp += snprintf(sp, ep - sp, "storage_url=%s,",
					it->storage_url);
			if (sp >= ep)
				break;
		}

		if (it->use_device)
			sp += snprintf(sp, ep - sp, "device=%s;", it->path);
		else
			sp += snprintf(sp, ep - sp, "image=%s;",
					get_rel_path(h->env_param->fs->ve_private,
							it->path, path, sizeof(path)));
		if (sp >= ep)
			break;
	}
	if (*(sp - 1) == ';')
		*(sp - 1) = 0;
	return strdup(buf);
}

static int get_real_device(const char *device, char *out, int size)
{
	char x[PATH_MAX];

	if (realpath(device, x) == NULL)
		return vzctl_err(-1, errno, "Failed to get realpath %s", device);

	snprintf(out, size, "%s", x);

	return 0;
}

const char *get_fs_partname(struct vzctl_disk *disk)
{
	return disk->partname;
}

dev_t get_fs_partdev(struct vzctl_disk *disk)
{
	return disk->part_dev;
}

static int get_part_device(const char *device, char *out, int size)
{
	int i;
	char x[PATH_MAX];
	char *sfx[] = {"p1", "1"};
	const char *devname = get_devname(device);

	for (i = 0; i < sizeof(sfx) / sizeof(sfx[0]); i++) {
		snprintf(x, sizeof(x), "/sys/block/%s/%s%s",
				devname, devname, sfx[i]);
		if (access(x, F_OK) == 0) {
			snprintf(out, size, "/dev/%s%s", devname, sfx[i]);
			return 0;
		}
	}

	return vzctl_err(VZCTL_E_SYSTEM, 0, "Cannot detect partition for %s", device);
}

static int get_disk_mount_param(struct vzctl_env_handle *h, struct vzctl_disk *d,
		struct vzctl_mount_param *param, int flags,
		char *mnt_opts, int mnt_opts_size)
{
	int ret;

	if (is_root_disk(d)) {
		char *target = h->env_param->fs->ve_root;
		if (target == NULL)
			return vzctl_err(VZCTL_E_INVAL, 0,
					"Unable to mount root image: VE_ROOT is not set");

		ret = vzctl_get_mount_opts(d, mnt_opts, mnt_opts_size);
		if (ret)
			return ret;

		/* root disk mounted from VE */
		param->target = target;
		param->mount_data = mnt_opts;
	} else
		param->mount_data = d->mnt_opts;

	param->flags = d->mnt_flags;
	param->fsck = fsck_flags2mode(flags);

	return 0;
}

int mount_disk_device(struct vzctl_env_handle *h, struct vzctl_disk *d, int flags)
{
	int ret;
	struct stat st;
	char device[PATH_MAX];
	char part[PATH_MAX];
	char buf[PATH_MAX];
	struct vzctl_mount_param param = {};

	ret = get_disk_mount_param(h, d, &param, flags, buf, sizeof(buf));
	if (ret)
		return ret;

	if (stat(d->path, &st))
		return vzctl_err(VZCTL_E_SYSTEM, errno, "Can not stats %s",
				d->path);

	if (!S_ISBLK(st.st_mode))
		return vzctl_err(VZCTL_E_INVAL, 0,
				"Unable to mount root image: %s is not block device",
				d->path);

	ret = get_real_device(d->path, device, sizeof(device));
	if (ret)
		return ret;

	ret = get_part_device(device, part, sizeof(part));
	if (ret)
		return ret;

	unlink(part);
	if (mknod(part, st.st_mode, st.st_rdev + 1) && errno != EEXIST)
		return vzctl_err(VZCTL_E_SYSTEM, errno, "mknod %s", part);

	if (param.target != NULL) {
		if (access(param.target, F_OK)) {
			ret = make_dir(param.target, 1);
			if (ret)
				return ret;
		}

		logger(0, 0, "Mount root disk device %s %s", part, param.target);
		if (mount(part, param.target, d->fstype, 0, NULL))
			return vzctl_err(VZCTL_E_SYSTEM, errno,
					"Failed to mount device %s", part);
	}

	return 0;
}

int mount_disk_image(struct vzctl_env_handle *h, struct vzctl_disk *d, int flags)
{
	int ret;
	char buf[PATH_MAX];
	struct vzctl_mount_param param = {};

	if (!is_permanent_disk(d))
		param.ro = 1;

	ret = get_disk_mount_param(h, d, &param, flags, buf, sizeof(buf));
	if (ret)
		return ret;

	if (param.target != NULL) {
		ret = make_dir(param.target, 1);
		if (ret)
			return ret;
	}

	switch(get_disk_type(d)) {
	case DISK_PLOOP: 
		return mount_ploop_image(h, d, &param);
	default:
		return VZCTL_E_INVAL;
	}
}

int update_disk_info(struct vzctl_env_handle *h, struct vzctl_disk *disk)
{
	char devname[STR_SIZE];
	char partname[STR_SIZE];
	int ret;
	struct stat st;
	struct ploop_mnt_info info = {};

	switch (get_disk_type(disk)) {
	case DISK_DEVICE:
		if (get_real_device(disk->path, devname, sizeof(devname)))
			return VZCTL_E_SYSTEM;

		if (stat(devname, &st))
			return vzctl_err(VZCTL_E_SYSTEM, errno, "stat %s", devname);
		if (gnu_dev_major(st.st_rdev) == 253) {
			disk->dev = st.st_rdev;
			disk->part_dev = st.st_rdev;
			free(disk->devname);
			disk->devname = strdup(devname);
			free(disk->partname);
			disk->partname = strdup(devname);
			
			return 0;
		}

		if (get_part_device(devname, partname, sizeof(partname)))
			return VZCTL_E_FS_NOT_MOUNTED;
		break;
	case DISK_PLOOP:
	default:
		ret = vzctl2_get_ploop_dev2(disk->path, devname, sizeof(devname),
					partname, sizeof(partname));
		if (ret == -1)
			return VZCTL_E_DISK_CONFIGURE;
		else if (ret)
			return VZCTL_E_FS_NOT_MOUNTED;
		break;
	}

	if (stat(devname, &st))
		return vzctl_err(VZCTL_E_SYSTEM, errno, "stat %s", devname);
	disk->dev = st.st_rdev;
	free(disk->devname);
	disk->devname = realpath(devname, NULL);

	if (stat(partname, &st))
		return vzctl_err(VZCTL_E_SYSTEM, errno, "stat %s", partname);
	disk->part_dev = st.st_rdev;
	xstrdup(&disk->partname, partname);

	info.quota = get_ploop_quota_type(disk->user_quota);
	if (ploop_get_mnt_info(disk->partname, &info))
		return vzctl_err(VZCTL_E_SYSTEM, 0, "Cannot get ploop %s mount info: %s",
				disk->partname, ploop_get_last_error());
	disk->opts = info.opts;
	snprintf(disk->fstype, sizeof(disk->fstype), "%s", info.fstype);
	snprintf(disk->fsuuid, sizeof(disk->fsuuid), "%s", info.uuid);

	logger(5, 0, "Disk info dev=%s part=%s fs=%s",
				disk->devname, disk->partname, disk->fstype);
	return 0;
}

static int mount_disk(struct vzctl_env_handle *h, struct vzctl_disk *disk,
                int flags)
{
        if (!disk->use_device)
                return mount_disk_image(h, disk, flags);
        else if (is_root_disk(disk))
                return mount_disk_device(h, disk, flags);

        return 0;
}

static int umount_disk(struct vzctl_env_handle *h, struct vzctl_disk *disk)
{
	switch (get_disk_type(disk)) {
	case DISK_DEVICE:
		if (is_root_disk(disk))
			return umount_disk_device(disk);
		break;
	case DISK_PLOOP:
	default:
		return vzctl2_umount_disk_image(disk->path);
	}

	return 0;
}

int vzctl2_mount_disk(struct vzctl_env_handle *h,
		const struct vzctl_env_disk *env_disk, int flags)
{
	int ret;
	struct vzctl_disk *disk, *e;

	/* disks */
	list_for_each(disk, &env_disk->disks, list) {
		if (disk->enabled == VZCTL_PARAM_OFF)
			continue;

		ret = mount_disk(h, disk, flags);
		if (ret) {
			if (is_permanent_disk(disk))
				goto err;
			disk->enabled = VZCTL_PARAM_OFF;
			continue;
		}

		if (is_root_disk(disk)) {
			const char *target = h->env_param->fs->ve_root;
			if (mount("none", target, NULL, MS_SHARED, NULL)) {
				ret = vzctl_err(VZCTL_E_MOUNT_IMAGE, errno,
						"Failed to make shared %s", target);
				goto err;
			}
		}
		ret = update_disk_info(h, disk);
		if (ret)
			goto err;
	}

	return 0;

err:
	for (e = list_entry(disk->list.prev, typeof(*e), list);
			&e->list != (list_elem_t*)(&env_disk->disks);
			e = list_entry(e->list.prev, typeof(*e), list))
	{
		umount_disk(h, e);
	}

	return ret;
}

int get_mnt_by_dev(const char *device, char *out, int size)
{
	FILE *fp;
	int ret = 1;
	int n;
	char buf[PATH_MAX];
	char target[4097];
	unsigned _major, _minor, minor, major, u;
	struct stat st;

	if (stat(device, &st))
		return vzctl_err(-1, errno, "Can't stat %s", device);

	major = gnu_dev_major(st.st_rdev);
	minor = gnu_dev_minor(st.st_rdev);

	fp = fopen("/proc/self/mountinfo", "r");
	if (fp == NULL)
		return vzctl_err(-1, errno, "Can't open /proc/self/mountinfo");

	while (fgets(buf, sizeof(buf), fp)) {
		n = sscanf(buf, "%u %u %u:%u %*s %4096s", &u, &u, &_major, &_minor, target);
		if (n != 5)
			continue;
		if (major == _major && (_minor == minor || _minor == minor + 1)) {
			strncpy(out, target, size - 1);
			out[size - 1] = '\0';
			ret = 0;
			break;
		}
	}
	fclose(fp);

	return ret;
}

int umount_disk_device(struct vzctl_disk *d)
{
	char device[PATH_MAX];
	char target[PATH_MAX];
	int ret;

	ret = get_real_device(d->path, device, sizeof(device));
	if (ret)
		return ret;

	ret = get_mnt_by_dev(device, target, sizeof(target));
	if (ret == -1)
		return vzctl_err(VZCTL_E_UMOUNT_IMAGE, 0,
				"Unable to get mount point by %s: %s",
				device, ploop_get_last_error());
	if (ret == 0) {
		logger(0, 0, "Unmount device=%s mnt=%s", device, target);
		if (umount(target))
			return vzctl_err(VZCTL_E_UMOUNT_IMAGE, errno,
					"Failed to unmount %s", target);
	}

	return 0;
}

int vzctl2_umount_disk(struct vzctl_env_handle *h,
		const struct vzctl_env_disk *env_disk)
{
	int ret;
	struct vzctl_disk *disk;

	assert(env_disk);

	list_for_each_prev(disk, &env_disk->disks, list) {
		ret = umount_disk(h, disk);
		if (ret && ret != SYSEXIT_DEV_NOT_MOUNTED &&
				is_permanent_disk(disk))
			return ret;
	}
	return 0;
}

int configure_mount_opts(struct vzctl_env_handle *h, struct vzctl_disk *disk)
{
	int ret;
	char buf[4096];
	char mnt_opts[4096];
	dev_t dev = get_fs_partdev(disk);
	char *sp = buf, *ep = buf + sizeof(buf);

	ret = get_mount_opts(disk, mnt_opts, sizeof(mnt_opts));
	if (ret)
		return ret;
	/* FIXME: add balloon_ino calculation */
	sp += snprintf(sp, ep - sp, "0 %u:%u;",
			gnu_dev_major(dev), gnu_dev_minor(dev));
	if (mnt_opts[0] != '\0') {
		sp += snprintf(sp, ep - sp, "1 %s", mnt_opts);
		if (!disk->use_device)
			sp += snprintf(sp, ep - sp, ",balloon_ino=%llu", disk->balloon_ino);
	}

	logger(0, 0, "Setting mount options for image=%s opts=%s",
			disk->path, buf);
	return cg_set_param(EID(h), CG_VE, "ve.mount_opts", buf);
}

int configure_disk_perm(struct vzctl_env_handle *h, struct vzctl_disk *disk,
		int del, int flags)
{
	int ret;
	struct vzctl_dev_perm devperms = {
		.mask = S_IROTH | (is_root_disk(disk) ? 0 : S_IXUSR),
		.type = S_IFBLK | VE_USE_MINOR,
	};

	logger(0, 0, "Setting permissions for image=%s", disk->path);
	if (del)
		devperms.mask = 0;

	devperms.dev = disk->dev;
	ret = get_env_ops()->env_set_devperm(h, &devperms, flags);
	if (ret)
		return ret;

	devperms.dev = disk->part_dev;
	ret = get_env_ops()->env_set_devperm(h, &devperms, flags);
	if (ret)
		return ret;

	return 0;
}

int is_dm_device(dev_t dev)
{
	char x[PATH_MAX];

	snprintf(x, sizeof(x), "/sys/dev/block/%d:%d/dm",
			major(dev), minor(dev));
	if (access(x, F_OK) == 0)
		return 1;
	return 0;
}

static int configure_sysfsperm(struct vzctl_env_handle *h, struct vzctl_disk *d,
		int del)
{
	char buf[PATH_MAX + 15];
	char sys_dev[PATH_MAX];
	char sys_part[STR_SIZE];
	int ret;

	ret = get_sysfs_device_path("block", d->devname, sys_dev,
			sizeof(sys_dev));
	if (ret)
		return ret;
	ret = xstrdup(&d->sys_devname, get_devname(sys_dev));
	if (ret)
		return ret;
	ret = get_sysfs_device_path("block", d->partname, sys_part,
			sizeof(sys_dev));
	if (ret)
		return ret;
	ret = xstrdup(&d->sys_partname, get_devname(sys_part));
	if (ret)
		return ret;

	if (del) {
		snprintf(buf, sizeof(buf), "%s -", sys_dev);
		if (cg_set_param(EID(h), CG_VE, "ve.sysfs_permissions", buf))
			return VZCTL_E_DISK_CONFIGURE;

		snprintf(buf, sizeof(buf), "%s -", sys_part);
		if (cg_set_param(EID(h), CG_VE, "ve.sysfs_permissions", buf))
			return VZCTL_E_DISK_CONFIGURE;

		return 0;
	}

	if (cg_set_param(EID(h), CG_VE, "ve.sysfs_permissions", "block rx"))
		return VZCTL_E_DISK_CONFIGURE;

	if (add_sysfs_dir(h, sys_dev, NULL, "rx"))
		return VZCTL_E_DISK_CONFIGURE;

	ret = add_sysfs_entry(h, sys_dev);
	if (ret)
		return ret;

	ret = add_sysfs_entry(h, sys_part);
	if (ret)
		return ret;

	if (is_dm_device(d->dev)) {
		snprintf(buf, sizeof(buf), "%s/dm", sys_dev);
		ret = add_sysfs_entry(h, buf);
		if (ret)
			return ret;
	}

	if (is_dm_device(d->part_dev)) {
		char part[64];
		if (get_part_device(d->devname, part, sizeof(part)) == 0) {
			ret = get_sysfs_device_path("block", part, sys_dev,
					sizeof(sys_dev));
			if (ret)
				return ret;
			ret = add_sysfs_entry(h, sys_dev);
			if (ret)
				return ret;
		}

		snprintf(sys_dev, sizeof(sys_dev), "%s/dm", sys_part);
		ret = add_sysfs_entry(h, sys_dev);
		if (ret)
			return ret;
		snprintf(sys_dev, sizeof(sys_dev), "%s/slaves", sys_part);
		ret = add_sysfs_entry(h, sys_dev);
		if (ret)
			return ret;
	}

	return 0;
}

static int do_setup_disk(struct vzctl_env_handle *h, struct vzctl_disk *disk,
		int flags, int automount)
{
	int ret;
	int root = is_root_disk(disk);
	int skip_configure = (flags & VZCTL_SKIP_CONFIGURE);

	if (disk->dev == 0) {
		ret = update_disk_info(h, disk);
		if (ret)
			return ret;
	}

	if (!root) {
		ret = configure_mount_opts(h, disk);
		if (ret)
			return ret;
	}

	ret = configure_disk_perm(h, disk, 0, flags);
	if (ret)
		return ret;

	ret = configure_sysfsperm(h, disk, 0);
	if (ret)
		return ret;

	if (!skip_configure) {
		ret = configure_disk(h, disk, flags, automount);
		if (ret)
			return ret;
	}

	return 0;
}

static int enable_disk(struct vzctl_env_handle *h, struct vzctl_disk *d)
{
	int ret;

	if (!d->use_device) {
		if (vzctl2_is_image_mounted(d->path))
			return 0;

		ret = mount_disk_image(h, d, 0);
		if (ret)
			return ret;
	}

	ret = do_setup_disk(h, d, 0, 1);
	if (ret == 0 && !is_ub_supported())
		ret = apply_io_param(h, h->env_param, 0);
	if (ret && !d->use_device)
		vzctl2_umount_disk_image(d->path);

	return ret;
}

static void get_dd_path(const struct vzctl_disk *disk, char *buf, size_t size)
{
	snprintf(buf, size, "%s/" DISKDESCRIPTOR_XML, disk->path);
}

static int create_image(struct vzctl_env_handle *h,
		struct vzctl_disk *param, int flags)
{
	int ret;
	struct vzctl_create_image_param create_param = {
		.size = param->size,
		.enc_keyid = param->enc_keyid,
	};

	if (make_dir(param->path, 1))
		return VZCTL_E_SYSTEM; 

	ret = vzctl_create_image(h, param->path, &create_param);
	if (ret)
		unlink(param->path);

	return ret;
}

static int register_ploop_image(struct vzctl_disk *disk,
		struct vzctl_disk_param *param,	int flags)
{
	int rc;
	char fname[PATH_MAX];
	struct ploop_info info = {};
	struct ploop_disk_images_data *di;

	get_dd_path(disk, fname, sizeof(fname));
	rc = stat_file(fname);
	if (rc == -1)
		return VZCTL_E_SYSTEM;
	else if (rc == 0)
		return vzctl_err(VZCTL_E_INVAL, 0,
			"Failed to register ploop image: no such file %s", fname);
	logger(0, 0, "The ploop image %s already exists: %s",
			param->path, flags & VZCTL_DISK_RECREATE ?
			"recreate" : "register");
	if (open_dd(disk->path, &di))
		return VZCTL_E_SYSTEM;

	if (ploop_read_dd(di)) {
		ploop_close_dd(di);
		return VZCTL_E_SYSTEM;
	}

	if (flags & VZCTL_DISK_RECREATE) {
		struct ploop_create_param p = {};

		if (param->enc_keyid)
			p.keyid = param->enc_keyid;
		else if (di->enc)
			p.keyid = strdupa(di->enc->keyid);

		if (ploop_init_image(di, &p)) {
			ploop_close_dd(di);
			return vzctl_err(VZCTL_E_SYSTEM, 0,
				"Failed to recreate image: %s",
				ploop_get_last_error());
		}
	}

	if (ploop_get_info_by_descr(fname, &info))
		disk->size = (unsigned long)di->size >> 1; /* sectors -> 1K */
	else
		disk->size = info.fs_blocks * info.fs_bsize / 1024;

	ploop_close_dd(di);

	return 0;
}

static void update_DISKSPACE(struct vzctl_env_handle *h, unsigned long size)
{
	char s[64];

	snprintf(s, sizeof(s), "%lu:%lu", size, size);
	vzctl2_env_set_param(h, "DISKSPACE", s);
}

int vzctl2_add_disk(struct vzctl_env_handle *h, struct vzctl_disk_param *param,
		int flags)
{
	int ret, rc;
	struct vzctl_disk *d;
	int created = 0;
	char fname[PATH_MAX];
	struct vzctl_env_disk *env_disk = h->env_param->disk;

	ret = VZCTL_E_ADD_IMAGE;
	if (param->uuid[0] == '\0' && ploop_uuid_generate(param->uuid, sizeof(param->uuid)))
		return vzctl_err(ret, 0, "ploop_uuid_generate");

	if (param->path == NULL && param->storage_url == NULL)
		return vzctl_err(ret, 0, "Image is not specified");

	if (check_new_disk(env_disk, param))
		return VZCTL_E_ADD_IMAGE;

	d = disk_param2disk(h, param);
	if (d == NULL)
		return VZCTL_E_NOMEM;

	if (d->use_device || d->storage_url)
		goto skip_create;

	if (d->path[0] == '\0')
		goto out;

	get_rel_path(h->env_param->fs->ve_private, d->path, fname, sizeof(fname));
	if (is_external_disk(fname) && is_pcs(h->env_param->fs->ve_private) &&
			(h->env_param->disk->root != VZCTL_PARAM_OFF) && shaman_is_configured()) {
		logger(-1, 0, "External disks cannot be added to Containers in a"
				" High Availability cluster");
		goto err;
	}

	rc = stat_file(d->path);
	if (rc == -1) {
		goto err;
	} else if (rc == 1) {
		ret = register_ploop_image(d, param, flags);
		if (ret)
			goto err;
	} else {
		if (flags & VZCTL_DISK_SKIP_CREATE)
			goto out;

		if (param->size == 0) {
			logger(-1, 0, "The --size option have to be specified");
			goto err;
		}

		ret = create_image(h, d, flags);
		if (ret)
			goto err;

		created = 1;
	}

skip_create:
	if (!(flags & VZCTL_DISK_SKIP_CONFIGURE) &&
			is_env_run(h) == 1 && d->enabled != VZCTL_PARAM_OFF) {
		ret = enable_disk(h, d);
		if (ret)
			goto err;
	}

out:
	/* add disk to list */
	add_disk(env_disk, d);

	if (is_root_disk(d)) {
		update_DISKSPACE(h, d->size);
		env_disk->root = VZCTL_PARAM_ON;
	}

	logger(0, 0, "The %s %s uuid=%s has been successfully added.",
			d->use_device ? "device" : "image",
			d->path, param->uuid);

	return 0;
err:
	if (created)
		destroydir(d->path);

	if (d)
		free_disk(d);

	return ret;
}

static void split_external_path(const char *path, char *dir, int dsz, char *name, int nsz)
{
	char buf[PATH_MAX];

	snprintf(buf, sizeof(buf), "%s", path);
	snprintf(dir, dsz, "%s", dirname(buf));

	snprintf(buf, sizeof(buf), "%s", dir);
	snprintf(name, nsz, "%s", basename(buf));
}

static void remove_empty_bundle(struct vzctl_env_handle *h, const char *path)
{
	char name[PATH_MAX], dir[PATH_MAX];

	split_external_path(path, dir, sizeof(dir), name, sizeof(name));

	if (strcmp(name, EID(h)) != 0)
		return;

	if (rmdir(dir)) {
		if (errno != ENOTEMPTY)
			logger(0, errno, "The external bundle %s was not deleted", dir);
	} else {
		logger(3, 0, "The external bundle %s has been successfully deleted", dir);
	}
}

static int env_umount(void *data)
{
	char mnt[PATH_MAX];

	if (get_mnt_by_dev((const char *)data, mnt, sizeof(mnt)) == 0) {
		if (umount(mnt))
			return vzctl_err(-1, errno, "Failed to umount %s", mnt);
	}
	return 0;
}

static int del_disk(struct vzctl_env_handle *h, struct vzctl_disk *d)
{
	int ret;

	ret = update_disk_info(h, d);
	if (ret == VZCTL_E_FS_NOT_MOUNTED)
		return 0;
	else if (ret)
		return ret;

	if (is_env_run(h)) {
		if (vzctl_env_exec_fn(h, env_umount, (void *)get_fs_partname(d), 0))
			vzctl_err(-1, 0, "Failed to unmount %s",
					get_fs_partname(d));

		ret = configure_disk_perm(h, d, 1, 0);
		if (ret)
			return ret;

		ret = configure_sysfsperm(h, d, 1);
		if (ret)
			return ret;
	}

	ret = umount_disk(h, d);
	if (ret)
		return ret;

	return 0;
}

int vzctl2_del_disk(struct vzctl_env_handle *h, const char *guid, int flags)
{
	int ret;
	struct vzctl_disk *d;
	struct vzctl_env_disk *env_disk = h->env_param->disk;

	d = find_disk(env_disk, guid);
	if (d == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0, "Unable to delete the disk with uuid %s: no such disk",
				guid);

	assert(d->path);
	// FIXME: deny to destroy if used in snapshot

	ret = stat_file(d->path);
	if (ret == -1)
		return VZCTL_E_SYSTEM;
	else if (ret == 1) {
		if (!(flags & VZCTL_DISK_SKIP_CONFIGURE)) {
			ret = del_disk(h, d);
			if (ret)
				return ret;
		}

		if (!d->use_device && !(flags & VZCTL_DISK_DETACH)) {
			if (destroydir(d->path))
				return vzctl_err(VZCTL_E_DEL_IMAGE, 0,
						"Failed to destroy the image %s", d->path);

			remove_empty_bundle(h, d->path);

			logger(0, 0, "The ploop %s %s has been successfully deleted",
					d->use_device ? "device" : "image",
					d->path);
		} else
			logger(0, 0, "The ploop %s %s has been successfully detached",
					d->use_device ? "device" : "image",
					d->path);
	} else {
		logger(0, 0, "The ploop %s %s has been successfully unregistered",
				d->use_device ? "device" : "image",
				d->path);
	}

	if (is_root_disk(d))
		env_disk->root = VZCTL_PARAM_OFF;

	/* remove disk from the list */
	list_del(&d->list);
	free_disk(d);

	return 0;
}

unsigned long get_disk_size(unsigned long size)
{
	/* treat size > 9223372036854775807 as unlimited = 16Tbytes */
	return size >= LONG_MAX ? PLOOP_MAX_FS_SIZE >> 10 : size;
}

int set_max_diskspace(struct vzctl_2UL_res **diskspace)
{
	if (*diskspace != NULL)
		return 0;
	if ((*diskspace = (struct vzctl_2UL_res *)malloc(sizeof(struct vzctl_2UL_res))) == NULL)
		return VZCTL_E_NOMEM;
	(*diskspace)->b = LONG_MAX;
	(*diskspace)->l = LONG_MAX;
	return 0;
}

int vzctl2_resize_disk(struct vzctl_env_handle *h, const char *guid,
		unsigned long size, int offline)
{
	int ret, root;
	struct vzctl_disk *d;
	pid_t pid = 0;

	d = find_disk(h->env_param->disk, guid);
	if (d == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0,
				"Unable to configure the disk with uuid %s: no such disk",
				guid);
	root = is_root_disk(d);
	if (!root && is_env_run(h)) {
		ret = cg_env_get_init_pid(EID(h), &pid);
		if (ret)
			return ret;
	}

	size = get_disk_size(size);
	ret = resize_disk_image(d->path, size, offline, pid);
	if (ret)
		return ret;

	if (root)
		update_DISKSPACE(h, size);

	d->size = size;

	return 0;
}

int vzctl2_set_disk(struct vzctl_env_handle *h, struct vzctl_disk_param *param)
{
	int ret;
	struct vzctl_disk *d;

	d = find_disk(h->env_param->disk, param->uuid);
	if (d == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0,
				"Unable to configure the disk with uuid %s: no such disk",
				param->uuid);
	
	d->updated = 1;
	if (param->size) {
		ret = vzctl2_resize_disk(h, param->uuid, param->size,
				param->offline_resize);
		if (ret)
			return ret;
	}

	if (param->mnt != NULL) {
		if (is_root_disk(d) && !is_root_mnt(param->mnt))
			h->env_param->disk->root = VZCTL_PARAM_OFF;
	 	else if (!is_root_disk(d) && is_root_mnt(param->mnt))
			h->env_param->disk->root = VZCTL_PARAM_ON;

		ret = xstrdup(&d->mnt, param->mnt);
		if (ret)
			return ret;
	}

	if (param->enabled) {
		if (is_env_run(h) == 1 && param->enabled != VZCTL_PARAM_OFF) {
			ret = enable_disk(h, d);
			if (ret)
				return ret;
		}
		d->enabled = param->enabled;
	}

	if (param->autocompact)
		d->autocompact = param->autocompact;

	if (param->path) {
		logger(0, 0, "Update image path %s -> %s",
				d->path, param->path);
		ret = xstrdup(&d->path, param->path);
		if (ret)
			return ret;
		d->use_device = param->use_device;
	}

	if (param->storage_url != NULL) {
		ret = xstrdup(&d->storage_url, param->storage_url);
		if (ret)
			return ret;
	}

	return 0;
}

int vzctl_setup_disk(struct vzctl_env_handle *h, struct vzctl_env_disk *env_disk, int flags)
{
	int ret;
	struct vzctl_disk *disk;
	int configured = 0;

	if (env_disk == NULL || list_empty(&env_disk->disks))
		return 0;

	list_for_each(disk, &env_disk->disks, list) {
		if (disk->enabled == VZCTL_PARAM_OFF)
			continue;

		int automount = (is_dm_device(disk->part_dev) && !is_root_disk(disk)) ? 1 : 0;

		ret = do_setup_disk(h, disk, flags, automount);
		if (ret && is_permanent_disk(disk))
			return ret;

		configured = 1;
	}

	if (!(flags & VZCTL_RESTORE) && configured)
		fin_configure_disk(h, env_disk);

	return 0;
}

int is_external_disk(const char *path)
{
	return path[0] == '/';
}

int check_external_disk(const char *basedir, struct vzctl_env_disk *env_disk)
{
	char fname[PATH_MAX], path[PATH_MAX];
	struct vzctl_disk *d;

	if (env_disk == NULL)
		return 0;

	list_for_each(d, &env_disk->disks, list) {
		if (d->use_device)
			continue;

		if (realpath(d->path, path) == NULL) {
			vzctl2_log(VZCTL_E_SYSTEM, errno,
				"Failed to get realpath for disk %s", d->path);
			continue;
		}

		get_rel_path(basedir, path, fname, sizeof(fname));
		if (is_external_disk(fname))
			return 1;
	}

	return 0;
}

static int get_disk_iostat(const char *device, struct vzctl_iostat *stat)
{
	FILE *f;
	char fname[STR_SIZE];

	if (memcmp(device, "/dev/", 5) == 0)
		device += 5;
	snprintf(fname, sizeof(fname), "/sys/block/%s/stat", device);
	f = fopen(fname, "rt");
	if (f == NULL) {
		if (errno == ENOENT)
			return 0;
		return vzctl_err(VZCTL_E_SYSTEM, errno, "Cant open %s", fname);
	}
	/*
	   /sys/block/ploop/stat fields: 
	   1 - reads completed successfully
	   2 - reads merged
	   3 - sectors read
	   4 - time spent reading (ms)
	   5 - writes completed
	   6 - writes merged
	   7 - sectors written
	   8 - time spent writing (ms)
	   9 - I/Os currently in progress
	   10 - time spent doing I/Os (ms)
	   11 - weighted time spent doing I/Os (ms)
	   */
	if (fscanf(f, "%llu %*s %llu  %*s %llu %*s %llu",
				&stat->read_reqs, &stat->read, &stat->write_reqs, &stat->write) == 2) {
		stat->read *= 512;
		stat->write *= 512;
	}

	fclose(f);

	return 0;
}

int vzctl2_get_disk_stats(const char *path, struct vzctl_disk_stats *stats,
		int size)
{
	int ret;
	char buf[PATH_MAX];
	struct ploop_fs_info i;
	struct vzctl_disk_stats st = {};

	snprintf(buf, sizeof(buf), "%s/" DISKDESCRIPTOR_XML, path);
	ret = ploop_get_fs_info(buf, &i, sizeof(i));
	if (ret == 0) {
		st.total = i.fs.fs_bsize * i.fs.fs_blocks / 1024;
		st.free = i.fs.fs_bsize * i.fs.fs_bfree / 1024;
		st.inodes = i.fs.fs_inodes;
		st.ifree = i.fs.fs_ifree;
		snprintf(st.part, sizeof(st.part), "%s", i.part);
	} else if (ret != SYSEXIT_FSTAT)
		return VZCTL_E_SYSTEM;

	if (i.dev[0] != '\0') {
		snprintf(st.device, sizeof(st.device), "%s", i.dev);
		ret = get_disk_iostat(st.device, &st.io);
		if (ret)
			return ret;
	}

	memcpy(stats, &st, size < sizeof(st) ? size : sizeof(st));

	return 0;
}

int vzctl2_env_get_disk_stats(struct vzctl_env_handle *h, const char *uuid,
	struct vzctl_disk_stats *stats, int size)
{
	struct vzctl_disk *d;

	if (h->env_param->fs->layout < VZCTL_LAYOUT_5)
		return VZCTL_E_INVAL;

	d = find_disk(h->env_param->disk, uuid);
	if (d == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0, "Unable to get disk "
			"statistics: disk %s is not found", uuid);

	if (d->use_device || !is_permanent_disk(d))
		return VZCTL_E_NOTSUPP;

	return vzctl2_get_disk_stats(d->path, stats, size);
}

int vzctl2_env_encrypt_disk(struct vzctl_env_handle *h, const char *uuid,
		const char *keyid, int flags)
{

	struct vzctl_disk *d;

	d = find_disk(h->env_param->disk, uuid);
	if (d == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0,
			"Unable to encrypt the disk with uuid %s: no such disk",
			uuid);

	return vzctl_encrypt_disk_image(d->path, keyid, flags);
}

int vzctl2_get_disk_usage(const char *path, unsigned long long *out)
{
	int ret, i;
	struct stat st;
	struct ploop_disk_images_data *di;

	ret = open_dd(path, &di);
	if (ret)
		return ret;
	ret = read_dd(di);
	if (ret)
		goto err;
	*out = 0;
	for (i = 0; i < di->nimages; i++) {
		if (stat(di->images[i]->file, &st) == 0)
			*out += st.st_size;
	}

err:
	ploop_close_dd(di);
	return ret;
}

int vzctl2_get_criu_arg(struct vzctl_env_handle *h, int op, char *out, int size)
{
	switch(op) {
	case VZCTL_GET_PLOOP_ARGS_EXTERNAL:
		return make_ploop_dev_args_no_envvar(h, out, size);
	default:
		return vzctl_err(VZCTL_E_UNKNOWN_PARM, 0, "Unknown vzctl2_get_ploop_args opcode %d", op);
	}
}
