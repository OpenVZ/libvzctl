/*
 * Copyright (c) 2015 Parallels IP Holdings GmbH
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
 * Our contact details: Parallels IP Holdings GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

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
#include <linux/vzcalluser.h>
#include <sys/mount.h>
#include <libgen.h>
#include <dirent.h>

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


static int mount_disk_image(struct vzctl_env_handle *h, struct vzctl_disk *d, int flags);
static int umount_disk_image(struct vzctl_disk *d);
static int mount_disk_device(struct vzctl_env_handle *h, struct vzctl_disk *d, int flags);
static int umount_disk_device(struct vzctl_disk *d);

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

static void add_disk(struct vzctl_env_disk *env_disk, struct vzctl_disk *disk)
{
	list_add_tail(&disk->list, &env_disk->disks);
}

static int is_root_disk(struct vzctl_disk *disk)
{
	return (disk->mnt != NULL && strcmp(disk->mnt, "/") == 0);
}

struct vzctl_disk *find_root_disk(const struct vzctl_env_disk *env_disk)
{
	struct vzctl_disk *disk;

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
		if (strncmp(fname, basedir, n) == 0)
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

static struct vzctl_disk *disk_param2disk(struct vzctl_env_handle *h,
		struct vzctl_disk_param *param)
{
	struct vzctl_disk *d;
	char path[PATH_MAX];

	d = calloc(1, sizeof(struct vzctl_disk));
	if (d == NULL)
		return NULL;

	memcpy(d->uuid, param->uuid, sizeof(d->uuid));
	d->enabled = param->enabled;
	d->size = param->size;
	d->use_device = param->use_device;

	if (param->path != NULL) {
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

	if (param->storage_url && xstrdup(&d->storage_url, param->storage_url))
		goto err;

	return d;

err:
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

static int get_user_quota_mode(const struct vzctl_dq_param *dq)
{
	/* by default the journaled quota is used */
	return !is_2quota_enabled(dq) ? 0 :
		(dq->journaled_quota == VZCTL_PARAM_OFF ?
			 VZCTL_QUOTA_MODE : VZCTL_JQUOTA_MODE);
}

const char *get_root_disk(struct vzctl_env_handle *h)
{
	struct vzctl_disk *d;

	if (h->env_param->disk) {
		d = find_root_disk(h->env_param->disk);
		if (d)
			return d->path;
	}

	return NULL;
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

		return ret;
	}

	if (env->disk->root != VZCTL_PARAM_OFF && find_root_disk(env->disk) == NULL) {
		/* build default root disk: VE_PRIVATE/root.hdd */
		root = calloc(1, sizeof(struct vzctl_disk));
		if (root == NULL) {
			ret = vzctl_err(VZCTL_E_NOMEM, ENOMEM, "set_disk_param");
			goto err;
		}

		strncpy(root->uuid, DISK_ROOT_UUID, sizeof(root->uuid));
		root->enabled = VZCTL_PARAM_ON;

		if (env->dq->diskspace != NULL)
			root->size = env->dq->diskspace->b;

		ret = xstrdup(&root->path,
				(flags & VZCTL_CONF_USE_RELATIVE_PATH) ? VZCTL_VE_ROOTHDD_DIR :
					 get_root_disk_path(env->fs->ve_private, path, sizeof(path)));
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

		root->mount = mount_disk_image;
		root->umount = umount_disk_image;
			
		/* add to the head */
		list_add(&root->list, &env->disk->disks);
	}

	root = find_root_disk(env->disk);
	if (root != NULL)
		root->user_quota = get_user_quota_mode(env->dq);

	if (!(flags & VZCTL_CONF_USE_RELATIVE_PATH)) {
		list_for_each(disk, &env->disk->disks, list) {
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
			GET_PARAM_VAL(p, "image=")
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

	if (!disk->use_device)  {
		disk->mount = mount_disk_image;
		disk->umount = umount_disk_image;
	} else if (is_root_disk(disk)) {
		disk->mount = mount_disk_device;
		disk->umount =umount_disk_device;
	}

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

static int get_device_name(const char *device, char *out, int size)
{
	char device_r[PATH_MAX];

	if (realpath(device, device_r) == NULL)
		return vzctl_err(-1, errno, "Failed to get realpath %s",
				device);

	snprintf(out, size, "%s1", device_r);

	return 0;
}

static int get_disk_mount_param(struct vzctl_env_handle *h, struct vzctl_disk *d,
		struct vzctl_mount_param *param, int flags,
		char *mnt_opts, int mnt_opts_size)
{
	int ret;

	bzero(param, sizeof(struct vzctl_mount_param));
	if (is_root_disk(d)) {
		char *target = h->env_param->fs->ve_root;
		if (target == NULL)
			return vzctl_err(VZCTL_E_INVAL, 0,
					"Unable to mount root image: VE_ROOT is not set");

		ret = vzctl2_get_mount_opts(d->mnt_opts, d->user_quota,
				mnt_opts, mnt_opts_size);
		if (ret)
			return ret;

		/* root disk mounted from VE */
		param->target = target;
		param->mount_data = mnt_opts;
	} else
		param->mount_data = d->mnt_opts;

	param->flags = d->mnt_flags;
	param->fsck = (flags & VZCTL_SKIP_FSCK) ? VZCTL_PARAM_OFF : 0;

	return 0;
}

int mount_disk_device(struct vzctl_env_handle *h, struct vzctl_disk *d, int flags)
{
	int ret;
	struct stat st;
	char fname[PATH_MAX];
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

	if (access(param.target, F_OK)) {
		ret = make_dir(param.target, 1);
		if (ret)
			return ret;
	}

	ret = get_device_name(d->path, fname, sizeof(fname));
	if (ret)
		return ret;

	unlink(fname);
	if (mknod(fname, st.st_mode, st.st_rdev + 1) && errno != EEXIST)
		return vzctl_err(VZCTL_E_SYSTEM, errno, "mknod %s", fname);

	logger(0, 0, "Mount root disk %s %s", fname, param.target);
	if (mount(fname, param.target, "ext4", 0, NULL))
		return vzctl_err(VZCTL_E_SYSTEM, errno,
				"Failed to mount device %s", fname);
	return 0;
}

int mount_disk_image(struct vzctl_env_handle *h, struct vzctl_disk *d, int flags)
{
	int ret;
	char buf[PATH_MAX];
	struct vzctl_mount_param param = {};

	ret = get_disk_mount_param(h, d, &param, flags, buf, sizeof(buf));
	if (ret)
		return ret;

	return vzctl2_mount_disk_image(d->path, &param);
}

int vzctl2_mount_disk(struct vzctl_env_handle *h,
		const struct vzctl_env_disk *env_disk, int flags)
{
	int ret;
	struct vzctl_disk *disk;

	/* disks */
	list_for_each(disk, &env_disk->disks, list) {
		if (disk->enabled == VZCTL_PARAM_OFF || disk->mount == NULL)
			continue;

		ret = disk->mount(h, disk, flags);
		if (ret && is_permanent_disk(disk))
			goto err;

		if (is_root_disk(disk)) {
			const char *target = h->env_param->fs->ve_root;
			if (mount("none", target, NULL, MS_SHARED, NULL)) {
				ret = vzctl_err(VZCTL_E_MOUNT_IMAGE, errno,
						"Failed to make shared %s", target);
				goto err;
			}
		}
	}

	return 0;

err:
	vzctl2_umount_disk(env_disk);

	return ret;
}

static int get_mnt_by_dev(const char *device, char *out, int size)
{
	FILE *fp;
	int ret = 1;
	int n;
	char buf[PATH_MAX];
	char target[4097];
	unsigned _major, _minor, minor, major, u;
	struct stat st;

	if (stat(device, &st))
		return vzctl_err(-1, errno, "Faile dto stat %s", device);

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
	char device_r[PATH_MAX];
	char target[PATH_MAX];
	int ret;

	ret = get_device_name(d->path, device_r, sizeof(device_r));
	if (ret)
		return ret;

	ret = get_mnt_by_dev(device_r, target, sizeof(target));
	if (ret == -1)
		return vzctl_err(VZCTL_E_UMOUNT_IMAGE, 0,
				"Unable to get mount point by %s: %s",
				device_r, ploop_get_last_error());
	if (ret == 0) {
		logger(0, 0, "Unmount device=%s mnt=%s", device_r, target);
		if (umount(target))
			return vzctl_err(VZCTL_E_UMOUNT_IMAGE, errno,
					"Failed to unmount %s", target);
	}

	return 0;
}


int umount_disk_image(struct vzctl_disk *d)
{
	return vzctl2_umount_disk_image(d->path);
}

int vzctl2_umount_disk(const struct vzctl_env_disk *env_disk)
{
	int ret;
	struct vzctl_disk *disk;

	assert(env_disk);

	list_for_each_prev(disk, &env_disk->disks, list) {
		if (disk->umount == NULL)
			continue;

		ret = disk->umount(disk);
		if (ret && ret != SYSEXIT_DEV_NOT_MOUNTED &&
				is_permanent_disk(disk))
			return ret;
	}
	return 0;
}

static int configure_mount_opts(struct vzctl_env_handle *h, struct vzctl_disk *disk,
		 dev_t dev)
{
	int ret;
	char buf[4096];
	char mnt_opts[4096];

	ret = vzctl2_get_mount_opts(disk->mnt_opts, disk->user_quota,
			mnt_opts, sizeof(mnt_opts));
	if (ret)
		return ret;

	/* FIXME: add balloon_ino calculation */
	snprintf(buf, sizeof(buf), "0 %u:%u;1 balloon_ino=12,%s",
			gnu_dev_major(dev), gnu_dev_minor(dev),	mnt_opts);
	logger(0, 0, "Setting mount options for image=%s opts=%s",
			disk->path, buf + 2);
	return cg_set_param(EID(h), CG_VE, "ve.mount_opts", buf);
}

static int configure_devperm(struct vzctl_env_handle *h, struct vzctl_disk *disk,
		dev_t dev, int del)
{
	struct vzctl_dev_perm devperms = {
		.dev = dev,
		.mask = S_IROTH | S_IXUSR,
		.type = S_IFBLK | VE_USE_MINOR,
	};

	if (del)
		devperms.mask = 0;

	logger(0, 0, "Setting permissions for image=%s", disk->path);
	return get_env_ops()->env_set_devperm(h, &devperms);
}

static int add_sysfs_entry(struct vzctl_env_handle *h, const char *sysfs)
{
	char path[PATH_MAX];
	struct dirent **namelist;
	struct stat st;
	int n;
	int ret = 0;

	snprintf(path, sizeof(path), "%s rx", sysfs);
	if (cg_set_param(EID(h), CG_VE, "ve.sysfs_permissions", path))
		return VZCTL_E_DISK_CONFIGURE;

	snprintf(path, sizeof(path), "/sys/%s", sysfs);
	if (lstat(path, &st))
		return vzctl_err(VZCTL_E_SYSTEM, errno, "Cant stat %s", path);

	if (!S_ISDIR(st.st_mode))
		return 0;

	n = scandir(path, &namelist, NULL, NULL);
	if (n < 0)
		return vzctl_err(VZCTL_E_SYSTEM, errno, "Unabel to open %s",
				path);

	while (n--) {
		if (strcmp(namelist[n]->d_name, ".") == 0 ||
				strcmp(namelist[n]->d_name, "..") == 0)
			continue;

		snprintf(path, sizeof(path), "%s/%s %s",
			sysfs, namelist[n]->d_name,
			!strcmp(namelist[n]->d_name, "uevent") ? "rw" : "rx");
		if (cg_set_param(EID(h), CG_VE, "ve.sysfs_permissions", path))
			ret = VZCTL_E_DISK_CONFIGURE;

		free(namelist[n]);
	}
	free(namelist);

	return ret;
}

static int configure_sysfsperm(struct vzctl_env_handle *h, const char *devname,
		int del)
{
	char buf[STR_SIZE];
	int ret;
	const char *dev = get_devname(devname);

	if (del) {
		snprintf(buf, sizeof(buf), "devices/virtual/block/%s -", dev);
		if (cg_set_param(EID(h), CG_VE, "ve.sysfs_permissions", buf))
			return VZCTL_E_DISK_CONFIGURE;

		snprintf(buf, sizeof(buf), "devices/virtual/block/%s/%sp1 -",
				dev, dev);
		if (cg_set_param(EID(h), CG_VE, "ve.sysfs_permissions", buf))
			return VZCTL_E_DISK_CONFIGURE;

		return 0;
	}

	if (cg_set_param(EID(h), CG_VE, "ve.sysfs_permissions", "block rx"))
		return VZCTL_E_DISK_CONFIGURE;

	if (cg_set_param(EID(h), CG_VE, "ve.sysfs_permissions",
				"devices/virtual/block rx"))
		return VZCTL_E_DISK_CONFIGURE;

	snprintf(buf, sizeof(buf), "devices/virtual/block/%s rx", dev);
	if (cg_set_param(EID(h), CG_VE, "ve.sysfs_permissions", buf))
		return VZCTL_E_DISK_CONFIGURE;

	snprintf(buf, sizeof(buf), "devices/virtual/block/%s", dev);
	ret = add_sysfs_entry(h, buf);
	if (ret)
		return ret;

	snprintf(buf, sizeof(buf), "devices/virtual/block/%s/%sp1", dev, dev);
	ret = add_sysfs_entry(h, buf);
	if (ret)
		return ret;

	return 0;
}

static int do_setup_disk(struct vzctl_env_handle *h, struct vzctl_disk *disk,
		int flags, int automount)
{
	int ret;
	struct stat st;
	char devname[STR_SIZE];
	dev_t dev;

	if (disk->use_device) {
		snprintf(devname, sizeof(devname), "%s", disk->path);
	} else {
		ret = vzctl2_get_ploop_dev(disk->path, devname, sizeof(devname));
		if (ret == -1)
			return VZCTL_E_DISK_CONFIGURE;
		else if (ret)
			return 0;
	}

	if (stat(devname, &st))
		return vzctl_err(VZCTL_E_DISK_CONFIGURE, errno, "Unable to stat %s",
				devname);

	dev = st.st_rdev;

	if (!disk->use_device) {
		char part[STR_SIZE];
		/* Give access to the first partition 'ploopNp1' */
		dev += 1;
		get_partition_dev_name(dev, part, sizeof(part));
		ret = get_fs_uuid(part, disk->fsuuid);
		if (ret)
			return ret;
	}

	ret = configure_mount_opts(h, disk, dev);
	if (ret)
		return ret;

	ret = configure_devperm(h, disk, dev, 0);
	if (ret)
		return ret;

	ret = configure_sysfsperm(h, devname, 0);
	if (ret)
		return ret;

	if (!(flags & VZCTL_SKIP_CONFIGURE)) {
		ret = configure_disk(h, disk, dev, flags, automount);
		if (ret)
			return ret;
	}

	return 0;
}

static int enable_disk(struct vzctl_env_handle *h, struct vzctl_disk *d)
{
	struct vzctl_mount_param mount_param = {};
	int ret;

	if (!d->use_device) {
		if (vzctl2_is_image_mounted(d->path))
			return 0;

		ret = vzctl2_mount_disk_image(d->path, &mount_param);
		if (ret)
			return ret;
	}

	ret = do_setup_disk(h, d, 0, 1);
	if (ret && !d->use_device)
		vzctl2_umount_disk_image(d->path);

	return ret;
}

static void get_dd_path(const struct vzctl_disk *disk, char *buf, size_t size)
{
	snprintf(buf, size, "%s/" DISKDESCRIPTOR_XML, disk->path);
}

int vzctl2_add_disk(struct vzctl_env_handle *h, struct vzctl_disk_param *param,
		int flags)
{
	int ret, rc;
	struct vzctl_create_image_param create_param = {};
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

	if (d->use_device)
		goto skip_create;

	get_rel_path(h->env_param->fs->ve_private, d->path, fname, sizeof(fname));
	if (is_external_disk(fname) && is_pcs(h->env_param->fs->ve_private) &&
			shaman_is_configured()) {
		logger(-1, 0, "External disks cannot be added to Containers in a"
				" High Availability cluster");
		goto err;
	}

	rc = stat_file(d->path);
	if (rc == -1) {
		goto err;
	} else if (rc == 1) {
		/* disk registration */
		char fname[PATH_MAX];
		struct ploop_disk_images_data *di;

		get_dd_path(d, fname, sizeof(fname));
		rc = stat_file(fname);
		if (rc == -1) {
			goto err;
		} else if (rc == 0) {
			logger(-1, 0, "Failed to register ploop image:"
					" no such file %s", fname);

			goto err;
		}
		logger(0, 0, "The ploop image %s already exists",
				d->path);
		if (read_dd(d->path, &di))
			goto err;
		d->size = (unsigned long)di->size >> 1; /* sectors -> 1K */
		ploop_close_dd(di);
	} else {
		if (flags & VZCTL_DISK_SKIP_CREATE)
			goto out;

		if (param->size == 0) {
			logger(-1, 0, "The --size option have to be specified");
			goto err;
		}
		/* disk creation */
		if (make_dir(d->path, 1))
			goto err;

		create_param.size = param->size;
		ret = vzctl2_create_disk_image(d->path, &create_param);
		if (ret) {
			unlink(d->path);
			goto err;
		}
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

	if (is_root_disk(d))
		env_disk->root = VZCTL_PARAM_ON;

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
	return umount((const char *)data);
}

static int del_disk(struct vzctl_env_handle *h, struct vzctl_disk *d)
{
	char dev[STR_SIZE];
	struct stat st;
	int ret;

	if (d->use_device) {
		snprintf(dev, sizeof(dev), "%s", d->path);
	} else {
		ret = vzctl2_get_ploop_dev(d->path, dev, sizeof(dev));
		if (ret == -1)
			return vzctl_err(VZCTL_E_DEL_IMAGE, 0,
				"Unable to get ploop image %s mounted state",
				d->path);
		else if (ret == 1)
			return 0;
	}

	if (stat(dev, &st))
		return vzctl_err(VZCTL_E_SYSTEM, errno,	"Unable to stat %s",
				dev);

	if (is_env_run(h) && d->mnt != NULL)
		vzctl2_env_exec_fn2(h, env_umount, d->mnt, 0, 0);

	if (d->umount != NULL) {
		ret = d->umount(d);
		if (ret)
			return ret;
	}

	if (is_env_run(h)) {
		ret = configure_devperm(h, d, st.st_rdev + 1, 1);
		if (ret)
			return ret;

		ret = configure_sysfsperm(h, dev, 1);
		if (ret)
			return ret;
	}

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

int vzctl2_resize_disk(struct vzctl_env_handle *h, const char *guid,
		unsigned long size, int offline)
{
	int ret;
	struct vzctl_disk *d;

	d = find_disk(h->env_param->disk, guid);
	if (d == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0,
				"Unable to configure the disk with uuid %s: no such disk",
				guid);

	ret = vzctl2_resize_disk_image(d->path, size, offline);
	if (ret)
		return ret;

	if (is_root_disk(d)) {
		char s[64];

		snprintf(s, sizeof(s), "%lu:%lu", size, size);
		vzctl2_env_set_param(h, "DISKSPACE", s);
	}

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

	if (param->size) {
		ret = vzctl2_resize_disk(h, param->uuid, param->size,
				param->offline_resize);
		if (ret)
			return ret;
	}

	if (param->mnt != NULL) {
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
                if (disk->enabled == VZCTL_PARAM_OFF ||
				is_root_disk(disk))
                        continue;

		ret = do_setup_disk(h, disk, flags, 0);
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

int check_external_disk(struct vzctl_env_disk *env_disk)
{
	struct vzctl_disk *disk;

	if (env_disk != NULL && !list_empty(&env_disk->disks)) {
		list_for_each(disk, &env_disk->disks, list)
			if (is_external_disk(disk->path))
				return 1;
	}

	return 0;
}

static int get_ploop_disk_stats(const struct vzctl_disk *disk, struct vzctl_disk_stats *stats)
{
	int ret;
	char dev[64];
	char buf[PATH_MAX];
	struct ploop_info info;

	ret = vzctl2_get_ploop_dev(disk->path, dev, sizeof(dev));
	if (ret == 0) {
		ret = ploop_get_mnt_by_dev(dev, buf, sizeof(buf));
		if (ret == 0) {
			strncpy(stats->device, dev, sizeof(stats->device) - 1);
			stats->device[sizeof(stats->device) - 1] = '\0';
		}
	}
	if (ret != 0 && ret != 1)
		return VZCTL_E_SYSTEM;
	get_dd_path(disk, buf, sizeof(buf));
	ret = ploop_get_info_by_descr(buf, &info);
	if (ret == 0) {
		stats->total = info.fs_bsize * info.fs_blocks / 1024;
		stats->free = info.fs_bsize * info.fs_bfree / 1024;
	}
	return (ret == 0 || ret == 1) ? 0 : VZCTL_E_SYSTEM;
}

int vzctl2_env_get_disk_stats(struct vzctl_env_handle *h, const char *uuid,
	struct vzctl_disk_stats *stats, int size)
{
	int ret = 0;
	struct vzctl_disk_stats st = {};
	struct vzctl_disk *d;

	if (h->env_param->fs->layout != VZCTL_LAYOUT_5)
		return vzctl_err(VZCTL_E_INVAL, 0,
			"Unable to get disk statistics: Unsupported CT layout %d",
			h->env_param->fs->layout);
	d = find_disk(h->env_param->disk, uuid);
	if (d == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0, "Unable to get disk "
			"statistics: disk %s is not found", uuid);
	ret = get_ploop_disk_stats(d, &st);
	if (ret == 0)
		memcpy(stats, &st, size);
	return ret;
}
