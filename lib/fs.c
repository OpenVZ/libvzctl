/*
 *  Copyright (c) 1999-2017, Parallels International GmbH
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
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <string.h>
#include <stdio.h>
#include <mntent.h>

#include "vztypes.h"
#include "fs.h"
#include "vz.h"
#include "util.h"
#include "logger.h"
#include "vzerror.h"
#include "config.h"
#include "image.h"
#include "disk.h"
#include "env.h"
#include "env_ops.h"
#include "evt.h"
#include "create.h"
#include <ploop/libploop.h>

#ifndef MNT_DETACH
#define MNT_DETACH      0x00000002
#endif

static int fs_bindmount(struct vzctl_env_handle *h)
{
	struct vzctl_fs_param *fs = h->env_param->fs;

	if (check_var(fs->ve_root, "VE_ROOT is not set"))
		return VZCTL_E_NO_PARAM;
	if (check_var(fs->ve_private_fs, "VE_PRIVATE is not set"))
		return VZCTL_E_NO_PARAM;
	if (!stat_file(fs->ve_private_fs))
		return vzctl_err(VZCTL_E_NO_PARAM, 0,
				"Container private area %s does not exist",
				fs->ve_private_fs);
	/* Create VE_ROOT mount point if not exist */
	if (make_dir(fs->ve_root, 1))
		return VZCTL_E_CREATE_DIR;

	logger(1, 0, "Mounting root: %s %s", fs->ve_private_fs, fs->ve_root);
	if (mount(fs->ve_private_fs, fs->ve_root, "", MS_BIND, NULL) == -1)
		return vzctl_err(VZCTL_E_MOUNT, errno, "Failed to bindmount %s %s",
				fs->ve_private_fs, fs->ve_root);

	return 0;
}

static int do_umount(const char *mnt)
{
	int i, ret;

	for (i = 0; i < 60; i++) {
		ret = umount(mnt);
		if (ret == 0)
			return 0;
		//was unmounted before [EINVAL target is not a mount point]
		if (ret == -1 && errno == EINVAL)
			return 0;
		if (ret == -1 && errno != EBUSY)
			break;
		sleep(1);
	}
	return vzctl_err(VZCTL_E_UMOUNT, errno, "Cannot unmount '%s'", mnt);
}

/** Unmount Container.
 *
 * @param veid		Container id.
 * @param root		Container root.
 * @return		0 on success.
 */
static int fsumount(const struct vzctl_fs_param *fs)
{
	return do_umount(fs->ve_root);
}

#define DELETED_STR     " (deleted)"
static const char *get_mount_path(const char *in, char *out, int size)
{
	char *p;

	p = strstr(in, DELETED_STR);
	if (p == NULL)
		return in;

	/* strip from begin */
	if (p == in)
		return p + sizeof(DELETED_STR) -1;

	/* strip from end */
	if (strcmp(p, DELETED_STR) == 0) {
		int n = p - in + 1;
		snprintf(out, n < size ? n : size, "%s", in);
		return out;
	}

	return in;
}

static int do_umount_submounts(struct vzctl_env_handle *h)
{
	FILE *fp;
	struct mntent *mnt;
	int len;
	char path[PATH_MAX + 1];
	char buf[PATH_MAX + 1];
	char ploop[PATH_MAX + 1];
	struct vzctl_str_param *it;
	list_head_t head;
	struct stat st;
	char *root = h->env_param->fs->ve_root;

	if (realpath(root, path) == NULL) {
		logger(-1, errno, "realpath %s failed", root);
		return -1;
	}
	if ((fp = setmntent("/proc/mounts", "r")) == NULL) {
		logger(-1, errno, "Unable to open /proc/mounts");
		return -1;
	}
	list_head_init(&head);
	strcat(path, "/"); // skip base mountpoint
	len = strlen(path);
	while ((mnt = getmntent(fp)) != NULL) {
		const char *m = get_mount_path(mnt->mnt_dir, buf, sizeof(buf));

		if (strncmp(path, m, len) == 0)
			add_str_param(&head, m);
	}
	endmntent(fp);
	/* umount the last mounted first */
	list_for_each_prev(it, &head, list) {
		logger(10, 0, "umount %s", it->str);
		if (umount(it->str))
			logger(-1, errno, "Cannot umount %s",
					it->str);
	}
	free_str(&head);
	
	//store stats fs for ploop devices
	if (h->env_param->fs->layout == VZCTL_LAYOUT_5)
	{
		//generate generic ploop image path
		snprintf(ploop, sizeof(ploop), "%s/%s/root.hds", h->env_param->fs->ve_private, VZCTL_VE_ROOTHDD_DIR);
		if (access(ploop, F_OK) == 0)
		{
			ploop_store_statfs_info(root, ploop);
		}
	}

	if (umount(root) && errno == EBUSY)
		if (stat(root, &st) == 0)
			vzctl2_send_umount_evt(EID(h), st.st_dev);

	return 0;
}

static int do_env_umount(struct vzctl_env_handle *h)
{
	do_umount_submounts(h);
	if (h->env_param->fs->layout == VZCTL_LAYOUT_5)
		return vzctl2_umount_disk(h, h->env_param->disk);
	else
		return fsumount(h->env_param->fs);
}

static int do_env_mount(struct vzctl_env_handle *h, int flags)
{
	if (h->env_param->fs->layout == VZCTL_LAYOUT_5)
		return vzctl2_mount_disk(h, h->env_param->disk, flags);
	else
		return fs_bindmount(h);
}

/** Mount Container and run mount action script if exists.
 */
int vzctl2_env_mount(struct vzctl_env_handle *h, int flags)
{
	int ret;
	const struct vzctl_fs_param *fs = h->env_param->fs;

	if (check_var(fs->ve_private, "Container private area is not set"))
		return VZCTL_E_VE_PRIVATE_NOTSET;

	if (check_var(fs->ve_root, "VE_ROOT is not set"))
		return VZCTL_E_VE_ROOT_NOTSET;

	if (!(flags & VZCTL_FORCE) && vzctl2_env_is_mounted(h)) {
		logger(0, 0, "Container is already mounted");
		return 0;
	}

	/* Execute per Container & global pre mount scripts */
	if (!(flags & VZCTL_SKIP_ACTION_SCRIPT)) {
		ret = run_action_scripts(h, VZCTL_ACTION_PRE_MOUNT);
		if (ret) {
			if (ret == VZCTL_E_SKIP_ACTION)
				goto skip;
			return ret;
		}
	}

	if (h->ctx->state == VZCTL_STATE_STARTING) {
		const char *v;
		vzctl2_conf_get_param(h->conf, "REPAIR_MODE", &v);
		if (v != NULL && strcmp(v, "force") == 0) {
			char f[PATH_MAX];

			get_running_state_fname(h->env_param->fs->ve_private, f, sizeof(f));
			if (access(f, F_OK) == 0)
				flags |= VZCTL_FORCE_REPAIR;
		}
	}

	ret = do_env_mount(h, flags);
	if (ret)
		return ret;

skip:
	/* Execute per Container & global mount scripts */
	if (!(flags & VZCTL_SKIP_ACTION_SCRIPT)) {
		ret = run_action_scripts(h, VZCTL_ACTION_MOUNT);
		if (ret)
			goto err;
	}
	logger(0, 0, "Container is mounted");

	return 0;

err:
	do_env_umount(h);

	return ret;
}

/** Unmount Container and run unmount action script if exists.
 */
int vzctl2_env_umount(struct vzctl_env_handle *h, int flags)
{
	int ret;
	char fname[PATH_MAX];
	const struct vzctl_fs_param *fs = h->env_param->fs;

	if (check_var(fs->ve_root, "VE_ROOT is not set"))
		return VZCTL_E_NO_PARAM;
	if (is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_RUN, 0, "Unable to unmount"
				" running Container: stop it first");

	repair_finish(h);
	get_env_ops()->env_cleanup(h, flags);
	get_running_state_fname(fs->ve_private, fname, sizeof(fname));
	if (access(fname, F_OK) == 0)
		run_stop_script(h);

	if (!vzctl2_env_is_mounted(h)) {
		if (flags & VZCTL_FORCE)
			return 0;

		return vzctl_err(VZCTL_E_FS_NOT_MOUNTED, 0,
				"Container is not mounted");
	}

	if (!(flags & VZCTL_SKIP_ACTION_SCRIPT)) {
		ret = run_action_scripts(h, VZCTL_ACTION_UMOUNT);
		if (ret)
			return ret;
	}

	ret = do_env_umount(h);
	if (ret)
		return ret;

	if (!(flags & VZCTL_SKIP_ACTION_SCRIPT)) {
		ret = run_action_scripts(h, VZCTL_ACTION_POST_UMOUNT);
		if (ret)
			return ret;
	}

	logger(0, 0, "Container is unmounted");

	return 0;
}

struct vzctl_fs_param *alloc_fs_param(void)
{
	return calloc(1, sizeof(struct vzctl_fs_param));
}

void free_fs_param(struct vzctl_fs_param *fs)
{
	xfree(fs->ve_root);
	xfree(fs->ve_root_orig);
	xfree(fs->ve_private);
	xfree(fs->ve_private_orig);
	xfree(fs->ve_private_fs);
	xfree(fs->tmpl);
	xfree(fs->mount_opts);
	free(fs);
}



#if 0
int vzctl_env_set_fs(struct vzctl_fs_param *g_fs, struct vzctl_fs_param *fs)
{
	if (fs->noatime != VZCTL_PARAM_ON)
		return 0;
	if (check_var(g_fs->ve_root, "VE_ROOT is not set"))
		return VZ_VE_ROOT_NOTSET;
	if (check_var(g_fs->ve_private, "VE_PRIVATE is not set"))
		return VZ_VE_PRIVATE_NOTSET;
	if (!vzctl2_env_is_mounted(g_fs->ve_root)) {
		logger(-1, 0, "Container is not mounted");
		return VZ_FS_NOT_MOUNTED;
	}
	g_fs->noatime = fs->noatime;
	return vz_mount(g_fs, 1);
}
#endif
