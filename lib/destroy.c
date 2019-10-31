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

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>

#include "libvzctl.h"

#include "logger.h"
#include "vzerror.h"
#include "util.h"
#include "lock.h"
#include "vztypes.h"
#include "config.h"
#include "name.h"
#include "net.h"
#include "util.h"
#include "env.h"
#include "disk.h"
#include "list.h"
#include "image.h"
#include "exec.h"
#include "wrap.h"

#define BACKUP		0
#define DESTR		1

const char destroy_dir_magic[] = "vzctl-rm-me.";

static int del_dir(const char *dir)
{
	int ret;
	char *argv[4];

	argv[0] = "/bin/rm";
	argv[1] = "-rf";
	argv[2] = (char *)dir;
	argv[3] = NULL;
	ret = vzctl2_wrap_exec_script(argv, NULL, 0);

	return ret;
}

#define DESTROY_DIR_MAGIC       "vzctl-rm-me."
static int maketmpdir(const char *dir, char *out, int len)
{
	char buf[PATH_MAX];

	snprintf(buf, sizeof(buf), "%s/"DESTROY_DIR_MAGIC"XXXXXXX", dir);
	if (mkdtemp(buf) == NULL) {
		logger(-1, errno, "Error in mkdtemp(%s)", buf);
		return 1;
	}
	snprintf(out, len, "%s", buf);

	return 0;
}

/* Removes all the directories under 'root'
 * those names start with 'destroy_dir_magic'
 */
static void do_destroydir(const char *root)
{
	char buf[PATH_MAX *2 +1];
	struct stat st;
	struct dirent *ep;
	DIR *dp;
	int del, ret;

	do {
		if (!(dp = opendir(root)))
			return;
		del = 0;
		while ((ep = readdir(dp))) {
			if (strncmp(ep->d_name, DESTROY_DIR_MAGIC,
						sizeof(DESTROY_DIR_MAGIC) - 1))
			{
				continue;
			}
			snprintf(buf, sizeof(buf), "%s/%s", root, ep->d_name);
			if (stat(buf, &st))
				continue;
			if (!S_ISDIR(st.st_mode))
				continue;
			snprintf(buf, sizeof(buf), "rm --one-file-system -rf %s/%s",
					root, ep->d_name);
			ret = system(buf);
			if (ret == -1 || WEXITSTATUS(ret))
				sleep(10);
			del = 1;
		}
		closedir(dp);
	} while (del);
}

int destroydir(const char *dir)
{
	int ret;
	char buf[PATH_MAX + 15];
	char tmp[PATH_MAX];
	char *tmp_dir;
	int fd_lock = -1, pid;
	struct stat st;

	if (stat(dir, &st)) {
		if (errno != ENOENT)
			return vzctl_err(-1, errno, "Unable to stat %s", dir);
		return 0;
	}

	if (S_ISREG(st.st_mode)) {
		logger(5, 0, "remove %s", dir);
		if (unlink(dir))
			return vzctl_err(-1, errno, "Unable to unlink %s", dir);
		return 0;
	}

	ret = VZCTL_E_SYSTEM;
	tmp_dir = get_fs_root(dir);
	if (tmp_dir == NULL)
		goto err;

	snprintf(tmp, sizeof(tmp), "%s/del", tmp_dir);
	free(tmp_dir);

	if (stat(tmp, &st)) {
		if (errno != ENOENT)
			return vzctl_err(-1, errno, "Unable to stat %s", tmp);
		/* try to create temporary del dir */
		if (make_dir(tmp, 1))
			goto err;
	}

	logger(5, 0, "destroy dir=%s", dir);
	snprintf(buf, sizeof(buf), "%s/rm.lck", tmp);
	fd_lock = vzctl2_lock(buf, VZCTL_LOCK_EX | VZCTL_LOCK_NB, 0);
	if (fd_lock == -1)
		goto err;

	/* move to del */
	if (maketmpdir(tmp, buf, sizeof(buf)))
		goto err;

	if (rename(dir, buf)) {
		logger(-1, errno, "Can't rename %s -> %s", dir, buf);
		goto err;
	}

	if (fd_lock == -2) /* already locked */
		return 0;

	int r, s[2] = {-1, -1};
	if (pipe(s)) {
		vzctl_err(-1, errno, "pipe");
		goto err;
	}
	ret = 0;
	if (!(pid = fork())) {
		setsid();
		close_fds(VZCTL_CLOSE_STD | VZCTL_CLOSE_NOCHECK, fd_lock, -1);
		do_destroydir(tmp);
		_exit(0);
	} else if (pid < 0)
		ret = vzctl_err(VZCTL_E_FORK, errno, "destroydir: Unable to fork");

	close(s[1]);
	if (read(s[0], &r, sizeof(r)) == -1)
		vzctl_err(-1, errno, "read");
	close(s[0]);

err:
	if (fd_lock >= 0)
		close(fd_lock);
	if (ret) {
		logger(-1, 0, "Remove the directory %s in place", dir);
		if (maketmpdir(dir, tmp, sizeof(tmp)) == 0 &&
				rename(dir, tmp) == 0)
			dir = tmp;

		if (del_dir(dir))
			return VZCTL_E_FS_DEL_PRVT;
	}

	return 0;
}

int env_destroy_prvt(const char *dir, int layout)
{
	return destroydir(dir);
}

static void destroy_conf(struct vzctl_env_handle *h)
{
	int i;
        char conf[STR_SIZE];
        char newconf[STR_SIZE + 15];
        struct stat st;
	char *actions[] = {
		VZCTL_START_PREFIX,
		VZCTL_STOP_PREFIX,
		VZCTL_PRE_MOUNT_PREFIX,
		VZCTL_MOUNT_PREFIX,
		VZCTL_UMOUNT_PREFIX,
	};

	snprintf(conf, sizeof(conf), VZ_ENV_CONF_DIR "%s.conf", EID(h));
	if (stat(conf, &st) == 0 && S_ISREG(st.st_mode)) {
		snprintf(newconf, sizeof(newconf), "%s.destroyed", conf);
		rename(conf, newconf);
	} else
		unlink(conf);

	for (i = 0; i < sizeof(actions)/sizeof(actions[0]); i++) {
		snprintf(conf, sizeof(conf), VZ_ENV_CONF_DIR "%s.%s", EID(h), actions[i]);
		snprintf(newconf, sizeof(newconf), "%s.destroyed", conf);
		rename(conf, newconf);
	}
        get_env_conf_lockfile(h, conf, sizeof(conf));
        unlink(conf);
}

static int umount_all(const char *path)
{
	int ret;
	char **s, **devs = NULL;

	if (stat_file(path) == 0)
		return 0;

	ret = vzctl2_get_ploop_devs(path, &devs);
	if (ret) /* ignore error */
		return 0;

	for (s = devs; *s != NULL; s++) {
		if (ploop_umount(*s, NULL))
			ret = vzctl_err(VZCTL_E_FS_MOUNTED, 0,
					"Failed to unmount %s", *s);
	}
	ploop_free_array(devs);

	return ret;
}

static int validate_ve_private(const char *ctid, int layout, const char *path)
{
	char buf[PATH_MAX], sctid[STR_SIZE], *ptr;

	if (layout > 0)
		return 0;

	if (realpath(path, buf) == NULL) {
		if (errno == ENOENT)
			return 0;
		return vzctl_err(-1, errno, "realpath function for path \"%s\" returned error", path);
	}

	// We can skip rindex result verifivation because realpath would return a valid path consisting at least of one "/"
	// Hence rindex will 100% succeed. If path is invalid realpath would fail itself.
	ptr = rindex(buf, '/');
	sprintf(sctid, "/%s", ctid);

	if (!strcmp(ptr, sctid))
		// Lines are equal -> ve_private ends with "/$VEID" which is considered OK
		return 0;
	else
		// Lines are different -> ve_private does not end with "/$VEID" which we cannot accept
		return 1;
}

int vzctl_env_destroy(struct vzctl_env_handle *h, int flags)
{
	int ret;
	char buf[PATH_LEN];
	const struct vzctl_fs_param *fs = h->env_param->fs;
	struct vzctl_disk *disk, *disk_safe;
	LIST_HEAD(ips);

	if (check_var(fs->ve_private, "VE_PRIVATE is not set"))
		return VZCTL_E_VE_PRIVATE_NOTSET;
	if (is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_RUN, 0, "Container is currently running."
				" Stop it before proceeding.");
	if (vzctl2_env_is_mounted(h))
		return vzctl_err(VZCTL_E_FS_MOUNTED, 0, "Container is currently mounted."
				" Unmount it before proceeding.");

	/* Check if directory looks like a valid container if we cannot determine ve_layout */
	ret = validate_ve_private(EID(h), fs->layout, fs->ve_private);
	if (ret) {
		if (ret == -1)
			/* "-1" in case realpath of ve_private fails */
			logger(-1, 0, "Container's private area (%s) is invalid.",fs->ve_private);
		else 
			/* "1" in case we couldn't confirm gparam->ve_private as a container's private area */
			logger(-1, 0, "Container's private area (%s) does not resemble a valid container directory."
					" Container removal is aborted to avoid accidential data loss.",fs->ve_private);
		return VZCTL_E_FS_DEL_PRVT;
	}

	logger(0, 0, "Destroying Container private area: %s", fs->ve_private);
	if (h->env_param->fs->layout >= VZCTL_LAYOUT_5) {
		list_for_each_safe(disk, disk_safe, &h->env_param->disk->disks, list) {
			if (disk->use_device)
				continue;
			ret = umount_all(disk->path);
			if (ret)
				return ret;
			vzctl2_del_disk(h, disk->uuid, 0);
		}
	}

	remove_names(h);

	/* cleanup venet0 ip addresses */
	run_stop_script(h);

	ret = vzctl2_env_unreg(h, 0);
	if (ret && ret != VZCTL_E_UNREGISTER)
		return ret;

	if ((ret = env_destroy_prvt(fs->ve_private,
			h->env_param->fs->layout)))
		return ret;

	destroy_conf(h);

	/* Dump file */
	vzctl2_get_dump_file(h, buf, sizeof(buf));
	destroydir(buf);
	/* VE_ROOT */
	rmdir(fs->ve_root);

	vzctl2_send_state_evt(EID(h), VZCTL_ENV_DELETED);
	logger(0, 0, "Container private area was destroyed");

	return 0;
}

int vzctl2_env_destroy(struct vzctl_env_handle *h, int flags)
{
	if (vzctl2_get_flags() & VZCTL_FLAG_DONT_USE_WRAP)
		return vzctl_env_destroy(h, flags);

	return vzctl_wrap_env_destroy(h, flags);
}
