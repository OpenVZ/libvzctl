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
#include <sys/mount.h>
#include <sys/vfs.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <stdio.h>

#include "fs.h"
#include "logger.h"
#include "vzerror.h"
#include "util.h"
#include "vz.h"
#include "image.h"

const char *vz_fs_get_name(const char *mnt)
{
	return "simfs";
}

int real_mount(const struct vzctl_fs_param *fs, const char *dst, int remount)
{
	char buf[STR_SIZE * 4];
	int mntopt = 0;
	const char *fstype;

	if (fs->noatime == VZCTL_PARAM_ON)
		mntopt |= MS_NOATIME;
	if (remount)
		mntopt |= MS_REMOUNT;

	fstype = vzctl2_veformat2fs(vzctl2_get_veformat(fs->ve_private));
	if (fstype == NULL)
		return vzctl_err(VZCTL_E_MOUNT, 0, "Unable to mount Container:"
			" unsupported file system");

	snprintf(buf, sizeof(buf), "%s/root", fs->ve_private_fs);

	logger(2, 0,  "Mounting root: %s %s %s", buf, dst, fstype);
	if (mount(buf, dst, fstype, mntopt, buf))
		return vzctl_err(VZCTL_E_MOUNT, errno,
				"Cannot mount: %s %s", buf, dst);

	return 0;
}

const char *vzctl2_veformat2fs(int format)
{
	return format == VZ_T_SIMFS ? "simfs" : NULL;
}

#define VZFS_VER	"VERSION"

int vzctl2_get_vzfs_ver(const char *ve_private)
{
	char buf[STR_SIZE];
	char content[8];        /* 005.00x */
	struct stat st;
	int n, ver = -1;

	snprintf(buf, sizeof(buf), "%s/" VZFS_VER, ve_private);
	if (lstat(buf, &st)) {
		if (errno != ENOENT) {
			logger(-1, errno, "Unable to find %s", buf);
			return -1;
		}
		return VZ_T_SIMFS;
	}
	if (!S_ISLNK(st.st_mode))
		return -1;
	n = readlink(buf, content, sizeof(content));
	if (n < 0 || n >= sizeof(content))
		return -1;
	content[n] = 0;
	if (!strcmp(content, "simfs"))
		return VZ_T_SIMFS;
	if (sscanf(content, "005.00%d", &ver) != 1) {
		logger(-1, errno, "Unknown vzfs version %s", content);
		return -1;
	}
	switch (ver) {
	case 4:
		return VZ_T_VZFS4;
	case 3:
		return VZ_T_VZFS3;
	case 0:
		return VZ_T_SIMFS;
	}
	return -1;
}

int vzctl2_get_veformat(const char *ve_private)
{
	int ver;
	char fs[4096];

	ver = vzctl2_env_layout_version(ve_private);
	snprintf(fs, sizeof(fs), "%s%s", ve_private,
			ver >= VZCTL_LAYOUT_4 ? VZCTL_VE_FS_DIR : "");

	return vzctl2_get_vzfs_ver(fs);
}

int vzctl2_create_env_private(const char *ve_private, int layout)
{
	char path[MAXPATHLEN];

	if (layout < VZCTL_LAYOUT_3 || layout > VZCTL_LAYOUT_5)
		return vzctl_err(-1, 0, "Unsupported layout %d", layout);

	if (stat_file(ve_private) == 0 && make_dir(ve_private, 1))
		return -1;

	if (layout == VZCTL_LAYOUT_3) {
		/* Old VZ 3.0 layout */
		return 0;
	} else if (layout == VZCTL_LAYOUT_4) {
		/* VZ 4.0 layout structure */
		snprintf(path, sizeof(path), "%s" VZCTL_VE_FS_DIR, ve_private);
		if (make_dir(path, 1))
			goto err;
		snprintf(path, sizeof(path), "%s" VZCTL_VE_DUMP_DIR, ve_private);
		if (make_dir(path, 1))
			goto err;
		snprintf(path, sizeof(path), "%s" VZCTL_VE_SCRIPTS_DIR, ve_private);
		if (make_dir(path, 1))
			goto err;
	} else if (layout == VZCTL_LAYOUT_5) {
		/* VZ 5.0 layout structure */
		snprintf(path, sizeof(path), "%s" VZCTL_VE_FS_DIR, ve_private);
		if (make_dir(path, 1))
			goto err;
		if (make_dir(get_root_disk_path(ve_private, path, sizeof(path)), 1))
			goto err;
		snprintf(path, sizeof(path), "%s" VZCTL_VE_DUMP_DIR, ve_private);
		if (make_dir(path, 1))
			goto err;
		snprintf(path, sizeof(path), "%s" VZCTL_VE_SCRIPTS_DIR, ve_private);
		if (make_dir(path, 1))
			goto err;
	}

	snprintf(path, sizeof(path), "%s/" VZCTL_VE_LAYOUT, ve_private);
	if (symlink(layout == VZCTL_LAYOUT_4 ? "4" : "5", path)) {
		logger(-1, errno, "Unable to create symlink %s", path);
		goto err;
	}
	return 0;
err:
	return  -1;
}

