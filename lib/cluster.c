/*
 *  Copyright (c) 1999-2015 Parallels IP Holdings GmbH
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
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <mntent.h>
#include <errno.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include "vzctl.h"
#include "list.h"
#include "logger.h"
#include "util.h"
#include "config.h"
#include "vztypes.h"
#include "cluster.h"
#include "lock.h"

static int is_shared_fs_type(const char *fs)
{
	if (!strcmp(fs, "nfs") ||
			!strcmp(fs, "gfs") ||
			!strcmp(fs, "gfs2") ||
			!strcmp(fs, "fuse.pstorage"))
		return 1;
	return 0;
}

static int is_in_exclude_list(const char *mnt)
{

	if (strstr(mnt, "/.snapshot") != NULL)
		return 1;
	return 0;
}

static int read_shared_fs(list_head_t *head)
{
	FILE *fp;
	struct mntent *mnt;
	int ret = 0;

	if ((fp = setmntent("/proc/mounts", "r")) == NULL) {
		logger(-1, errno, "Unable to open /proc/mounts");
		return -1;
	}
	while ((mnt = getmntent(fp)) != NULL) {
		if (is_in_exclude_list(mnt->mnt_dir))
			continue;
		if (is_shared_fs_type(mnt->mnt_type)) {
			if (add_str_param(head, mnt->mnt_dir) == NULL) {
				logger(-1, ENOMEM, "%s", __func__);
				free_str(head);
				ret = -1;
				break;
			}
		}
	}
	endmntent(fp);
	return ret;
}

char **vzctl2_get_storage(void)
{
	const struct vzctl_config *gconf;
	list_head_t head, *phead;
	char **mnts = NULL;
	const char *prvt = NULL;

	if ((gconf = vzctl_global_conf()) == NULL)
		return NULL;

	phead = &head;
	list_head_init(phead);
	if (read_shared_fs(phead) == 0) {
		if (list_empty(phead)) {
			vzctl2_conf_get_param(gconf, "VE_PRIVATE", &prvt);
			/* If shared fs is not found use VE_PRIVATE for storage */
			mnts = malloc(2 * sizeof(char *));
			mnts[0] = get_mnt_root(prvt);
			mnts[1] = NULL;
		} else {
			mnts = list2ar_str(phead);
		}
	}
	free_str(phead);
	return mnts;
}

#ifndef GFS2_MAGIC
#define GFS2_MAGIC              0x01161970
#endif

#ifndef NFS_SUPER_MAGIC
#define NFS_SUPER_MAGIC         0x6969
#endif

/* Kernel sources, fs/fuse/inode.c */
#ifndef FUSE_SUPER_MAGIC
#define FUSE_SUPER_MAGIC        0x65735546
#endif

#ifndef EXT4_SUPER_MAGIC
#define EXT4_SUPER_MAGIC        0xEF53
#endif


static int check_fs_type(const char *path, long magic)
{
	struct statfs st;

	if (statfs(path, &st) != 0)
		return vzctl_err(-1, errno, "statfs '%s'", path);
	if (st.f_type == magic)
		return 1;
	return 0;
}

int is_gfs(const char *path)
{
	return check_fs_type(path, GFS2_MAGIC);
}

int is_nfs(const char *path)
{
	return check_fs_type(path, NFS_SUPER_MAGIC);
}

int is_pcs(const char *path)
{
	return check_fs_type(path, FUSE_SUPER_MAGIC);
}

int is_shared_fs(const char *path)
{
	struct statfs st;

	if (statfs(path, &st)) {
		logger(-1, errno, "statfs '%s'", path);
		return -1;
	}
	return (st.f_type == GFS2_MAGIC ||
			st.f_type == NFS_SUPER_MAGIC ||
			st.f_type == FUSE_SUPER_MAGIC);
}
