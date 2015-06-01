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

#ifndef	__FS_H__
#define __FS_H__

#include "vztypes.h"

#ifndef VZFS_SUPER_MAGIC
#define VZFS_SUPER_MAGIC	0x565a4653
#endif

/**  Data structure for file system parameter.
 */
struct vzctl_fs_param {
	char *ve_private;	/**< VE private  */
	char *ve_private_orig;	/**< original not expanded private path. */
	char *ve_private_fs;	/**< original path to VE private */
	char *ve_root;		/**< VE root path. */
	char *ve_root_orig;	/**< original not expanded root path. */
	char *tmpl;		/**< TEMPLATE path. */
	int layout;		/* VE layout version */
	int noatime;
	char *mount_opts;
};

struct vzctl_dq_param;
struct vzctl_env_handle;

/** Get VEFORMAT
 *
 * @param ve_private	VE_PRIVATE
 * @return		technologie VZ_T_VZFS3 | VZ_T_VZFS4
			0 in case unknown
 */
int vzctl_get_veformat(const char *ve_private);
int vzctl2_create_env_private(const char *ve_private, int layout);
int vzctl2_env_mount(struct vzctl_env_handle *h, int flags);
int vzctl2_env_umount(struct vzctl_env_handle *h, int flags);

struct vzctl_fs_param *alloc_fs_param(void);
void free_fs_param(struct vzctl_fs_param *fs);
const char *vz_fs_get_name(const char *mnt);

#endif /* __FS_H__ */
