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

#ifndef __QCOW_H__
#define __QCOW_H__

int mount_qcow2_image(struct vzctl_env_handle *h, struct vzctl_disk *d,
		struct vzctl_mount_param *param);
int get_qcow2_info(struct vzctl_env_handle *h, struct vzctl_disk *d, char *out,
		int len);
int umount_qcow2_image(struct vzctl_env_handle *h, struct vzctl_disk *disk);
int create_qcow_image(struct vzctl_env_handle *h, const char *fname,
		struct vzctl_create_image_param *param);
#endif


