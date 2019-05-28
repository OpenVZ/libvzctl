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

#ifndef _BINDMOUNT_H_
#define _BINDMOUNT_H_
#include "list.h"

struct vzctl_bindmount {
	list_elem_t list;
	char *src;
	char *dst;
	int op;
	int mntopt;
};

struct vzctl_bindmount_param {
	list_head_t mounts;
	int delall;
};

struct vzctl_env_handle;

struct vzctl_bindmount_param *alloc_bindmount_param(void);
void free_bindmount_param(struct vzctl_bindmount_param *mnt);
int parse_bindmount(struct vzctl_bindmount_param *mnt, const char *str, int add);
char *bindmount2str(struct vzctl_bindmount_param *old_mnt, struct vzctl_bindmount_param *mnt);
int vzctl2_bind_mount(struct vzctl_env_handle *h, struct vzctl_bindmount_param *mnt, int flags);

#endif // _BINDMOUNT_H_
