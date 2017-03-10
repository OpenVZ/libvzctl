/*
 *  Copyright (c) 1999-2017, Parallels International GmbH
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
 *
 */

#ifndef __ENV_CONFIGURE_H__
#define __ENV_CONFIGURE_H__

#include "list.h"

struct vzctl_misc_param *alloc_misc_param();
void free_misc_param(struct vzctl_misc_param *param);
int env_ip_configure(struct vzctl_env_handle *h, int cmd,
                list_head_t *ip, int delall, int flags);
int vzctl_env_configure(struct vzctl_env_handle *h,
	struct vzctl_env_param *env, int flags);

int env_pw_configure(struct vzctl_env_handle *h,
	const char *user, const char *pw, int flags);

int env_console_configure(struct vzctl_env_handle *h, int flags);

int apply_quota_param(struct vzctl_env_handle *h, struct vzctl_env_param *env, int flags);

#endif /* __ENV_CONFIGURE_H__ */
