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

#ifndef _VZCTL_HOOK_H_
#define _VZCTL_HOOK_H_

#include "list.h"

typedef list_head_t hook_ctx;

struct vzctl_config;
struct vzctl_env_param;
struct vzctl_data_param;

#define HOOK_CTX_INIT(x)   LIST_HEAD_INIT(x)

enum {
	ALLOC_PARAM_HOOK,
	DESTROY_PARAM_HOOK,
	STR2PARAM_HOOK,
	PARAM2STR_HOOK,
	APPLY_PARAM_HOOK,
};

struct vzctl_ops {
	int (* alloc_param) (struct vzctl_env_param *env, int offset);
	void (* destroy_param) (struct vzctl_env_param *env, int offset);
	int (* str2param) (struct vzctl_env_param *env, int offset,
			struct vzctl_data_param *data, int flags);
	int (* param2str) (struct vzctl_config *conf,
			struct vzctl_env_param *env, int offset);
	int (* apply_param) (struct vzctl_config *conf,
			struct vzctl_env_param *env, int offset, int flags);
#if 0
	mount
	umount
	start
	stop
	apply
#endif
};

struct vzctl_hook {
	list_elem_t list;
	unsigned int offset;
	struct vzctl_ops *ops;
	void *data;
};

hook_ctx *vzctl_get_hook_ctx(void);
struct vzctl_hook *vzctl_register_hook(struct vzctl_ops *ops, void *data, int flags);
void unregister_hook(struct vzctl_hook *h);
int vzctl_call_hook(int type, struct vzctl_config *conf, struct vzctl_env_param *env, void *data, int flags);

#endif /* _VZCTL_CLEANUP_H_ */
