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

#include "hook.h"
#include "logger.h"

static hook_ctx ops_hook_list;
static unsigned int _param_offset;


void unregister_hook(struct vzctl_hook *h)
{
	if (h != NULL) {
		list_del(&h->list);
		free(h);
	}
}

static void free_hook(hook_ctx *ctx)
{
	struct vzctl_hook *it, *tmp;

	list_for_each_safe(it, tmp, ctx, list) {
		unregister_hook(it);
	}
}

hook_ctx *vzctl_get_hook_ctx()
{
	if (ops_hook_list.next == NULL)
		list_head_init(&ops_hook_list);
	return &ops_hook_list;
}

static unsigned int get_param_offset()
{
	return _param_offset++;
}

struct vzctl_hook *register_hook(hook_ctx *ctx, struct vzctl_ops *ops,
		void *data, int tail)
{
	struct vzctl_hook *h;

	h = malloc(sizeof(struct vzctl_hook));
	if (h == NULL)
		return NULL;
	h->offset = get_param_offset();
	h->ops = ops;
	h->data = data;

	if (tail)
		list_add_tail(&h->list, ctx);
	else
		list_add(&h->list, ctx);
	return h;
}

struct vzctl_hook *vzctl_register_hook(struct vzctl_ops *ops, void *data,
		int flags)
{
	hook_ctx *ctx;

	if ((ctx = vzctl_get_hook_ctx()) == NULL)
		return NULL;
	return register_hook(ctx, ops, data, 1);
}

static int call_hook(hook_ctx *ctx, int type, struct vzctl_config *conf,
		struct vzctl_env_param *env, void *data, int flags)
{
	struct vzctl_hook *it;
	int ret = 0;

	list_for_each(it, ctx, list) {
		switch (type) {
		case ALLOC_PARAM_HOOK:
			if (it->ops->alloc_param != NULL)
				ret = it->ops->alloc_param(env, it->offset);
			break;
		case DESTROY_PARAM_HOOK:
			if (it->ops->destroy_param != NULL)
				it->ops->destroy_param(env, it->offset);
			break;
		case STR2PARAM_HOOK:
			if (it->ops->str2param != NULL)
				ret = it->ops->str2param(env, it->offset,
					(struct vzctl_data_param *) data,
					flags);
			break;
		case PARAM2STR_HOOK:
			if (it->ops->param2str != NULL)
				ret = it->ops->param2str(conf, env, it->offset);
			break;
		case APPLY_PARAM_HOOK:
			if (it->ops->apply_param != NULL)
				ret = it->ops->apply_param(conf, env, it->offset,
					flags);
			break;
		}
		/* Terminate on first error */
		if (ret)
			break;
	}
	return ret;
}

int vzctl_call_hook(int type, struct vzctl_config *conf,
		struct vzctl_env_param *env, void *data, int flags)
{
	return call_hook(vzctl_get_hook_ctx(), type, conf, env, data, flags);
}
