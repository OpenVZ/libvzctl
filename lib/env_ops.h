/*
 * Copyright (c) 2015-2017, Parallels International GmbH
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
 */

#ifndef __ENV_OPS_H__
#define __ENV_OPS_H__

#include <libvzctl.h>
#include "list.h"
#include "vztypes.h"

struct vzctl_env_handle;
struct vzctl_env_param;
struct vzctl_dev_perm;
struct start_param;
struct exec_param;
struct vzctl_cpt_param;
struct vzctl_cpumask;
struct vzctl_nodemask;
struct vzctl_veth_dev;

enum {
	F_SETLUID = (1 << 1),
};

struct vzctl_env_ops {
	int (* open)(void);
	int (* get_feature) (void);
	int (* env_create)(struct vzctl_env_handle *h, struct start_param *param);
	int (* env_chkpnt)(struct vzctl_env_handle *h, int cmd,
			struct vzctl_cpt_param *param, int flags);
	int (* env_restore)(struct vzctl_env_handle *h, struct start_param *start_param,
			struct vzctl_cpt_param *param, int flags);
	int (* env_cpt_cmd)(struct vzctl_env_handle *h, int action, int cmd,
                struct vzctl_cpt_param *param, int flags);
	int (* env_get_cpt_state)(struct vzctl_env_handle *h, int *state);
	int (* env_stop)(struct vzctl_env_handle *h, int stop_mode);
	int (* env_apply_param)(struct vzctl_env_handle *h, struct vzctl_env_param *env, int flags);
	int (* is_env_run)(struct vzctl_env_handle *h);
	int (* env_enter)(struct vzctl_env_handle *h, int flags);
	int (* env_setluid)(struct vzctl_env_handle *h);
	int (* env_set_devperm)(struct vzctl_env_handle *h, struct vzctl_dev_perm *dev, int flags);
	int (* env_set_cpumask)(struct vzctl_env_handle *h, struct vzctl_cpumask *cpumask);
	int (* env_set_nodemask)(struct vzctl_env_handle *h, struct vzctl_nodemask *nodemask);
	int (* env_set_ioprio)(struct vzctl_env_handle *h, int prio);
	int (* env_set_iolimit)(struct vzctl_env_handle *h, unsigned int speed);
	int (* env_get_iolimit)(struct vzctl_env_handle *h, unsigned int *speed);
	int (* env_set_iopslimit)(struct vzctl_env_handle *h, unsigned int speed);
	int (* env_get_iopslimit)(struct vzctl_env_handle *h, unsigned int *speed);
	int (* env_ip_ctl)(struct vzctl_env_handle *h, int op, const char *ip, int flags);
	int (* env_get_veip)(struct vzctl_env_handle *h, list_head_t *list);
	int (* env_veth_ctl)(struct vzctl_env_handle *h, int op, struct vzctl_veth_dev *dev, int flags);
	int (* env_netdev_ctl)(struct vzctl_env_handle *h, int op, const char *dev);

	int (* env_exec)(struct vzctl_env_handle *h, struct exec_param *param,
			int flags, pid_t *pid);
	int (* env_exec_fn)(struct vzctl_env_handle *h, execFn fn, void *data,
			int *data_fd, int timeout, int flags, pid_t *pid);
	int (* env_cleanup)(struct vzctl_env_handle *h, int flags);
	int (* env_get_runtime_param)(struct vzctl_env_handle *h, int flags);
	void (* close)(void);
};

struct vzctl_env_ops *get_env_ops(void);
void init_env_ops(void);

#endif
