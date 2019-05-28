/*
 * Copyright (c) 2017, Parallels International GmbH
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

#ifndef _WRAP_H_
#define _WRAP_H_

int vzctl2_unwrap_env_stop(struct vzctl_env_handle *h, int argc, char **argv);
int vzctl_wrap_env_stop(struct vzctl_env_handle *h, stop_mode_e stop_mode,
		int flags);
int vzctl2_unwrap_env_destroy(struct vzctl_env_handle *h, int argc, char **argv);
int vzctl_wrap_env_destroy(struct vzctl_env_handle *h, int flags);
int vzctl2_unwrap_env_start(struct vzctl_env_handle *h, int argc, char **argv);
int vzctl_wrap_env_start(struct vzctl_env_handle *h, int flags);
int vzctl2_unwrap_env_chkpnt(struct vzctl_env_handle *h, int argc, char **argv);
int vzctl_wrap_env_chkpnt(struct vzctl_env_handle *h, int cmd,
		struct vzctl_cpt_param *param, int flags);
int vzctl2_unwrap_env_restore(struct vzctl_env_handle *h, int argc, char **argv);
int vzctl_wrap_env_restore(struct vzctl_env_handle *h,
		struct vzctl_cpt_param *param, int flags);
int vzctl2_unwrap_env_create_snapshot(struct vzctl_env_handle *h, int argc,
		char **argv);
int vzctl_wrap_env_create_snapshot(struct vzctl_env_handle *h,
	struct vzctl_snapshot_param *param);
int vzctl2_unwrap_env_switch_snapshot(struct vzctl_env_handle *h, int argc,
		char **argv);
int vzctl_wrap_env_switch_snapshot(struct vzctl_env_handle *h,
		struct vzctl_switch_snapshot_param *param);
int vzctl2_unwrap_env_delete_snapshot(struct vzctl_env_handle *h, int argc,
		char **argv);
int vzctl_wrap_env_delete_snapshot(struct vzctl_env_handle *h, const char *guid);
#endif
