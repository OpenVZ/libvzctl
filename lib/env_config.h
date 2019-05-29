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

#ifndef __ENV_CONFIG_H__
#define __ENV_CONFIG_H__

#include "config.h"

int is_private_param(const char *name);

int vzctl2_add_env_param(struct vzctl_env_param *env, struct vzctl_data_param *data, int flags);
int vzctl_update_env_param(struct vzctl_env_handle *h, int flags);
int merge_env_param(struct vzctl_env_handle *h, struct vzctl_env_param *env,
		param_filter_f filter, int flags);

#endif /* __ENV_CONFIG_H__ */
