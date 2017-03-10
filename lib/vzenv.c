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

#include <stdlib.h>

#include "logger.h"
#include "env.h"
#include "vzenv.h"
#include "vzerror.h"
#include "errno.h"


void free_vz_env_param(struct vzctl_vz_env_param *env)
{
	if (env == NULL)
		return;
	if (env->tc != NULL)
		free_tc_param(env->tc);
	free(env);
}

struct vzctl_vz_env_param *alloc_vz_env_param(void)
{
	struct vzctl_vz_env_param *env;

        if ((env = calloc(1, sizeof(struct vzctl_vz_env_param))) == NULL)
                goto err;
	if ((env->tc = alloc_tc_param()) == NULL)
		goto err;

	return env;

err:
	free_vz_env_param(env);
	vzctl_err(VZCTL_E_NOMEM, ENOMEM, "vzctl_alloc_env_param");

	return NULL;
}
