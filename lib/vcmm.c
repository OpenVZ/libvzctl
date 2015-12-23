/*
 * Copyright (c) 2015 Parallels IP Holdings GmbH
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
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

#include "env.h"
#include "ub.h"
#include "logger.h"
#include "vzerror.h"
#include "exec.h"

#define VCMMCTL_BIN     "/usr/sbin/vcmmdctl"

int is_managed_by_vcmmd(void)
{
	return access(VCMMCTL_BIN, F_OK) == 0;
}

int vcmm_unregister(struct vzctl_env_handle *h)
{
	char *arg[] = {VCMMCTL_BIN, "unregister", "--id", EID(h), NULL};

	return vzctl2_wrap_exec_script(arg, NULL, 0);
}

int vcmm_set_memory_param(struct vzctl_env_handle *h, struct vzctl_ub_param *ub)
{
	char *arg[9] = {VCMMCTL_BIN, "register", "--id", EID(h)};
	char memory[21];
	char swap[21];
	int pagesize;
	int i = 0;

	if (h->state & VZCTL_STATE_STARTING)
		vzctl2_wrap_exec_script(arg, NULL, 0);

	if (ub->physpages == NULL && ub->swappages == NULL)
		return 0;

	pagesize = sysconf(_SC_PAGESIZE);
	if (pagesize == -1) {
		vzctl_err(VZCTL_E_SYSTEM, errno, "sysconf(_SC_PAGESIZE)");
		pagesize = 4096;
	}

	arg[i++] = VCMMCTL_BIN;
	arg[i++] = "set_config";
	arg[i++] = "--id";
	arg[i++] = EID(h);
	if (ub->physpages) {
		snprintf(memory, sizeof(memory), "%lu",
				ub->physpages->l * pagesize);
		arg[i++] = "--limit";
		arg[i++] = memory;
	}

	if (ub->swappages) {
		snprintf(swap, sizeof(swap), "%lu",
				ub->swappages->l * pagesize);
		arg[i++] = "--swap_limit";
		arg[i++] = swap;
	}
	arg[i] = NULL;

	return vzctl2_wrap_exec_script(arg, NULL, 0);
}
