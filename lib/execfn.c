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
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/errno.h>

#include "vzerror.h"
#include "util.h"
#include "common.h"

int vzctl2_env_exec_fn3(ctid_t ctid, execFn fn, void *data, int *data_fd, int flags)
{
	int ret;
	pid_t pid, pid2;

	fflush(stderr);
	fflush(stdout);

	pid = fork();
	if (pid < 0) {
		return vzctl_err(VZCTL_E_FORK, errno, "Cannot fork");
	} else if (pid == 0) {
		ret = env_enter(ctid, flags);
		if (ret)
			goto err;

		pid2 = fork();
		if (pid2 < 0) {
			ret = vzctl_err(VZCTL_E_FORK, errno, "Cannot fork");
			goto err;
		} else if (pid2 == 0) {
			_close_fds(data_fd != NULL ? VZCTL_CLOSE_STD : 0, data_fd);
			ret = fn(data);
			goto err;
		}
		ret = env_wait(pid2, 0, NULL);
err:
		_exit(ret);
	}

	return env_wait(pid, 0, NULL);
}
