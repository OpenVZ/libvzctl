/*
 * Copyright (c) 2015-2017, Parallels International GmbH
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
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "env_ops.h"

extern void env_vzops_init();
extern void env_nsops_init();

static struct vzctl_env_ops _g_ops = {};

struct vzctl_env_ops *get_env_ops(void)
{
	return &_g_ops;
}

void init_env_ops(void)
{
	env_nsops_init(get_env_ops());
}

static const char *get_cmdname(char *out, int size)
{
	int fd, n;
	const char *p;
	char x[64];

	snprintf(x, sizeof(x), "/proc/%d/cmdline", getpid());
	fd = open(x, O_RDONLY);
	if (fd != -1 && (n = read(fd, x, sizeof(x) - 1)) != -1) {
		x[n] = '\0';
		p = strrchr(x, '/');
		snprintf(out, size, "%s", p ? ++p : x);
	} else
		snprintf(out, size, "%d", getpid());

	if (fd != -1)
		close(fd);

	return out;
}

__attribute__((constructor)) void __init_env_ops(void)
{
	char cmdnamep[64];

	init_env_ops();

	vzctl2_init_log(get_cmdname(cmdnamep, sizeof(cmdnamep)));
	vzctl2_set_log_quiet(1);
}

