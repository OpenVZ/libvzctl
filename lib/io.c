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
 */

#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <string.h>
#include <limits.h>

#include "vzerror.h"
#include "logger.h"
#include "env.h"
#include "io.h"
#include "util.h"
#include "vz.h"
#include "env_ops.h"

int vzctl2_set_ioprio(struct vzctl_env_handle *h, int prio)
{
	return get_env_ops()->env_set_ioprio(h, prio);
}

int vzctl2_set_iolimit(struct vzctl_env_handle *h, unsigned int limit)
{
	return get_env_ops()->env_set_iolimit(h, limit);
}

int vzctl2_get_iolimit(struct vzctl_env_handle *h, unsigned int *limit)
{
	return get_env_ops()->env_get_iolimit(h, limit);
}

int vzctl2_set_iopslimit(struct vzctl_env_handle *h, unsigned int limit)
{
	return get_env_ops()->env_set_iopslimit(h, limit);
}

int vzctl2_get_iopslimit(struct vzctl_env_handle *h, unsigned int *limit)
{
	return get_env_ops()->env_get_iopslimit(h, limit);
}

int apply_io_param(struct vzctl_env_handle *h, struct vzctl_env_param *env, int flags)
{
	int ret;

	if (env->io->prio >= 0) {
		ret = vzctl2_set_ioprio(h, env->io->prio);
		if (ret)
			return ret;
	}

	if (env->io->limit != UINT_MAX) {
		ret = vzctl2_set_iolimit(h, env->io->limit);
		if (ret)
			return ret;
	}
	if (env->io->iopslimit != UINT_MAX) {
		ret = vzctl2_set_iopslimit(h, env->io->iopslimit);
		if (ret)
			return ret;
	}

	return 0;
}

void free_io_param(struct vzctl_io_param *io)
{
	free(io);
}

struct vzctl_io_param *alloc_io_param(void)
{
	struct vzctl_io_param *new;

	new = malloc(sizeof(struct vzctl_io_param));
	if (new == NULL)
		return NULL;
	new->prio = -1;
	new->limit = UINT_MAX;
	new->iopslimit = UINT_MAX;
	return new;
}

int parse_ioprio(struct vzctl_io_param *io, const char *val)
{
	int n;

	if (parse_int(val, &n))
		return VZCTL_E_INVAL;
	if (n < VE_IOPRIO_MIN || n > VE_IOPRIO_MAX)
		return VZCTL_E_INVAL;
	io->prio = n;

	return 0;
}

int parse_iolimit(struct vzctl_io_param *io, const char *str, int def_mul)
{
	char *tail;
	unsigned long long n, tmp;

	if (strcmp(str, STR_UNLIMITED) == 0) {
		io->limit = 0;
		return 0;
	}

	errno = 0;
	tmp = strtoull(str, &tail, 10);
	if (errno == ERANGE)
		return VZCTL_E_INVAL;

	if (*tail != '\0') {
		if (get_mul(*tail, &n))
			return 1;
		tmp = tmp * n ;
	} else {
		tmp *= def_mul;
	}

	if (tmp > UINT_MAX)
		return VZCTL_E_INVAL;

	io->limit = tmp;

	return 0;
}

int parse_iopslimit(struct vzctl_io_param *io, const char *str)
{
	int ret = 0;
	unsigned long n;

	if (strcmp(str, STR_UNLIMITED) == 0) {
		io->iopslimit = 0;
		return 0;
	}

	ret = parse_ul(str, &n);
	if (n > UINT_MAX)
		return VZCTL_E_INVAL;
	io->iopslimit = (unsigned int)n;

	return ret;
}
