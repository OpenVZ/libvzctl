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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <errno.h>

#include "libvzctl.h"
#include "../lib/vzerror.h"
#include "../lib/dist.h"
#include "../lib/logger.h"
#include "../lib/exec.h"
#include "../lib/env.h"

static void usage()
{
	printf("exec_wrap <ID> <SCRIPT> <VE_ROOT> <timeout> <0|1> [arg...arg]\n");
}

int parse_ul(const char *str, unsigned long *val)
{
	char *tail;

	errno = 0;
	*val = strtoul(str, (char **)&tail, 10);
	if (*tail != '\0' || errno == ERANGE)
		return 1;
	return 0;
}

int parse_int(const char *str, int *val)
{
	char *tail;

	errno = 0;
	*val = (int)strtol(str, (char **)&tail, 10);
	if (*tail != '\0' || errno == ERANGE)
		return 1;
	return 0;
}

int main(int argc, char **argv)
{
	int ret;
	int timeout = 0;
	const char *fname;
	const char *inc = NULL;
	int flags;
	ctid_t ctid = {};
	struct vzctl_env_handle *h;

	if (argc < 6) {
		usage();
		return VZCTL_E_INVAL;
	}

	// ID
	if (*argv[1] != '\0' && vzctl2_parse_ctid(argv[1], ctid))
		return VZCTL_E_INVAL;
	// SCRIPT
	fname = argv[2];
	// VE_ROOT
	//ve_root = argv[3];
	// timeout
	if (parse_int(argv[4], &timeout))
		return VZCTL_E_INVAL;
	// use_fz_func
	if (!strcmp(argv[5], "1"))
		inc = DIST_FUNC;
	// Flags
	if (parse_int(argv[6], &flags))
		return VZCTL_E_INVAL;

	vzctl2_init_log(basename(argv[0]));
	vzctl2_set_ctx(ctid);
	if ((ret = vzctl2_lib_init()))
		return ret;
	argv += 7;
	argc -= 7;

	if (EMPTY_CTID(ctid))
		return vzctl2_exec_script(argv, NULL, flags);

	h = vzctl2_env_open(ctid, 0, &ret);
	if (h == NULL)
		return ret;

	ret = vzctl2_env_exec_script(h, argv, NULL, fname, inc,
			timeout, flags);

	vzctl2_env_close(h);

	return ret;
}
