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
#include <signal.h>

#include "libvzctl.h"
#include "../lib/vzerror.h"
#include "../lib/dist.h"
#include "../lib/logger.h"
#include "../lib/exec.h"
#include "../lib/env.h"

static void usage()
{
	printf("exec_wrap <ID> <SCRIPT> <""> <timeout> <0|1> <flags> [arg...arg]\n");
	printf("          <ID> <""> <in:out:err:comm> <timeout> <0|1|4> <flags> [arg...arg]\n");
}

static void cleanup(int sig)
{
	vzctl2_cancel_last_operation();
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
	int stdfd[4] = {-1, -1, -1, -1};
	struct vzctl_env_handle *h;
	struct sigaction a = {};
	exec_mode_e mode = MODE_EXEC;

	if (argc < 6)
		goto err;

	// ID
	if (*argv[1] != '\0' && vzctl2_parse_ctid(argv[1], ctid))
		goto err;
	// SCRIPT
	fname = argv[2];

	// timeout
	if (parse_int(argv[4], &timeout))
		goto err;

	// Flags
	if (parse_int(argv[6], &flags))
		goto err;

	if (fname[0] == '\0') {
		if (sscanf(argv[3], "%d:%d:%d:%d", &stdfd[0], &stdfd[1], &stdfd[2], &stdfd[3]) != 4)
			goto err;

		mode = atoi(argv[5]);
		flags |= EXEC_NOENV;
	} else {
		// use_fz_func
		if (!strcmp(argv[5], "1"))
			inc = DIST_FUNC;
	}

	vzctl2_init_log(basename(argv[0]));
	if (mode == MODE_TTY)
		vzctl2_set_log_quiet(1);
	vzctl2_set_ctx(ctid);
	vzctl2_set_flags(VZCTL_FLAG_WRAP);
	if ((ret = vzctl2_lib_init()))
		return ret;
	argv += 7;
	argc -= 7;

	if (EMPTY_CTID(ctid))
		return vzctl2_exec_script(argv, NULL, flags);

	h = vzctl2_env_open(ctid, 0, &ret);
	if (h == NULL)
		return ret;

	a.sa_handler = cleanup;
	sigaction(SIGTERM, &a, NULL);
	sigaction(SIGINT, &a, NULL);
	sigaction(SIGHUP, &a, NULL);

	if (fname[0] == '\0') {
		if (mode == MODE_TTY) {
			ret = vzctl2_env_exec_pty_priv(h, mode, argv, NULL, stdfd, flags);
		} else {
			ret = vzctl2_env_execve_priv(h, mode, argv, NULL,
					timeout, stdfd, flags);
		}
	} else
		ret = vzctl2_env_exec_script(h, NULL, NULL, fname, inc,
			timeout, flags);

	vzctl2_env_close(h);
	return ret;

err:
	usage();
	return VZCTL_E_INVAL;
}
