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
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <errno.h>
#include <unistd.h>

#include "libvzctl.h"
#include "../lib/vzerror.h"
#include "../lib/logger.h"
#include "../lib/wrap.h"

static int usage()
{
	fprintf(stderr, "action_wrap <ACTION> <ID> <OPTIONS>\n");
	return VZCTL_E_INVAL;
}

int main(int argc, char **argv)
{
	int ret;
	const char *action;
	ctid_t ctid = {};
	struct vzctl_env_handle *h;

	if (argc < 3)
		return usage();

	/* Action */
	action = argv[1];
	/* CTID */
	if (vzctl2_parse_ctid(argv[2], ctid))
		return VZCTL_E_INVAL;

	vzctl2_init_log(getenv("VZCTL_LOG_PROGNAME") ?
				getenv("VZCTL_LOG_PROGNAME") : basename(argv[0]));
	if (getenv("VZCTL_LOG_QUIET"))
		vzctl2_set_log_quiet(1);

	vzctl2_set_ctx(ctid);
	if ((ret = vzctl2_lib_init()))
		return ret;

	vzctl2_set_flags(VZCTL_FLAG_DONT_USE_WRAP);

	h = vzctl2_env_open(ctid, 0, &ret);
	if (h == NULL)
		return ret;
	argc -= 3;
	argv += 3;
	if (!strcmp(action, "start"))
		ret = vzctl2_unwrap_env_start(h, argc, argv);
	else if (!strcmp(action, "stop"))
		ret = vzctl2_unwrap_env_stop(h, argc, argv);
	else if (!strcmp(action, "chkpnt"))
		ret = vzctl2_unwrap_env_chkpnt(h, argc, argv);
	else if (!strcmp(action, "restore"))
		ret = vzctl2_unwrap_env_restore(h, argc, argv);
	else if (!strcmp(action, "destroy"))
		ret = vzctl2_unwrap_env_destroy(h, argc, argv);
	else if (!strcmp(action, "create-snapshot"))
		ret = vzctl2_unwrap_env_create_snapshot(h, argc, argv);
	else if (!strcmp(action, "delete-snapshot"))
		ret = vzctl2_unwrap_env_delete_snapshot(h, argc, argv);
	else if (!strcmp(action, "switch-snapshot"))
		ret = vzctl2_unwrap_env_switch_snapshot(h, argc, argv);

	else
		ret = vzctl_err(VZCTL_E_INVAL_PARAMETER_SYNTAX, 0,
				"Unknown action: %s", action);

	vzctl2_env_close(h);
	const char *p = getenv("VZCTL_ERR_FD");
	if (p && ret) {
		int fd = atoi(p);
		const char *m = vzctl2_get_last_error();
		write(fd, m, strlen(m));
		close(fd);
	}

	return ret;
}
