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

#include <unistd.h>
#include <errno.h>

#include "libvzctl.h"
#include "exec.h"
#include "logger.h"
#include "vzerror.h"
#include "util.h"
#include "snapshot.h"

static int do_exec(char *const arg[])
{
	int pid;

	pid = vfork();
	if (pid == -1) {
		return vzctl_err(VZCTL_E_FORK, errno, "Cannot fork");
	} else if (pid == 0) {
		execvp(arg[0], arg);
		_exit(VZCTL_E_SYSTEM);
	}

	return env_wait(pid, 0, NULL);
}

static int exec_action(struct vzctl_env_handle *h, char *action,
		char *const arg[])
{
	int ret;
	char **n;
	char *a[] = {VZCTL_ACTION_WRAP_BIN, action, EID(h), NULL};

	n = build_arg(a, arg);
	if (n == NULL)
		return VZCTL_E_NOMEM;

	ret = do_exec(n);
	free(n);

	return ret;
}

int vzctl2_unwrap_env_stop(struct vzctl_env_handle *h, int argc, char **argv)
{
	int flags, mode;

	if (argc != 2)
		return VZCTL_E_INVAL;

	if (parse_int(argv[0], &mode))
		return VZCTL_E_INVAL;

	if (parse_int(argv[1], &flags))
		return VZCTL_E_INVAL;

	return vzctl_env_stop(h, mode, flags);
}

int vzctl_wrap_env_stop(struct vzctl_env_handle *h, stop_mode_e stop_mode,
		int flags)
{
	if (vzctl2_get_flags() & VZCTL_FLAG_DONT_USE_WRAP)
		return vzctl_env_stop(h, stop_mode, flags);

	char m[12];
	char f[12];
	char *const arg[] = {m, f, NULL};

	snprintf(m, sizeof(m), "%d", stop_mode);
	snprintf(f, sizeof(f), "%d", flags);

	return exec_action(h, "stop", arg);
}

int vzctl2_unwrap_env_destroy(struct vzctl_env_handle *h, int argc, char **argv)
{
	int flags;

	if (argc != 1)
		return VZCTL_E_INVAL;

	if (parse_int(argv[0], &flags))
		return VZCTL_E_INVAL;

	return vzctl_env_destroy(h, flags);
}

int vzctl_wrap_env_destroy(struct vzctl_env_handle *h, int flags)
{
	if (vzctl2_get_flags() & VZCTL_FLAG_DONT_USE_WRAP)
		return vzctl_env_destroy(h, flags);

	char f[12];
	char *const arg[] = {f, NULL};

	snprintf(f, sizeof(f), "%d", flags);

	return exec_action(h, "destroy", arg);
}

int vzctl2_unwrap_env_start(struct vzctl_env_handle *h, int argc, char **argv)
{
        int flags;

        if (argc != 1)
                return VZCTL_E_INVAL;

        if (parse_int(argv[0], &flags))
                return VZCTL_E_INVAL;

        return vzctl_env_start(h, flags);
}

int vzctl_wrap_env_start(struct vzctl_env_handle *h, int flags)
{
	if (vzctl2_get_flags() & VZCTL_FLAG_DONT_USE_WRAP)
		return vzctl_env_start(h, flags);

	char f[12];
	char *const arg[] = {f, NULL};

	snprintf(f, sizeof(f), "%d", flags);

	return exec_action(h, "start", arg);
}

int vzctl2_unwrap_env_chkpnt(struct vzctl_env_handle *h, int argc, char **argv)
{
	struct vzctl_cpt_param param = {};
	int flags, cmd;

	if (argc != 3)
		return VZCTL_E_INVAL;

	if (argv[0][0] != '\0')
		param.dumpfile = argv[0];

	if (parse_int(argv[1], &cmd))
		return VZCTL_E_INVAL;

	if (parse_int(argv[2], &flags))
		return VZCTL_E_INVAL;

	return vzctl_env_chkpnt(h, cmd, &param, flags);
}

int vzctl_wrap_env_chkpnt(struct vzctl_env_handle *h, int cmd,
		struct vzctl_cpt_param *param, int flags)
{
	if (vzctl2_get_flags() & VZCTL_FLAG_DONT_USE_WRAP)
		return vzctl_env_chkpnt(h, cmd, param, flags);

	char c[12];
	char f[12];
	char *const arg[] = {param->dumpfile ?: "", c, f, NULL};

	snprintf(c, sizeof(c), "%d", cmd);
	snprintf(f, sizeof(f), "%d", flags);

	return exec_action(h, "chkpnt", arg);
}

int vzctl2_unwrap_env_restore(struct vzctl_env_handle *h, int argc, char **argv)
{
        struct vzctl_cpt_param param = {};
        int flags;

        if (argc != 3)
                return VZCTL_E_INVAL;

        if (argv[0][0] != '\0')
                param.dumpfile = argv[0];

        if (parse_int(argv[1], &param.cmd))
                return VZCTL_E_INVAL;

        if (parse_int(argv[2], &flags))
                return VZCTL_E_INVAL;

        return vzctl_env_restore(h, &param, flags);
}

int vzctl_wrap_env_restore(struct vzctl_env_handle *h,
		struct vzctl_cpt_param *param, int flags)
{
	if (vzctl2_get_flags() & VZCTL_FLAG_DONT_USE_WRAP)
		return vzctl_env_restore(h, param, flags);

	char c[12];
	char f[12];
	char *const arg[] = {param->dumpfile ?: "", c, f, NULL};

	snprintf(c, sizeof(c), "%d", param->cmd);
	snprintf(f, sizeof(f), "%d", flags);

	return exec_action(h, "restore", arg);
}

int vzctl2_unwrap_env_create_snapshot(struct vzctl_env_handle *h, int argc,
		char **argv)
{
	struct vzctl_snapshot_param param = {};

	if (argc != 4)
		return VZCTL_E_INVAL;

	if (argv[0][0] != '\0')
		param.guid = argv[0];
	if (argv[1][0] != '\0')
		param.name = argv[1];
	if (argv[2][0] != '\0')
		param.desc = argv[2];

	if (parse_int(argv[3], &param.flags))
		return VZCTL_E_INVAL;

	return vzctl_env_create_snapshot(h, &param);
}

int vzctl_wrap_env_create_snapshot(struct vzctl_env_handle *h,
		struct vzctl_snapshot_param *param)
{
	if (vzctl2_get_flags() & VZCTL_FLAG_DONT_USE_WRAP)
		return vzctl_env_create_snapshot(h, param);

	char f[12];
	char *const arg[] = {param->guid ?: "", param->name ?: "", param->name ?: "",
		f, NULL};

	snprintf(f, sizeof(f), "%d", param->flags);

	return exec_action(h, "create-snapshot", arg);
}

int vzctl2_unwrap_env_switch_snapshot(struct vzctl_env_handle *h, int argc,
		char **argv)
{
	struct vzctl_switch_snapshot_param param = {};

	if (argc != 2)
		return VZCTL_E_INVAL;

	param.guid = argv[0];

	if (parse_int(argv[1], &param.flags))
		return VZCTL_E_INVAL;

	return vzctl_env_switch_snapshot(h, &param);
}

int vzctl_wrap_env_switch_snapshot(struct vzctl_env_handle *h,
		struct vzctl_switch_snapshot_param *param)
{
	if (vzctl2_get_flags() & VZCTL_FLAG_DONT_USE_WRAP)
		return vzctl_env_switch_snapshot(h, param);

	char f[12];
	char *const arg[] = {param->guid, f, NULL};

	snprintf(f, sizeof(f), "%d", param->flags);

	return exec_action(h, "switch-snapshot", arg);
}

int vzctl2_unwrap_env_delete_snapshot(struct vzctl_env_handle *h, int argc,
		char **argv)
{
	if (argc != 1)
		return VZCTL_E_INVAL;

	return vzctl_env_delete_snapshot(h, argv[0]);
}

int vzctl_wrap_env_delete_snapshot(struct vzctl_env_handle *h, const char *guid)
{
	if (vzctl2_get_flags() & VZCTL_FLAG_DONT_USE_WRAP)
		return vzctl_env_delete_snapshot(h, guid);

	char *const arg[] = {(char *)guid, NULL};

	return exec_action(h, "delete-snapshot", arg);
}
