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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include "util.h"
#include "vzerror.h"
#include "logger.h"
#include "ha.h"
#include "env.h"
#include "config.h"
#include "cluster.h"
#include "exec.h"

#define SHAMAN_BIN	"/usr/sbin/shaman"
#define CPUFEATURES_BIN	"/usr/sbin/cpufeatures"

static int is_bin_present(const char *path)
{
	return stat_file(path);
}

static void shaman_get_resname(ctid_t ctid, char *buf, int size)
{
	snprintf(buf, size, "ct-%s", ctid);
}

int handle_set_cmd_on_ha_cluster(ctid_t ctid, const char *ve_private,
		struct ha_params *cmdline, struct ha_params *config)
{
	char *argv[9];
	char *fail_act = NULL;
	char resname[NAME_MAX];
	char prio[NAME_MAX];
	int rc, i = 0;
	int del = cmdline->ha_enable == VZCTL_PARAM_OFF;

	if (!is_bin_present(SHAMAN_BIN))
		return 0;

	if (config->ha_enable == VZCTL_PARAM_OFF &&
			cmdline->ha_enable != VZCTL_PARAM_ON)
		return 0;

	argv[i++] = SHAMAN_BIN;
	argv[i++] = "-i";

	if (cmdline->ha_enable == VZCTL_PARAM_ON) {
		/*
		 * If there is a '--ha-enable yes' in the command line, then use 'add'
		 * command to create resource file and set up needed parameters.
		 */
		argv[i++] = "add";
		fail_act = "set";
	} else if (cmdline->ha_enable == VZCTL_PARAM_OFF) {
		argv[i++] = "del";
	} else if (cmdline->ha_prio) {
		argv[i++] = "set";
		fail_act = "add";
	} else {
		/* HA options are not present in the command line */
		return 0;
	}

	shaman_get_resname(ctid, resname, sizeof(resname));
	argv[i++] = resname;

	if (!del) {
		/*
		 * Specify all parameters from the config when doing 'shaman add'.
		 * This is needed e.g. when registering an already existing CT - newly
		 * created cluster resource for this CT should contain all actual
		 * HA parameter values.
		 */
		if (cmdline->ha_prio || config->ha_prio) {
			snprintf(prio, sizeof(prio), "%lu",
					cmdline->ha_prio ? *cmdline->ha_prio :
					*config->ha_prio);
			argv[i++] = "--prio";
			argv[i++] = prio;
		}
		argv[i++] = "--path";
		argv[i++] = (char *)ve_private;
	}
	argv[i] = NULL;

	rc = vzctl2_wrap_exec_script(argv, NULL, 0);
	if (rc == 2 && fail_act != NULL) {
		/* try to guess action if failed */
		argv[2] = fail_act;
		rc = vzctl2_wrap_exec_script(argv, NULL, 0);
	}

	return rc;
}

void shaman_del_everywhere(ctid_t ctid)
{
	char resname[NAME_MAX];
	char *argv[] = {SHAMAN_BIN, "-i", "-q", "del-everywhere", resname, NULL};

	if (!is_bin_present(SHAMAN_BIN))
		return;

	shaman_get_resname(ctid, resname, sizeof(resname));
	vzctl2_wrap_exec_script(argv, NULL, 0);
}

int shaman_del_resource(ctid_t ctid)
{
	char resname[NAME_MAX];
	char *argv[] = {SHAMAN_BIN, "-i", "del", resname, NULL};

	if (!is_bin_present(SHAMAN_BIN))
		return 0;

	shaman_get_resname(ctid, resname, sizeof(resname));
	return vzctl2_wrap_exec_script(argv, NULL, 0);
}

int shaman_add_resource(ctid_t ctid, struct vzctl_config *conf, const char *ve_private)
{
	char resname[NAME_MAX];
	char *argv[] = {SHAMAN_BIN, "-i", "add", resname,
					"--prio", NULL,
					"--path", (char *)ve_private,
					"--force",
					NULL};
	const char *prio = NULL;

	if (!is_bin_present(SHAMAN_BIN))
		return 0;

	shaman_get_resname(ctid, resname, sizeof(resname));
	vzctl2_conf_get_param(conf, "HA_PRIO", &prio);
	argv[5] = (char *)(prio ?: "0");

	return vzctl2_wrap_exec_script(argv, NULL, 0);
}

int shaman_is_configured(void)
{
	char *argv[] = {SHAMAN_BIN, "info", NULL};

	if (!is_bin_present(SHAMAN_BIN))
		return 0;

	return vzctl2_wrap_exec_script(argv, NULL, 1) == 0;
}

int ha_sync(struct vzctl_env_handle *h, int flags)
{
	if (is_bin_present(CPUFEATURES_BIN)) {
		char *argv[] = {CPUFEATURES_BIN, "--quiet", "sync", NULL};
		if (vzctl2_wrap_exec_script(argv, NULL, 0))
			return vzctl_err(VZCTL_E_CPUPOOLS, 0,
				"Error syncing node and pool features.");
	}

	const char *private = h->env_param->fs->ve_private;
	if (!(flags & VZCTL_SKIP_HA_REG) &&
			h->env_param->opts->ha_enable != VZCTL_PARAM_OFF &&
			is_shared_fs(private))
	{
		shaman_add_resource(h->ctid, h->conf, private);
	}

	return 0;
}
