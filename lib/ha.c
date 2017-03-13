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
		struct ha_params *cmdline,
		struct ha_params *config,
		int save)
{
	int i = 5;
	struct stat st;
	char command[NAME_MAX];
	char resname[NAME_MAX];
	char *argv[] = {SHAMAN_BIN, "-i", "-q", command, resname, NULL, NULL, NULL};
	char prio[NAME_MAX];

	if (cmdline->ha_enable) {
		/*
		 * If there is a '--ha-enable yes' in the command line, then use 'add'
		 * command to create resource file and set up needed parameters.
		 */
		snprintf(command, sizeof(command), "%s", id2yesno(cmdline->ha_enable));
	} else if (cmdline->ha_prio) {
		snprintf(command, sizeof(command), "set");
	} else {
		/* HA options are not present in the command line */
		return 0;
	}

	/*
	 * Check that '--ha-*' options are always used along with '--save', otherwise
	 * CT config and HA cluster contents could become unsynchronized.
	 */
	if (!save) {
		logger(-1, 0, "High Availability Cluster options could be set only"
			" when --save option is provided");
		return VZCTL_E_NOT_ENOUGH_PARAMS;
	}

	/*
	 * If HA_ENABLE is explicitely set to "no" in the CT config and the command
	 * line doesn't provide the '--ha_enable' option -- just save parameters
	 * in the CT config and don't run shaman.
	 */
	if ((config->ha_enable == VZCTL_PARAM_ON) && !cmdline->ha_enable)
		return 0;

	if (stat(ve_private, &st) || !is_shared_fs(ve_private))
		return 0;

	if (!is_bin_present(SHAMAN_BIN))
		return 0;

	shaman_get_resname(ctid, resname, sizeof(resname));

	if (cmdline->ha_prio || config->ha_prio) {
		snprintf(prio, sizeof(prio), "%lu",
				 cmdline->ha_prio ? *cmdline->ha_prio : *config->ha_prio);
		argv[i++] = "--prio";
		argv[i++] = prio;
	}

	return vzctl2_wrap_exec_script(argv, NULL, 0);
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
	char *argv[] = {SHAMAN_BIN, "-i", "-q", "del", resname, NULL};

	if (!is_bin_present(SHAMAN_BIN))
		return 0;

	shaman_get_resname(ctid, resname, sizeof(resname));
	return vzctl2_wrap_exec_script(argv, NULL, 0);
}

int shaman_add_resource(ctid_t ctid, struct vzctl_config *conf, const char *ve_private)
{
	char resname[NAME_MAX];
	char *argv[] = {SHAMAN_BIN, "-i", "-q",
					"add", resname,
					"--prio", NULL,
					"--path", (char *)ve_private,
					NULL};
	const char *prio = NULL;

	if (!is_bin_present(SHAMAN_BIN))
		return 0;

	shaman_get_resname(ctid, resname, sizeof(resname));

	vzctl2_conf_get_param(conf, "HA_PRIO", &prio);
	argv[6] = (char *)(prio ?: "0");

	return vzctl2_wrap_exec_script(argv, NULL, 0);
}

int shaman_is_configured(void)
{
	char *argv[] = {SHAMAN_BIN, "info", NULL};

	if (!is_bin_present(SHAMAN_BIN))
		return 0;

	return vzctl2_wrap_exec_script(argv, NULL, 1) == 0;
}


int cpufeatures_sync(void)
{
	char *argv[] = {CPUFEATURES_BIN, "--quiet", "sync", NULL};

	if (!is_bin_present(CPUFEATURES_BIN))
		return 0;

	return vzctl2_wrap_exec_script(argv, NULL, 0);
}
