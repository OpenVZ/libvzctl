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
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "vzerror.h"
#include "vztypes.h"
#include "logger.h"
#include "vztypes.h"
#include "fs.h"
#include "util.h"
#include "config.h"
#include "vz.h"

void remove_names(struct vzctl_env_handle *h)
{
	char buf[PATH_LEN];
	struct dirent *ep;
	DIR *dp;
	struct stat st_conf, st_name;

	vzctl2_get_env_conf_path_orig(h, buf, sizeof(buf));
	if (stat(buf, &st_conf))
		return;
	if (!(dp = opendir(ENV_NAME_DIR)))
		return;
	while ((ep = readdir(dp))) {
		if (!strcmp(ep->d_name, ".") || !strcmp(ep->d_name, ".."))
			continue;
		snprintf(buf, sizeof(buf), ENV_NAME_DIR "%s", ep->d_name);
		if (stat(buf, &st_name))
			continue;
		if (st_conf.st_dev == st_name.st_dev &&
		    st_conf.st_ino == st_name.st_ino)
		{
			unlink(buf);
		}
	}
	closedir(dp);
}


int validate_env_name(struct vzctl_env_handle *h, const char *name, ctid_t ctid)
{
	char fconf[PATH_MAX];
	char fname[PATH_MAX];

	/* CTID conflict with name */
	if (vzctl2_get_envid_by_name(EID(h), ctid) == 0 &&
			!EMPTY_CTID(ctid) && CMP_CTID(ctid, EID(h)))
		return vzctl_err(VZCTL_E_SET_NAME, 0,
				"Conflict: CTID %s already used by Container %s",
				EID(h), ctid);

	if (name == NULL)
		return 0;

	if (!vzctl2_is_env_name_valid(name))
		return vzctl_err(VZCTL_E_INVAL, 0, "Error: invalid name %s", name);

	if (strcmp(EID(h), name) == 0)
		return 0;

	vzctl2_get_env_conf_path(name, fconf, sizeof(fconf));
	snprintf(fname, sizeof(fname), ENV_NAME_DIR "%s", name);

	/* name conflict with CTID */
	if (stat_file(fconf) == 1)
		return vzctl_err(VZCTL_E_INVAL, 0, "Conflict: name %s used as ctid",
				name);

	if (vzctl2_get_envid_by_name(name, ctid) == 0 &&
			!EMPTY_CTID(ctid) && CMP_CTID(ctid, EID(h)))
		return vzctl_err(VZCTL_E_SET_NAME, 0,
				"Conflict: name %s already used by Container %s",
				name, ctid);

	return 0;
}

int vzctl2_set_name(struct vzctl_env_handle *h, const char *name)
{
	int ret;
	ctid_t ctid_old;
	char fname[PATH_LEN];
	char veconf[PATH_LEN];
	const char *old_name = h->env_param->name->name;

	if (name == NULL)
		return 0;

	if (name[0] == '\0')
		goto del_name;

	ret = validate_env_name(h, name, ctid_old);
	if (ret)
		return ret;

	/* Container name not changed */
	if (old_name != NULL &&
		!strcmp(old_name, name) &&
		CMP_CTID(ctid_old, EID(h)) == 0)
	{
		return 0;
	}

	snprintf(fname, sizeof(fname), ENV_NAME_DIR "%s", name);
	vzctl2_get_env_conf_path_orig(h, veconf, sizeof(veconf));
	unlink(fname);
	if (symlink(veconf, fname))
		return vzctl_err(VZCTL_E_SET_NAME, errno,
				"Unable to create link %s", fname);

del_name:
	/* Remove the old name link */
	if (old_name != NULL && strcmp(old_name, name)) {
		if (vzctl2_get_envid_by_name(old_name, ctid_old) == 0 &&
				CMP_CTID(ctid_old, EID(h)) == 0)
		{
			snprintf(fname, sizeof(fname), ENV_NAME_DIR "/%s", old_name);
			unlink(fname);
		}
	}

	vzctl2_env_set_param(h, "NAME", name[0] == '\0' ? NULL : name);

	ret = vzctl2_env_save(h);
	if (ret) {
		snprintf(fname, sizeof(fname), ENV_NAME_DIR "%s", name);
		unlink(fname);
		return ret;
	}

	if (name[0] == 0)
		logger(0, 0, "Name %s detached",
			old_name != NULL ? old_name : "");
	else
		logger(0, 0, "Name %s assigned", name);

	vzctl2_send_state_evt(EID(h), VZCTL_ENV_CONFIG_CHANGED);

	return 0;
}

const char *gen_uniq_name(const char *name, char *out, int size)
{
	int i;
	char path[PATH_MAX];
	struct stat st;

#define NAME_FMT	"%s-(%d)"
	for (i = 0; i < 0xffff; i++) {
		snprintf(path, sizeof(path), ENV_NAME_DIR NAME_FMT, name, i);
		if (lstat(path, &st) && errno == ENOENT) {
			snprintf(out, size, NAME_FMT, name, i);
			return out;
		}
	}

#undef  NAME_FMT
	return "";
}
