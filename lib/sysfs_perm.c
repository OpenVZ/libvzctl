/*
 * Copyright (c) 2015 Parallels IP Holdings GmbH
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
 * Our contact details: Parallels IP Holdings GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include "errno.h"
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include "logger.h"
#include "env.h"
#include "list.h"
#include "cgroup.h"
#include "vzerror.h"

int add_sysfs_dir(struct vzctl_env_handle *h, const char *sysfs,
		const char *devname, const char *mode)
{
	char buf[PATH_MAX];
	char t[PATH_MAX];
	char *p;

	if (devname != NULL)
		snprintf(t, sizeof(t), "%s/%s/", sysfs, devname);
	else
		snprintf(t, sizeof(t), "%s/", sysfs);

	for (p = strchr(t, '/'); p != NULL; p = strchr(p, '/')) {
		*p = '\0';
		snprintf(buf, sizeof(buf), "%s %s", t, mode);
		if (cg_set_param(EID(h), CG_VE, "ve.sysfs_permissions", buf))
			return VZCTL_E_SYSFS_PERM;
		*p++ = '/';
	}

	return 0;
}

int add_sysfs_entry(struct vzctl_env_handle *h, const char *sysfs)
{
	char path[PATH_MAX];
	struct dirent **namelist;
	struct stat st;
	int n;
	int ret = 0;

	snprintf(path, sizeof(path), "%s rx", sysfs);
	if (cg_set_param(EID(h), CG_VE, "ve.sysfs_permissions", path))
		return VZCTL_E_SYSFS_PERM;

	snprintf(path, sizeof(path), "/sys/%s", sysfs);
	if (lstat(path, &st))
		return vzctl_err(VZCTL_E_SYSTEM, errno, "Cant stat %s", path);

	if (!S_ISDIR(st.st_mode))
		return 0;

	n = scandir(path, &namelist, NULL, NULL);
	if (n < 0)
		return vzctl_err(VZCTL_E_SYSTEM, errno, "Unable to open %s",
				path);

	while (n--) {
		if (strcmp(namelist[n]->d_name, ".") == 0 ||
				strcmp(namelist[n]->d_name, "..") == 0)
			continue;

		snprintf(path, sizeof(path), "%s/%s %s",
			sysfs, namelist[n]->d_name,
			!strcmp(namelist[n]->d_name, "uevent") ? "rw" : "rx");
		if (cg_set_param(EID(h), CG_VE, "ve.sysfs_permissions", path))
			ret = VZCTL_E_SYSFS_PERM;

		free(namelist[n]);
	}
	free(namelist);

	return ret;
}

int get_sysfs_device_path(const char *class, const char *devname, char *out,
		int size)
{
	int n;
	char x[STR_SIZE];
	char buf[PATH_MAX];
	const char *p = buf;

	snprintf(x, sizeof(x), "/sys/class/%s/%s", class, devname);

	n = readlink(x, buf, sizeof(buf) -1);
	if (n == -1)
		return vzctl_err(VZCTL_E_SYSTEM, errno, "Failed to read %s", x);
	buf[n-1] = '\0';

	p += 6;
	n = strlen(p) - strlen(devname) + 1;

	if (n < 0 || n > size)
		return vzctl_err(VZCTL_E_INVAL, 0,
			"get_sysfs_device_path: incorrect value %s", buf);

	snprintf(out, n, "%s", p);

	return 0;
}

