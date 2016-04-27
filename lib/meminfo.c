/*
 *  Copyright (c) 1999-2015 Parallels IP Holdings GmbH
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
 *
 */

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <linux/vzcalluser.h>
#include <string.h>
#include <limits.h>

#include "vzerror.h"
#include "logger.h"
#include "meminfo.h"
#include "vztypes.h"
#include "env.h"
#include "config.h"
#include "vz.h"
#include "util.h"

static struct {
	char *mode_nm;
	int mode_id;
} mode_tbl_[] = {
	{"none", VE_MEMINFO_NONE},
	{"pages", VE_MEMINFO_PAGES},
	{"privvmpages",	VE_MEMINFO_PRIVVMPAGES},
};

struct vzctl_meminfo_param *alloc_meminfo_param(void)
{
	return calloc(1, sizeof(struct vzctl_meminfo_param));
}

void free_meminfo_param(struct vzctl_meminfo_param *meminfo)
{
	free(meminfo);
}

int apply_meminfo_param(struct vzctl_env_handle *h, struct vzctl_env_param *env, int flags)
{
	int ret;
	struct vzctl_ve_meminfo meminfo;
	struct vzctl_meminfo_param *param = env->meminfo;

	if (param->mode != VE_MEMINFO_PAGES &&
			param->mode != VE_MEMINFO_NONE)
		return 0;

	meminfo.veid = h->veid;
	switch (param->mode) {
	case VE_MEMINFO_NONE:
		logger(0, 0, "Configure meminfo: none");
		meminfo.val = 0;
		break;
	case VE_MEMINFO_PAGES:
		logger(0, 0, "Configure meminfo: %lu", param->val);
		meminfo.val = param->val;
		break;
	case VE_MEMINFO_PRIVVMPAGES:
		logger(0, 0, "Warning: VE_MEMINFO_PRIVVMPAGES is not supported");
		return 0;
	default:
		logger(0, 0, "Warning: unrecognized mode"
			" to set meminfo parameter");
		return 0;
	}
	ret = ioctl(get_vzctlfd(), VZCTL_VE_MEMINFO, &meminfo);
	if (ret < 0) {
		if (errno == ENOTTY)
			logger(0, 0, "Warning: meminfo feature is not supported"
				" by kernel. skipped meminfo configure");
		else
			return vzctl_err(VZCTL_E_SET_MEMINFO, errno, "Unable to set meminfo");
	}
	return 0;
}

static int get_meminfo_mode(char *name)
{
	int i;

	for (i = 0; i < sizeof(mode_tbl_) / sizeof(mode_tbl_[0]); i++)
		if (!strcmp(mode_tbl_[i].mode_nm, name))
			return mode_tbl_[i].mode_id;

	return -1;
}

static const char *get_meminfo_mode_nm(int id)
{
	int i;

	for (i = 0; i < sizeof(mode_tbl_) / sizeof(mode_tbl_[0]); i++)
		if (mode_tbl_[i].mode_id == id)
			return mode_tbl_[i].mode_nm;
	return NULL;
}

int parse_meminfo(struct vzctl_meminfo_param *meminfo, const char *str)
{
	int mode;
	char mode_nm[32];
	unsigned long val;
	int ret;

	if (*str == 0)
		return 0;
	val = 0;
	ret = sscanf(str, "%31[^:]:%lu", mode_nm, &val);
	if (ret != 2 && ret != 1)
		return VZCTL_E_INVAL;
	if ((mode = get_meminfo_mode(mode_nm)) < 0)
		return VZCTL_E_INVAL;
	if ((mode != VE_MEMINFO_NONE && ret != 2) ||
			(mode == VE_MEMINFO_NONE && ret == 2))
		return VZCTL_E_INVAL;
	if((mode != VE_MEMINFO_NONE) && val == 0)
		return VZCTL_E_INVAL;
	meminfo->mode = mode;
	meminfo->val = val;

	return 0;
}

char *meminfo2str(struct vzctl_meminfo_param *meminfo)
{
	char buf[64];
	const char *mode_nm;

	if (meminfo->mode < 0)
		return NULL;
	mode_nm = get_meminfo_mode_nm(meminfo->mode);
	if (mode_nm == NULL)
		return NULL;
	if (meminfo->mode == VE_MEMINFO_NONE)
		snprintf(buf, sizeof(buf), "%s", mode_nm);
	else
		snprintf(buf, sizeof(buf), "%s:%lu", mode_nm, meminfo->val);
	return strdup(buf);
}
