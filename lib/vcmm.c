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
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

#include <libvcmmd/vcmmd.h>

#include "env.h"
#include "res.h"
#include "logger.h"
#include "vzerror.h"
#include "exec.h"
#include "util.h"

#define VCMMCTL_BIN     "/usr/sbin/vcmmdctl"
#define DEFAULT_MEM_GUARANTEE_PCT	0
static int vcmm_error(int rc, const char *msg)
{
	char buf[STR_SIZE];

	return vzctl_err(VZCTL_E_VCMM, 0, "vcmmd: %s: %s",
			msg, vcmmd_strerror(rc, buf, sizeof(buf)));
}

static struct vcmmd_ve_config *vcmm_get_config(struct vcmmd_ve_config *c,
		unsigned long *mem, unsigned long *swap, unsigned long *guar)
{
	vcmmd_ve_config_init(c);
	char s[STR_SIZE] = "";
	char *sp = s;

	if (mem != NULL) {
		vcmmd_ve_config_append(c, VCMMD_VE_CONFIG_LIMIT, *mem);
		sp += sprintf(sp, "memlimit=%lubytes ", *mem);
	}

	if (swap != NULL) {
		vcmmd_ve_config_append(c, VCMMD_VE_CONFIG_SWAP, *swap);
		sp += sprintf(sp, "swaplimit=%lubytes ", *swap);
	}

	if (guar != NULL) {
		vcmmd_ve_config_append(c, VCMMD_VE_CONFIG_GUARANTEE, *guar);
		sp += sprintf(sp, "guarantee=%lubytes", *guar);
	}

	logger(1, 0, "Configure %s", s);

	return c;
}

static int vcmm_get_param(const char *id, unsigned long *mem,
		unsigned long *guar)
{
	int rc;
	struct vcmmd_ve_config c;

	vcmmd_ve_config_init(&c);
	rc = vcmmd_get_ve_config(id, &c);
	if (rc)
		return vcmm_error(rc, "vcmmd_get_ve_config");

	if (!vcmmd_ve_config_extract(&c, VCMMD_VE_CONFIG_LIMIT, mem))
		return vzctl_err(VZCTL_E_VCMM, 0,
			"Unable to get VCMMD_VE_CONFIG_LIMIT parameter");

	if (!vcmmd_ve_config_extract(&c, VCMMD_VE_CONFIG_GUARANTEE, guar))
		*guar = 0;

	logger(5, 0, "vcmmd CT configuration mem=%lu guar=%lu",	*mem, *guar);

	return 0;
}

static int get_vcmm_config(const char *id, struct vcmmd_ve_config *c,
		struct vzctl_ub_param *ub, struct vzctl_mem_guarantee *guar,
		int init)
{
	int ret;
	unsigned long *mem_p = NULL, *swap_p = NULL, *guar_p = NULL;
	unsigned long mem, swap, guar_bytes;
	unsigned long mem_cur, guar_bytes_cur;
	unsigned long x;
	struct vzctl_mem_guarantee guar_def = {
		.type = VZCTL_MEM_GUARANTEE_AUTO
	};

	if (init) {
		if (ub->physpages == NULL)
			return vzctl_err(VZCTL_E_INVAL, 0,
				"physpages parameter is not set");
		/* use default garanty if not set */
		if (guar == NULL)
			guar = &guar_def;
	} else if (ub->physpages == NULL || guar == NULL) {
		ret = vcmm_get_param(id, &mem_cur, &guar_bytes_cur);
		if (ret)
			return ret;
		if (ub->physpages == NULL)
			mem = mem_cur;
	}

	if (ub->physpages != NULL) {
		mem = ub->physpages->l * get_pagesize();
		mem_p = &mem;
		/* scale guaranty on memlimit chage */
		if (guar == NULL) {
			guar_def.type = DEFAULT_MEM_GUARANTEE_PCT;
			guar_def.value = ((float)guar_bytes_cur / mem_cur) * 100;
			guar = &guar_def;
		}
	}

	if (ub->swappages != NULL) {
		swap = ub->swappages->l * get_pagesize();
		swap_p = &swap;
	}

	if (guar != NULL) {
		x = (guar->type == VZCTL_MEM_GUARANTEE_AUTO) ?
				DEFAULT_MEM_GUARANTEE_PCT : guar->value;

		guar_bytes = ((float)mem * x) / 100;

		logger(0, 0, "Configure memguarantee %lu%%", x);
		guar_p = &guar_bytes;
	}

	vcmm_get_config(c, mem_p, swap_p, guar_p);

	return 0;
}

int is_managed_by_vcmmd(void)
{
	return access(VCMMCTL_BIN, F_OK) == 0;
}

int vcmm_unregister(struct vzctl_env_handle *h)
{
	int rc;

	if (!is_managed_by_vcmmd())
		return 0;

	logger(1, 0, "vcmmd: unregister");
	rc = vcmmd_unregister_ve(EID(h));
	if (rc && rc != VCMMD_ERROR_VE_NOT_REGISTERED)
		return vcmm_error(rc, "failed to unregister Container");

	return 0;
}

int vcmm_register(struct vzctl_env_handle *h, struct vzctl_ub_param *ub,
		struct vzctl_mem_guarantee *guar)
{
	int rc;
	struct vcmmd_ve_config c;

	if (!is_managed_by_vcmmd())
		return 0;

	rc = get_vcmm_config(EID(h), &c, ub, guar, 1);
	if (rc)
		return rc;

	logger(1, 0, "vcmmd: register");
	rc = vcmmd_register_ve(EID(h), VCMMD_VE_CT, &c, 0);
	if (rc == VCMMD_ERROR_VE_NAME_ALREADY_IN_USE) {
		vcmm_unregister(h);
		rc = vcmmd_register_ve(EID(h), VCMMD_VE_CT, &c, 0);
	}
	if (rc)
		return vcmm_error(rc, "failed to register Container");

	logger(1, 0, "vcmmd: activate");
	rc = vcmmd_activate_ve(EID(h), 0);
	if (rc)
		return vcmm_error(rc, "failed to activate Container");

	return 0;
}

int vcmm_update(struct vzctl_env_handle *h, struct vzctl_ub_param *ub,
		struct vzctl_mem_guarantee *guar)
{
	int rc;
	struct vcmmd_ve_config c = {};

	if (ub->physpages == NULL && ub->swappages == NULL && guar == NULL)
		return 0;

	logger(1, 0, "vcmmd: update");
	rc = get_vcmm_config(EID(h), &c, ub, guar, 0);
	if (rc)
		return rc;

	rc = vcmmd_update_ve(EID(h), &c, 0);
	if (rc)
		return vcmm_error(rc, "failed to update Container configuration");

	return 0;
}
