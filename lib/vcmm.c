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
#ifdef USE_VCMMD
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
#include "bitmap.h"
#include "cgroup.h"

#define VCMMCTL_BIN     "/usr/sbin/vcmmdctl"
static int vcmm_error(int rc, const char *msg)
{
	char buf[STR_SIZE];

	return vzctl_err(VZCTL_E_VCMM, 0, "vcmmd: %s: %s",
			msg, vcmmd_strerror(rc, buf, sizeof(buf)));
}

static struct vcmmd_ve_config *vcmm_get_config(struct vzctl_env_handle *h,
		struct vcmmd_ve_config *c, unsigned long *mem,
		unsigned long *swap, unsigned long *guar,
		struct vzctl_env_param *env)
{
	vcmmd_ve_config_init(c);
	char s[STR_SIZE];

	if (mem != NULL) {
		vcmmd_ve_config_append(c, VCMMD_VE_CONFIG_LIMIT, *mem);
		logger(1, 0, "Configure memlimit: %lubytes", *mem);
	}

	if (swap != NULL) {
		vcmmd_ve_config_append(c, VCMMD_VE_CONFIG_SWAP, *swap);
		logger(1, 0, "Configure swaplimit: %lubytes", *swap);
	}

	if (guar != NULL) {
		vcmmd_ve_config_append(c, VCMMD_VE_CONFIG_GUARANTEE, *guar);
		logger(1, 0, "Configure guarantee: %lubytes", *guar);
	}

	struct vzctl_cpumask *cpumask = env->cpu->cpumask ?:
					h->env_param->cpu->cpumask;
	if (cpumask != NULL) {
		if (bitmap_all_bit_set(cpumask->mask,
				sizeof(env->cpu->cpumask->mask)))
			s[0] = '\0';
		else
			bitmap_snprintf(s, sizeof(s), cpumask->mask, 
				sizeof(env->cpu->cpumask->mask));
		vcmmd_ve_config_append_string(c, VCMMD_VE_CONFIG_CPU_LIST, s);
		logger(1, 0, "Configure cpumask: %s", s);
	}

	struct vzctl_nodemask *nodemask = env->cpu->nodemask ?:
					h->env_param->cpu->nodemask;
	if (nodemask != NULL) {
		if (bitmap_all_bit_set(nodemask->mask,
					sizeof(env->cpu->nodemask->mask)))
			s[0] = '\0';
		else
			bitmap_snprintf(s, sizeof(s), nodemask->mask, 
				sizeof(env->cpu->nodemask->mask));
		vcmmd_ve_config_append_string(c, VCMMD_VE_CONFIG_NODE_LIST, s);
		logger(1, 0, "Configure nodemask: %s", s);
	}

	return c;
}

int vcmm_get_param(const char *id, unsigned long *mem,
		unsigned long *swap, unsigned long *guar)
{
	int rc;
	struct vcmmd_ve_config c;

	vcmmd_ve_config_init(&c);
	rc = vcmmd_get_ve_config(id, &c);
	if (rc)
		return vcmm_error(rc, "vcmmd_get_ve_config");

	if (!vcmmd_ve_config_extract(&c, VCMMD_VE_CONFIG_LIMIT, mem)) {
		vcmmd_ve_config_deinit(&c);
		return vzctl_err(VZCTL_E_VCMM, 0,
			"Unable to get VCMMD_VE_CONFIG_LIMIT parameter");
	}

	if (!vcmmd_ve_config_extract(&c, VCMMD_VE_CONFIG_SWAP, swap))
		*swap = 0;

	if (!vcmmd_ve_config_extract(&c, VCMMD_VE_CONFIG_GUARANTEE, guar))
		*guar = 0;

	logger(5, 0, "vcmmd CT configuration mem=%lu swap=%lu guar=%lu",
			*mem, *swap, *guar);

	vcmmd_ve_config_deinit(&c);
	return 0;
}

static int get_vcmm_config(struct vzctl_env_handle *h,
		struct vcmmd_ve_config *c, struct vzctl_env_param *env,
		struct vzctl_ub_param *ub, int init)
{
	int ret;
	unsigned long *mem_p = NULL, *swap_p = NULL, *guar_p = NULL;
	unsigned long mem, swap, guar_bytes;
	unsigned long mem_cur, guar_bytes_cur = 0;
	unsigned long x;
	struct vzctl_mem_guarantee *guar = env->res->memguar;
	struct vzctl_mem_guarantee guar_def = {
		.type = VZCTL_MEM_GUARANTEE_AUTO
	};

	if (!init && (ub->physpages == NULL || guar == NULL)) {
		ret = vcmm_get_param(EID(h), &mem_cur, &x, &guar_bytes_cur);
		if (ret)
			return ret;
		if (ub->physpages == NULL)
			mem = mem_cur;
	}

	if (ub->physpages != NULL) {
		mem = ub->physpages->l * get_pagesize();
		mem_p = &mem;
		/* scale guaranty on memlimit change */
		if (guar == NULL && guar_bytes_cur != 0 &&
			h->env_param->res->memguar != NULL &&
			h->env_param->res->memguar->type == VZCTL_MEM_GUARANTEE_PCT)
		{
			guar_def.type = VZCTL_MEM_GUARANTEE_PCT;
			if (mem_cur)
				guar_def.value = ((float)guar_bytes_cur / mem_cur) * 100;
			guar = &guar_def;
		}
	}

	if (ub->swappages != NULL) {
		swap = ub->swappages->l * get_pagesize();
		swap_p = &swap;
	}

	if (guar != NULL) {
		switch (guar->type) {
		case VZCTL_MEM_GUARANTEE_AUTO:
			guar_bytes = 0;
			break;
		case VZCTL_MEM_GUARANTEE_PCT:
			logger(0, 0, "Configure memguarantee: %lu%%", guar->value);
			guar_bytes = ((float)mem * guar->value) / 100;
			break;
		case VZCTL_MEM_GUARANTEE_BYTES:
			guar_bytes = guar->value;
			break;
		}
		guar_p = &guar_bytes;
	}

	vcmm_get_config(h, c, mem_p, swap_p, guar_p, env);

	return 0;
}

int is_managed_by_vcmmd(void)
{
	/* FIXME temporary disable vcmmd it should also switch to cgroup v2 */
	if (is_cgroup_v2())
		return 0;

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

int vcmm_register(struct vzctl_env_handle *h, struct vzctl_env_param *env,
		struct vzctl_ub_param *ub)
{
	int rc;
	struct vcmmd_ve_config c;

	if (!is_managed_by_vcmmd())
		return 0;

	rc = get_vcmm_config(h, &c, env, ub, 1);
	if (rc)
		return rc;

	logger(1, 0, "vcmmd: register");
	rc = vcmmd_register_ve(EID(h), VCMMD_VE_CT, &c, 0);
	if (rc == VCMMD_ERROR_VE_NAME_ALREADY_IN_USE) {
		vcmm_unregister(h);
		rc = vcmmd_register_ve(EID(h), VCMMD_VE_CT, &c, 0);
	}
	vcmmd_ve_config_deinit(&c);
	if (rc)
		return vcmm_error(rc, "failed to register Container");

	return 0;
}

int vcmm_activate(struct vzctl_env_handle *h)
{
	int rc;

	if (!is_managed_by_vcmmd())
		return 0;

	logger(1, 0, "vcmmd: activate");
	rc = vcmmd_activate_ve(EID(h), 0);
	if (rc)
		return vcmm_error(rc, "failed to activate Container");
	return 0;
}

int vcmm_update(struct vzctl_env_handle *h, struct vzctl_env_param *env)
{
	int rc;
	struct vcmmd_ve_config c = {};

	if (env->res->ub->physpages == NULL &&
			env->res->ub->swappages == NULL &&
			env->res->memguar == NULL &&
			env->cpu->cpumask == NULL &&
			env->cpu->nodemask == NULL &&
			env->res->memguar == NULL)
		return 0;

	logger(1, 0, "vcmmd: update");
	rc = get_vcmm_config(h, &c, env, env->res->ub, 0);
	if (rc)
		return rc;

	rc = vcmmd_update_ve(EID(h), &c, 0);
	vcmmd_ve_config_deinit(&c);
	if (rc)
		return vcmm_error(rc, "failed to update Container configuration");

	return 0;
}
#endif
