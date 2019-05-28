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
#include <limits.h>

#include "libvzctl.h"
#include "env.h"
#include "ub.h"
#include "res.h"
#include "vzerror.h"
#include "util.h"
#include "vzctl_param.h"
#include "vcmm.h"

void free_res_param(struct vzctl_res_param *res)
{
	if (res->ub != NULL)
		free_ub_param(res->ub);
	if (res->slm != NULL)
		free_slm_param(res->slm);
	free(res->ramsize);
	free(res->memguar);
	free(res);
}

struct vzctl_res_param *alloc_res_param()
{
	struct vzctl_res_param *res;

	if ((res = calloc(1, sizeof(struct vzctl_res_param))) == NULL)
		return NULL;
	if ((res->ub = alloc_ub_param()) == NULL)
		goto err;
	if ((res->slm = alloc_slm_param()) == NULL)
		goto err;

	 return res;
err:
	free_res_param(res);
	return NULL;
}

int dump_resources_failcnt(ctid_t ctid)
{
	FILE *fd;
	char buf[STR_SIZE];
	int cnt = 0;

	sprintf(buf, "/proc/bc/%s/resources", ctid);
	fd = fopen(buf, "r");
	if (fd == NULL)
		return 0;

	while (fgets(buf, sizeof(buf), fd) != NULL) {
		char n[64];
		unsigned long n1, n2, n3, n4, failcnt;

		if (sscanf(buf, "%63s%lu%lu%lu%lu%lu",
					n, &n1, &n2, &n3, &n4, &failcnt) != 6)
			continue;
		if (failcnt == 0)
			continue;

		logger(0, 0, "%s %lu %lu %lu %lu %lu",
				n, n1, n2, n3, n4, failcnt );
		cnt++;
	}
	fclose(fd);

	return cnt;
}

//----------------------------------------------------

static int get_ub_resources_proc(ctid_t ctid, unsigned long *ram, unsigned long *swap)
{
	FILE *fd;
	char str[STR_SIZE];
	char name[STR_SIZE];
	int res;
	unsigned long held, maxheld, barrier, limit;

	sprintf(str, "/proc/bc/%s/resources", ctid);
	fd = fopen(str, "r");
	if (fd == NULL)
		return 1;

	while (fgets(str, STR_SIZE, fd) != NULL) {
		if ((res = sscanf(str, "%s%lu%lu%lu%lu",
						name, &held, &maxheld, &barrier, &limit)) == 5)
		{
			if (!strcmp(name, "physpages")) {
				ram[0] = barrier;
				ram[1] = limit;
				ram[2] = held;
			} else if (!strcmp(name, "swappages")) {
				swap[0] = barrier;
				swap[1] = limit;
				swap[2] = held;
			}
		}
	}
	fclose(fd);
	return 0;
}

static int get_ub_resources(ctid_t ctid, unsigned long *ram,
		unsigned long *swap)
{
	int ret;
	unsigned long ram_bytes, swap_bytes, x;

	if (!is_managed_by_vcmmd())
		return get_ub_resources_proc(ctid, ram, swap);

	ret = vcmm_get_param(ctid, &ram_bytes, &swap_bytes, &x);
	if (ret)
		return ret;

	ram[0] = ram[1] = ram_bytes / get_pagesize();
	swap[0] = swap[1] = swap_bytes / get_pagesize();

	return 0;
}

int vzctl2_get_env_total_meminfo(unsigned long *limit_bytes, unsigned long *usage_bytes)
{
	int ret, i;
	unsigned long ram[3], swap[3];
	float limit = 0, usage = 0;
	vzctl_ids_t *ids;

	ids = vzctl2_alloc_env_ids();
	if (ids == NULL)
		return VZCTL_E_NOMEM;

	ret = vzctl2_get_env_ids_by_state(ids, ENV_STATUS_RUNNING);
	if (ret < 0) {
		vzctl2_free_env_ids(ids);
		return vzctl_err(VZCTL_E_SYSTEM, 0, "Faied to get thr running CT ids");
	}

	for (i = 0; i < ret; i++) {
		if (get_ub_resources_proc(ids->ids[i], ram, swap) == 0) {
			limit += ram[1];
			usage += ram[2];
		}
	}

	limit *= 4096;
	usage *= 4096;
	*limit_bytes = (unsigned long)(limit > ULONG_MAX ? ULONG_MAX : limit);
	*usage_bytes = (unsigned long)(usage > ULONG_MAX ? ULONG_MAX : usage);
	vzctl2_free_env_ids(ids);
	return 0;
}

#define ADD_VSWAP_PARAM(id, size) \
{	\
	if (size >= LONG_MAX)			\
		res.b = LONG_MAX;		\
	else					\
		res.b = size;			\
	res.l = res.b; \
	vzctl_add_ub_param(vswap_param, id, &res); \
}

#define ADD_VSWAP_PARAM2(id, size) \
{	\
	res.b = size[0] > LONG_MAX ? LONG_MAX : size[0]; \
	res.l = size[1] > LONG_MAX ? LONG_MAX : size[1]; \
	vzctl_add_ub_param(vswap_param, id, &res); \
}

static void fill_vswap_param(struct vzctl_env_handle *h, struct vzctl_ub_param *vswap_param,
		unsigned long *ram, unsigned long *swap, float overcommit)
{
	float memory;
	struct vzctl_2UL_res res;
	struct vzctl_ub_param *ub = h->env_param->res->ub;

	if (overcommit == LONG_MAX)
		logger(1, 0, "\tRAM: %lu Swap: %lu", ram[1], swap[1]);
	else
		logger(1, 0, "\tRAM: %lu Swap: %lu ovr: %2.2f",
				ram[1], swap[1], overcommit);

	ADD_VSWAP_PARAM2(VZCTL_PARAM_PHYSPAGES, ram)
	if (ub->swappages == NULL)
		ADD_VSWAP_PARAM2(VZCTL_PARAM_SWAPPAGES, swap)
	if (ub->lockedpages == NULL)
		ADD_VSWAP_PARAM(VZCTL_PARAM_LOCKEDPAGES, ram[1])

	if (ub->vmguarpages == NULL) {
		memory = ram[1] + swap[1];
		ADD_VSWAP_PARAM(VZCTL_PARAM_VMGUARPAGES, memory)
	}

	if (ub->privvmpages == NULL) {
		memory = (ram[1] + swap[1]) * overcommit;
		ADD_VSWAP_PARAM(VZCTL_PARAM_PRIVVMPAGES, memory)
	}
}

int get_conf_mm_mode(struct vzctl_res_param *res)
{
	struct vzctl_2UL_res *physpages = res->ub->physpages;
	struct vzctl_slm_memorylimit *slmmemorylimit = res->slm->memorylimit;

	if (physpages != NULL)
	{
                /* Representation of unlimited physpages
		 * PHYSPAGES 0:LONG_MAX
		 * PHYSPAGES LONG_MAX:LONG_MAX
		 */
		if ((physpages->b == 0 && physpages->l == LONG_MAX) ||
			(physpages->b == LONG_MAX && physpages->l == LONG_MAX))
		{
			if (slmmemorylimit != NULL &&
					(res->slm->mode == VZCTL_MODE_SLM ||
					 res->slm->mode == VZCTL_MODE_ALL))
				return MM_SLM;
			else if (res->ub->privvmpages != NULL)
				return MM_UBC;
		}
		return MM_VSWAP;
	} else if (slmmemorylimit != NULL &&
			res->slm->mode != VZCTL_MODE_UBC) {
		return MM_SLM;
	}
	return MM_UBC;
}

static int is_ub_unlimited(struct vzctl_2UL_res *ub)
{
	return (ub != NULL && ub->b == LONG_MAX && ub->l == LONG_MAX) ? 1 : 0;
}

/*
1. UBC with privvm, phys, oomguar, vmguar and locked pages
2. SLM with slmmemorylimit (soft and hard)
3. VSwap with RAM, Swap and Overcommit
   Overcommit denotes how much virtual memory (not physical) can a
   container have. It can be thought of like an alias for privvmpages
   parameter.

In order to configure VSwap user needs to specify RAM and Swap.
By default other parameters are set like this
* Overcommit = Privvmpages = RAM + Swap
* Lockedpages = Oomguarpages = RAM
* Vmguarpages = RAM + Swap

When we have UBC configuration VSwap should be re-calculated this way:
* RAM = Privvmpages.soft
* Swap = 0
* Overcommit = Privvmpages.hard

When we have SLM configuration VSwap is re-calculated like:
* RAM = slmmemorylimit
* Swap = 0
* Overcommit = slmmemorylimit * 1.5 (unless there exists UBC params)
*/
static int update_vswap_param(struct vzctl_env_handle *h, struct vzctl_env_param *env,
		struct vzctl_ub_param *vswap_param)
{
	int changed = 0;
	unsigned long ram[3] = {};
	unsigned long swap[3] = {};
	float overcommit = LONG_MAX;
	struct vzctl_ub_param *ub = env->res->ub;
	struct vzctl_2UL_res res;

	switch(get_conf_mm_mode(h->env_param->res)) {
	case MM_VSWAP:
		if (h->env_param->res->slm->memorylimit != NULL)
			logger(0, 0, "Warning: the old slmmemorylimit=%lu parameter is skipped.",
					h->env_param->res->slm->memorylimit->quality);

		if (h->env_param->res->ub->vm_overcommit != NULL &&
				*h->env_param->res->ub->vm_overcommit != 0)
		{
			overcommit = *h->env_param->res->ub->vm_overcommit;
		}

		if (ub->physpages == NULL || ub->swappages == NULL)
			get_ub_resources(EID(h), ram, swap);

		if (ub->physpages != NULL) {
			ram[0] = ub->physpages->b;
			ram[1] = ub->physpages->l;
			changed = 1;
		}
		if (ub->swappages != NULL) {
			swap[0] = ub->swappages->b;
			swap[1] = ub->swappages->l;
			changed = 1;
		}
		if (ub->vm_overcommit != NULL && *ub->vm_overcommit != 0) {
			overcommit = *ub->vm_overcommit;
			changed = 1;
		}

		if (changed)
			fill_vswap_param(h, vswap_param, ram, swap, overcommit);
		break;
	case MM_SLM:
		logger(3, 0, "Warning: VSwap_slm compatiblity mode");

		if (ub->physpages == NULL || ub->swappages == NULL)
			get_ub_resources(EID(h), ram, swap);

		if (env->res->slm->memorylimit != NULL) {
			ram[0] = env->res->slm->memorylimit->quality / 4096;
			ram[1] = env->res->slm->memorylimit->quality / 4096;
			changed = 1;
			// Set unlimited PRIVVMPAGES bug #PSBM-10224
			ADD_VSWAP_PARAM(VZCTL_PARAM_PRIVVMPAGES, LONG_MAX)
		} else if (env->res->slm->mode == VZCTL_MODE_ALL) {
			if (ub->privvmpages != NULL) {
				ram[0] = ub->privvmpages->b;
				ram[1] = ub->privvmpages->l;
				changed = 1;
			}
			if (ub->swappages != NULL) {
				swap[0] = ub->swappages->b;
				swap[1] = ub->swappages->l;
				changed = 1;
			}
		}
		// Drop unlimited *GUARPAGES
		if (is_ub_unlimited(ub->vmguarpages))
			ADD_VSWAP_PARAM2(VZCTL_PARAM_VMGUARPAGES, ram)

		if (changed)
			fill_vswap_param(h, vswap_param, ram, swap, 1.0);
		break;
	default:
		if (ub->physpages == NULL || ub->swappages == NULL)
			get_ub_resources(EID(h), ram, swap);

		if (ub->physpages != NULL && !is_ub_unlimited(ub->physpages)) {
			ram[0] = ub->physpages->b;
			ram[1] = ub->physpages->l;
			changed = 1;
		} else if (ub->privvmpages != NULL) {
			ram[0] = ub->privvmpages->b;
			ram[1] = ub->privvmpages->l;
			changed = 1;
		}

		if (ub->swappages != NULL) {
			swap[0] = ub->swappages->b;
			swap[1] = ub->swappages->l;
			changed = 1;
		}

		if (changed)
			fill_vswap_param(h, vswap_param, ram, swap, 1.0);

		break;
	}

	return 0;
}

int get_vswap_param(struct vzctl_env_handle *h, struct vzctl_env_param *env,
		struct vzctl_ub_param **out)
{
	struct vzctl_ub_param *ub;
	int ret;

	ub = alloc_ub_param();
	if (ub == NULL)
		return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "alloc_ub");

	ret = merge_ub(ub, env->res->ub);
	if (ret)
		goto err;

	ret = update_vswap_param(h, env, ub);
	if (ret)
		goto err;

	*out = ub;

	return 0;
err:
	free_ub_param(ub);

	return ret;
}

static int mm_check_param(struct vzctl_res_param *res)
{
	int ret = 0;

	switch(get_conf_mm_mode(res)) {
	case MM_VSWAP:
		if (res->ub->physpages == NULL)
			return vzctl_err(VZCTL_E_NOT_ENOUGH_PARAMS, 0,
				"Resource parameter phsypages is not set");
		break;
	case MM_SLM:
		if (res->slm->mode == VZCTL_MODE_SLM &&
				res->slm->memorylimit == NULL)
			return vzctl_err(VZCTL_E_NOT_ENOUGH_PARAMS, 0,
					"Resource parameter slmmemorylimit is not set");
		break;
	default:
		ret = vzctl_check_ub(res->ub);
		break;
	}
	return ret;
}

int check_res_requires(struct vzctl_env_param *env)
{
	return mm_check_param(env->res);
}
