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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <linux/vzcalluser.h>
#include <linux/beancounter.h>

#include "vzctl.h"
#include "ub.h"
#include "vzctl_param.h"
#include "vzerror.h"
#include "logger.h"
#include "vzsyscalls.h"
#include "vztypes.h"
#include "env.h"
#include "util.h"

#define UB_IPTENTRIES  23      /* Number of iptables rules */

static int setublimit(unsigned veid, int id,
	const struct vzctl_2UL_res *res)
{
	unsigned long limit[2];

	limit[0] = res->b;
	limit[1] = res->l;
	if (limit[0] > LONG_MAX)
		limit[0] = LONG_MAX;
	if (limit[1] > LONG_MAX)
		limit[1] = LONG_MAX;

	return syscall(__NR_setublimit, veid, (unsigned long)id, limit);
}

static struct ubname2id {
	char *name;
	unsigned int id;
	unsigned int paramid;
} ubname2id[] = {
	{"KMEMSIZE",	UB_KMEMSIZE,	VZCTL_PARAM_KMEMSIZE},
	{"LOCKEDPAGES",	UB_LOCKEDPAGES,	VZCTL_PARAM_LOCKEDPAGES},
	{"PRIVVMPAGES",	UB_PRIVVMPAGES,	VZCTL_PARAM_PRIVVMPAGES},
	{"SHMPAGES",	UB_SHMPAGES,	VZCTL_PARAM_SHMPAGES},
	{"NUMPROC",	UB_NUMPROC,	VZCTL_PARAM_NUMPROC},
	{"PHYSPAGES",	UB_PHYSPAGES,	VZCTL_PARAM_PHYSPAGES},
	{"VMGUARPAGES",	UB_VMGUARPAGES,	VZCTL_PARAM_VMGUARPAGES},
	{"OOMGUARPAGES",UB_OOMGUARPAGES,VZCTL_PARAM_OOMGUARPAGES},
	{"NUMTCPSOCK",	UB_NUMTCPSOCK,	VZCTL_PARAM_NUMTCPSOCK},
	{"NUMFLOCK",	UB_NUMFLOCK,	VZCTL_PARAM_NUMFLOCK},
	{"NUMPTY",	UB_NUMPTY,	VZCTL_PARAM_NUMPTY},
	{"NUMSIGINFO",	UB_NUMSIGINFO,	VZCTL_PARAM_NUMSIGINFO},
	{"TCPSNDBUF",	UB_TCPSNDBUF,	VZCTL_PARAM_TCPSNDBUF},
	{"TCPRCVBUF",	UB_TCPRCVBUF,	VZCTL_PARAM_TCPRCVBUF},
	{"OTHERSOCKBUF",UB_OTHERSOCKBUF,VZCTL_PARAM_OTHERSOCKBUF},
	{"DGRAMRCVBUF",	UB_DGRAMRCVBUF,	VZCTL_PARAM_DGRAMRCVBUF},
	{"NUMOTHERSOCK",UB_NUMOTHERSOCK,VZCTL_PARAM_NUMOTHERSOCK},
	{"NUMFILE",	UB_NUMFILE,	VZCTL_PARAM_NUMFILE},
	{"DCACHESIZE",	UB_DCACHESIZE,	VZCTL_PARAM_DCACHESIZE},
	{"NUMIPTENT",	UB_IPTENTRIES,	VZCTL_PARAM_NUMIPTENT},
	{"SWAPPAGES",	UB_SWAPPAGES,	VZCTL_PARAM_SWAPPAGES},
	{NULL, 0},
};

/** Check that all required UBC parameters are specified.
 *
 * @param ub		UBC parameters.
 * @return		0 on success.
 */
int vzctl_check_ub(struct vzctl_ub_param *ub)
{
	int ret = 0;

#define CHECK_UB(name)						\
if (ub->name == NULL)						\
	ret = vzctl_err(VZCTL_E_NOT_ENOUGH_PARAMS, 0,		\
			"UB parameter " #name " not set");	\

	CHECK_UB(lockedpages)
	CHECK_UB(privvmpages)
	CHECK_UB(shmpages)
	CHECK_UB(numproc)
	CHECK_UB(physpages)
	CHECK_UB(vmguarpages)
	CHECK_UB(numflock)
	CHECK_UB(numpty)
	CHECK_UB(numsiginfo)
	CHECK_UB(numfile)
	CHECK_UB(numiptent)
#undef CHECK_UB

	return ret;
}

int is_ub_empty(const struct vzctl_ub_param *ub)
{
	if (ub == NULL)
		return 1;
#define CHECK_UB(name)	if (ub->name != NULL) return 0;

	CHECK_UB(lockedpages)
	CHECK_UB(privvmpages)
	CHECK_UB(shmpages)
	CHECK_UB(numproc)
	CHECK_UB(physpages)
	CHECK_UB(vmguarpages)
	CHECK_UB(numtcpsock)
	CHECK_UB(numflock)
	CHECK_UB(numpty)
	CHECK_UB(numsiginfo)
	CHECK_UB(tcpsndbuf)
	CHECK_UB(tcprcvbuf)
	CHECK_UB(othersockbuf)
	CHECK_UB(dgramrcvbuf)
	CHECK_UB(numothersock)
	CHECK_UB(numfile)
	CHECK_UB(numiptent)
	CHECK_UB(swappages)
#undef CHECK_UB

	return 1;
}

static const char *get_ub_name(int res_id)
{
	int i;

	for (i = 0; ubname2id[i].name != NULL; i++)
		if (ubname2id[i].id == res_id)
			return ubname2id[i].name;
        return NULL;
}

const char *get_ub_param_name(int id)
{
	int i;

	for (i = 0; ubname2id[i].name != NULL; i++)
		if (ubname2id[i].paramid == id)
			return ubname2id[i].name;
	return "";
}

const struct vzctl_2UL_res *vzctl_get_ub_res(struct vzctl_ub_param *ub, int id)
{
#define GET_UB_RES(name, res_id)	if (res_id == id) return ub->name;

	GET_UB_RES(lockedpages, VZCTL_PARAM_LOCKEDPAGES)
	GET_UB_RES(privvmpages, VZCTL_PARAM_PRIVVMPAGES)
	GET_UB_RES(shmpages, VZCTL_PARAM_SHMPAGES)
	GET_UB_RES(numproc, VZCTL_PARAM_NUMPROC)
	GET_UB_RES(physpages, VZCTL_PARAM_PHYSPAGES)
	GET_UB_RES(vmguarpages, VZCTL_PARAM_VMGUARPAGES)
	GET_UB_RES(numtcpsock, VZCTL_PARAM_NUMTCPSOCK)
	GET_UB_RES(numflock, VZCTL_PARAM_NUMFLOCK)
	GET_UB_RES(numpty, VZCTL_PARAM_NUMPTY)
	GET_UB_RES(numsiginfo, VZCTL_PARAM_NUMSIGINFO)
	GET_UB_RES(tcpsndbuf, VZCTL_PARAM_TCPSNDBUF)
	GET_UB_RES(tcprcvbuf, VZCTL_PARAM_TCPRCVBUF)
	GET_UB_RES(othersockbuf, VZCTL_PARAM_OTHERSOCKBUF)
	GET_UB_RES(dgramrcvbuf, VZCTL_PARAM_DGRAMRCVBUF)
	GET_UB_RES(numothersock, VZCTL_PARAM_NUMOTHERSOCK)
	GET_UB_RES(numfile, VZCTL_PARAM_NUMFILE)
	GET_UB_RES(numiptent, VZCTL_PARAM_NUMIPTENT)
	GET_UB_RES(avnumproc, VZCTL_PARAM_AVNUMPROC)
	GET_UB_RES(swappages, VZCTL_PARAM_SWAPPAGES)
#undef GET_UB_RES
	return NULL;
}

int set_ub_limit(unsigned veid, int id, struct vzctl_2UL_res *res)
{
	if (res != NULL) {
		logger(3, 0, "%s %lu:%lu",
				get_ub_name(id), res->b, res->l);
		if (setublimit(veid, id, res)) {
			return vzctl_err(VZCTL_E_SETUBC, errno,
					"setublimit %s %lu:%lu failed",
					get_ub_name(id), res->b, res->l);
		}
	}
	return 0;
}

int set_ub(unsigned veid, const struct vzctl_ub_param *ub)
{

#define SET_UB_LIMIT(name, id)						\
if (ub->name != NULL) {							\
	logger(3, 0, "%s %lu:%lu", \
		get_ub_name(id), ub->name->l, ub->name->b); \
	if (setublimit(veid, id, ub->name)) {				\
		return vzctl_err(VZCTL_E_SETUBC, errno,		\
			"setublimit %s %lu:%lu failed",			\
			get_ub_name(id), ub->name->l, ub->name->b);	\
	}								\
}

	SET_UB_LIMIT(lockedpages, UB_LOCKEDPAGES)
	SET_UB_LIMIT(privvmpages, UB_PRIVVMPAGES)
	SET_UB_LIMIT(shmpages, UB_SHMPAGES)
	SET_UB_LIMIT(numproc, UB_NUMPROC)
	SET_UB_LIMIT(physpages, UB_PHYSPAGES)
	SET_UB_LIMIT(vmguarpages, UB_VMGUARPAGES)
	SET_UB_LIMIT(numtcpsock, UB_NUMTCPSOCK)
	SET_UB_LIMIT(numflock, UB_NUMFLOCK)
	SET_UB_LIMIT(numpty, UB_NUMPTY)
	SET_UB_LIMIT(numsiginfo, UB_NUMSIGINFO)
	SET_UB_LIMIT(tcpsndbuf, UB_TCPSNDBUF )
	SET_UB_LIMIT(tcprcvbuf, UB_TCPRCVBUF)
	SET_UB_LIMIT(othersockbuf, UB_OTHERSOCKBUF)
	SET_UB_LIMIT(dgramrcvbuf, UB_DGRAMRCVBUF)
	SET_UB_LIMIT(numothersock, UB_NUMOTHERSOCK)
	SET_UB_LIMIT(numfile, UB_NUMFILE)
	SET_UB_LIMIT(numiptent, UB_IPTENTRIES)
	SET_UB_LIMIT(swappages, UB_SWAPPAGES)
#undef SET_UB_LIMIT

	return 0;
}

int env_ub_set_unl(unsigned veid)
{
	int i;
	struct vzctl_2UL_res res = {LONG_MAX, LONG_MAX};

	for (i = 0; i <= 23; i++)
		setublimit(veid, i, &res);
	res.b = 0; res.l = 0;
	setublimit(veid, UB_SWAPPAGES, &res);
	return 0;
}

void free_ub_param(struct vzctl_ub_param *ub)
{
	if (ub == NULL)
		return;
	xfree(ub->lockedpages);
	xfree(ub->privvmpages);
	xfree(ub->shmpages);
	xfree(ub->numproc);
	xfree(ub->physpages);
	xfree(ub->vmguarpages);
	xfree(ub->numtcpsock);
	xfree(ub->numflock);
	xfree(ub->numpty);
	xfree(ub->numsiginfo);
	xfree(ub->tcpsndbuf);
	xfree(ub->tcprcvbuf);
	xfree(ub->othersockbuf);
	xfree(ub->dgramrcvbuf);
	xfree(ub->numothersock);
	xfree(ub->numfile);
	xfree(ub->numiptent);
	xfree(ub->avnumproc);
	xfree(ub->swappages);
	xfree(ub->vm_overcommit);
	free(ub);
}

struct vzctl_ub_param *alloc_ub_param(void)
{
	return calloc(1, sizeof(struct vzctl_ub_param));
}

/** Add UBC resource in struct vzctl_2UL_res format
 *
 * @param ub            UBC parameters.
 * @param res           UBC resource in struct vzctl_2UL_res format.
 * @return              0 on success.
 */

int vzctl_add_ub_param(struct vzctl_ub_param *ub, int id,
		struct vzctl_2UL_res *res)
{
#define ADD_UB_PARAM(name, resid) \
if (resid == id) { \
	if (ub->name == NULL) { \
		ub->name = malloc(sizeof(struct vzctl_2UL_res)); \
		if (ub->name == NULL) \
			return VZCTL_E_NOMEM; \
	} \
	memcpy(ub->name, res, sizeof(struct vzctl_2UL_res)); \
	return 0; \
}

	ADD_UB_PARAM(lockedpages, VZCTL_PARAM_LOCKEDPAGES)
	ADD_UB_PARAM(privvmpages, VZCTL_PARAM_PRIVVMPAGES)
	ADD_UB_PARAM(shmpages, VZCTL_PARAM_SHMPAGES)
	ADD_UB_PARAM(numproc, VZCTL_PARAM_NUMPROC)
	ADD_UB_PARAM(physpages, VZCTL_PARAM_PHYSPAGES)
	ADD_UB_PARAM(vmguarpages, VZCTL_PARAM_VMGUARPAGES)
	ADD_UB_PARAM(numtcpsock, VZCTL_PARAM_NUMTCPSOCK)
	ADD_UB_PARAM(numflock, VZCTL_PARAM_NUMFLOCK)
	ADD_UB_PARAM(numpty, VZCTL_PARAM_NUMPTY)
	ADD_UB_PARAM(numsiginfo, VZCTL_PARAM_NUMSIGINFO)
	ADD_UB_PARAM(tcpsndbuf, VZCTL_PARAM_TCPSNDBUF)
	ADD_UB_PARAM(tcprcvbuf, VZCTL_PARAM_TCPRCVBUF)
	ADD_UB_PARAM(othersockbuf, VZCTL_PARAM_OTHERSOCKBUF)
	ADD_UB_PARAM(dgramrcvbuf, VZCTL_PARAM_DGRAMRCVBUF)
	ADD_UB_PARAM(numothersock, VZCTL_PARAM_NUMOTHERSOCK)
	ADD_UB_PARAM(numfile, VZCTL_PARAM_NUMFILE)
	ADD_UB_PARAM(numiptent, VZCTL_PARAM_NUMIPTENT)
	ADD_UB_PARAM(avnumproc, VZCTL_PARAM_AVNUMPROC)
	ADD_UB_PARAM(swappages, VZCTL_PARAM_SWAPPAGES)
	return VZCTL_E_INVAL;
#undef ADD_UB_PARAM
}

int merge_ub(struct vzctl_ub_param *dst, struct vzctl_ub_param *src)
{
#define MERGE_P2(x)						\
if ((src->x) != NULL) {						\
	if ((dst->x) == NULL) {					\
		dst->x = malloc(sizeof(*(dst->x)));		\
		if (dst->x == NULL) return VZCTL_E_NOMEM;	\
	}							\
	memcpy(dst->x, src->x, sizeof(*(dst->x)));		\
}

	MERGE_P2(lockedpages)
	MERGE_P2(privvmpages)
	MERGE_P2(shmpages)
	MERGE_P2(numproc)
	MERGE_P2(physpages)
	MERGE_P2(vmguarpages)
	MERGE_P2(numtcpsock)
	MERGE_P2(numflock)
	MERGE_P2(numpty)
	MERGE_P2(numsiginfo)
	MERGE_P2(tcpsndbuf)
	MERGE_P2(tcprcvbuf)
	MERGE_P2(othersockbuf)
	MERGE_P2(dgramrcvbuf)
	MERGE_P2(numothersock)
	MERGE_P2(numfile)
	MERGE_P2(numiptent)
	MERGE_P2(avnumproc)
	MERGE_P2(swappages)
	if (src->vm_overcommit != NULL) {
		if (dst->vm_overcommit == NULL)
			dst->vm_overcommit = malloc(sizeof(float));
		*dst->vm_overcommit = *src->vm_overcommit;
	}
	return 0;
#undef MERGE_P2
}

int parse_ub(struct vzctl_ub_param *ub, const char *val, int id,
	int divisor, int def_divisor)
{
	int ret;
	struct vzctl_2UL_res res;

	ret = parse_twoul_sfx(val, &res, divisor, def_divisor);
	if (ret && ret != VZCTL_E_LONG_TRUNC)
		return ret;
	ret = vzctl_add_ub_param(ub, id, &res);
	return ret;
}

