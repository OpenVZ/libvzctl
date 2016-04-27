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

#ifndef	_RES_H_
#define _RES_H_
#include "ub.h"
#include "slm.h"

enum {
	MM_UBC = 0,
	MM_SLM,
	MM_VSWAP,
};

struct vzctl_res_param {
	unsigned long *ramsize;
	struct vzctl_mem_guarantee *memguar;
	struct vzctl_ub_param *ub;
	struct vzctl_slm_param *slm;
};
struct vzctl_env_handle;
struct vzctl_env_param;

#ifdef __cplusplus
extern "C" {
#endif
int get_conf_mm_mode(struct vzctl_res_param *res);
void free_res_param(struct vzctl_res_param *res);
struct vzctl_res_param *alloc_res_param();
int merge_res(struct vzctl_res_param *dst, struct vzctl_res_param *src,
	int mode);
int get_vswap_param(struct vzctl_env_handle *h, struct vzctl_env_param *env,
	struct vzctl_ub_param **out);
int check_res_requires(struct vzctl_env_param *env);
int vzctl_res_setup_post(struct vzctl_env_handle *h);
int vzctl_res_configure(struct vzctl_env_handle *h, struct vzctl_env_param *env, int flags);
int dump_resources_failcnt(ctid_t ctid);
#ifdef __cplusplus
}
#endif
#endif /* _RES_H_ */
