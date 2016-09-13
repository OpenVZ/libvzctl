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

#ifndef	_UB_H_
#define	_UB_H_

#define PROCUBC		"/proc/user_beancounters"

struct vzctl_ub_param {
	struct vzctl_2UL_res *lockedpages;
	struct vzctl_2UL_res *privvmpages;
	struct vzctl_2UL_res *shmpages;
	struct vzctl_2UL_res *numproc;
	struct vzctl_2UL_res *physpages;
	struct vzctl_2UL_res *vmguarpages;
	struct vzctl_2UL_res *numtcpsock;
	struct vzctl_2UL_res *numflock;
	struct vzctl_2UL_res *numpty;
	struct vzctl_2UL_res *numsiginfo;
	struct vzctl_2UL_res *tcpsndbuf;
	struct vzctl_2UL_res *tcprcvbuf;
	struct vzctl_2UL_res *othersockbuf;
	struct vzctl_2UL_res *dgramrcvbuf;
	struct vzctl_2UL_res *numothersock;
	struct vzctl_2UL_res *numfile;
	struct vzctl_2UL_res *numiptent;
	struct vzctl_2UL_res *avnumproc;
	struct vzctl_2UL_res *swappages;
	float *vm_overcommit;
	int pagecache_isolation;
};
//typedef struct vzctl_ub_param vzctl_ub_param_t;

#ifdef __cplusplus
extern "C" {
#endif

/** Add UBC resource in struct vzctl_2UL_res format
 *
 * @param ub		UBC parameters.
 * @param res		UBC resource in struct vzctl_2UL_res format.
 * @return		0 on success.
 */
int vzctl_add_ub_param(struct vzctl_ub_param *ub, int id,
	struct vzctl_2UL_res *res);

const struct vzctl_2UL_res *vzctl_get_ub_res(struct vzctl_ub_param *ub, int id);
void free_ub_param(struct vzctl_ub_param *ub);
struct vzctl_ub_param *alloc_ub_param(void);
int set_ub(unsigned veid, const struct vzctl_ub_param *ub);
int merge_ub(struct vzctl_ub_param *dst, struct vzctl_ub_param *src);

int is_ub_empty(const struct vzctl_ub_param *ub);
int vzctl_check_ub(struct vzctl_ub_param *ub);
int env_ub_set_unl(unsigned veid);
int env_set_ub(unsigned veid, const struct vzctl_ub_param *ub);
int parse_ub(struct vzctl_ub_param *ub, const char *val, int id,
		int divisor, int def_devisor);
const struct vzctl_2UL_res *vzctl_get_ub_res(struct vzctl_ub_param *ub, int id);
const char *get_ub_param_name(int id);
#ifdef __cplusplus
}
#endif

#endif
