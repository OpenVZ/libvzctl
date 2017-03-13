/*
 *  Copyright (c) 1999-2017, Parallels International GmbH
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
 *
 */

#ifndef _CPT_H_
#define _CPT_H_
#define PROC_CPT	"/proc/cpt"
#define PROC_RST	"/proc/rst"

struct vzctl_env_handle;
struct start_param;

#ifdef __cplusplus
extern "C" {
#endif

int vz_env_cpt_cmd(struct vzctl_env_handle *h, int action, int cmd,
		struct vzctl_cpt_param *param, int flags);
int vz_env_chkpnt(struct vzctl_env_handle *h, int cmd, struct vzctl_cpt_param *param,
		int flags);
int vz_env_restore(struct vzctl_env_handle *h, struct start_param *start_param,
		struct vzctl_cpt_param *param, int flags);
int vz_env_get_cpt_state(struct vzctl_env_handle *h, int *state);
int vzctl2_cpt_cmd(struct vzctl_env_handle *h, int action, int cmd,
                struct vzctl_cpt_param *param, int flags);
void get_dumpfile(struct vzctl_env_handle *h, struct vzctl_cpt_param *param,
		char *dumpfile, int size);
int criu_cmd(struct vzctl_env_handle *h, int cmd,
		struct vzctl_cpt_param *param, struct start_param *data);
#ifdef __cplusplus
}
#endif

#endif
