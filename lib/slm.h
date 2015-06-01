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

#ifndef	__SLM_H__
#define __SLM_H__

enum slm_mode {
	VZCTL_MODE_UBC	= 1,
	VZCTL_MODE_ALL	= 2,
	VZCTL_MODE_SLM	= 3
};

struct vzctl_slm_memorylimit {
	unsigned long inst;
	unsigned long avg;
	unsigned long quality;
};

struct vzctl_slm_param {
	int enable;
	int mode;
	struct vzctl_slm_memorylimit *memorylimit;
};

#ifdef __cplusplus
extern "C" {
#endif
void free_slm_param(struct vzctl_slm_param *slm);
struct vzctl_slm_param *alloc_slm_param();
int slm_mode2id(const char *name);
const char *slm_id2mode(int id);
#ifdef __cplusplus
}
#endif
#endif
