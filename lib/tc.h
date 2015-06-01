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
#ifndef __TC_H__
#define __TC_H__
#include "list.h"

struct vzctl_rate {
	list_elem_t list;
	char *dev;
	int net_class;
	int rate;
};

struct vzctl_tc_param {
	list_head_t totalrate_list;
	list_head_t rate_list;
	int traffic_shaping;
	int ratebound;
};

int parse_rates(list_head_t *head, const char *str, int num, int replace);
struct vzctl_tc_param *alloc_tc_param(void);
void free_tc_param(struct vzctl_tc_param *param);
int vzctl_apply_tc_param(struct vzctl_env_handle *h, struct vzctl_env_param *env, int flags);
char *rate2str(list_head_t *head);
struct vzctl_rate *alloc_rate();
void free_rate(struct vzctl_rate *rate);

#endif /* __TC_H_ */

