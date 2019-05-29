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
#ifndef _VZCTL_MEMINFO_H_
#define _VZCTL_MEMINFO_H_

struct vzctl_meminfo_param {
	int mode;
#define VE_MEMINFO_NONE 1
#define VE_MEMINFO_PAGES 2
#define VE_MEMINFO_PRIVVMPAGES 3
	unsigned long val;
};
struct vzctl_env_handle;
struct vzctl_env_param;

struct vzctl_meminfo_param *alloc_meminfo_param(void);
int apply_meminfo_param(struct vzctl_env_handle *h, struct vzctl_env_param *env, int flags);
int parse_meminfo(struct vzctl_meminfo_param *meminfo, const char *str);
char *meminfo2str(struct vzctl_meminfo_param *meminfo);
void free_meminfo_param(struct vzctl_meminfo_param *meminfo);

#endif /* _VZCTL_MEMINFO_H_ */
