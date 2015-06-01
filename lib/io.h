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

#ifndef	_VZCTL_IOPRIO_H_
#define _VZCTL_IOPRIO_H_

#define VE_IOPRIO_MIN		0
#define VE_IOPRIO_MAX		7
#define IOPRIO_WHO_UBC		1000

#define IOPRIO_CLASS_SHIFT	13
#define IOPRIO_CLASS_BE		2

struct vzctl_io_param {
	unsigned int limit;
	unsigned int iopslimit;
};

struct vzctl_io_param *alloc_io_param(void);
void free_io_param(struct vzctl_io_param *io);
int parse_ioprio(struct vzctl_io_param *io, const char *val);
int parse_iolimit(struct vzctl_io_param *io, const char *val, int def_mul);
int parse_iopslimit(struct vzctl_io_param *io, const char *str);
int apply_io_param(struct vzctl_env_handle *h, struct vzctl_env_param *env, int flags);
void free_io_param(struct vzctl_io_param *io);
int vz_set_iolimit(struct vzctl_env_handle *h, unsigned int limit);
int vz_get_iolimit(struct vzctl_env_handle *h, unsigned int *limit);
int vz_set_iopslimit(struct vzctl_env_handle *h, unsigned int limit);
int vz_get_iopslimit(struct vzctl_env_handle *h, unsigned int *limit);
#endif
