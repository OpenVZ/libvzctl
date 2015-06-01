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

#ifndef _VZCTL_CLEANUP_H_
#define _VZCTL_CLEANUP_H_

#include "hook.h"

typedef list_head_t cleanup_ctx_t;

typedef void (* cleanup_FN) (void *data);

struct vzctl_cleanup_hook {
	list_elem_t list;
	cleanup_FN fn;
	void *data;
};

#ifdef __cplusplus
extern "C" {
#endif

struct vzctl_cleanup_hook *register_cleanup_hook(cleanup_FN f, void *data);
void unregister_cleanup_hook(struct vzctl_cleanup_hook *h);
void cleanup_kill_process(void *data);
void cleanup_destroydir(void *data);
void cleanup_quota_off(void *data);
void cleanup_kill_ve(void *data);

#ifdef __cplusplus
}
#endif

#endif /* _VZCTL_CLEANUP_H_ */
