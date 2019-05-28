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

#ifndef _CLUSTER_H_
#define _CLUSTER_H_
#include "list.h"

#define VZCTL_CLUSTER_SERVICE_VERSION	1
#define VZCTL_MAX_SRV_LEN	512
#define VZCTL_MAX_SRV		100

#ifdef __cplusplus
extern "C" {
#endif

char **vzctl_get_storage(void);
int is_nfs(const char *path);
int is_pcs(const char *path);
int is_shared_fs(const char *path);

#ifdef __cplusplus
}
#endif

#endif
