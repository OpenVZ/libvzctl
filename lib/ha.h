/*
 * Copyright (c) 2012-2017, Parallels International GmbH
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
 */
#ifndef	_HA_H_
#define	_HA_H_

struct ha_params {
	int ha_enable;
	unsigned long *ha_prio;
};

struct vzctl_config;
struct vzctl_env_handle;

int handle_set_cmd_on_ha_cluster(ctid_t ctid, const char *ve_private,
		struct ha_params *cmdline, struct ha_params *config);
void shaman_del_everywhere(ctid_t ctid);
int shaman_del_resource(ctid_t ctid);
int shaman_add_resource(ctid_t ctid, struct vzctl_config *conf, const char *ve_private);
int shaman_is_configured(void);
int ha_sync(struct vzctl_env_handle *h, int flags);
#endif	/* _HA_H_ */
