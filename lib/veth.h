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

#ifndef	__VETH_H__
#define	__VETH_H__

#include "list.h"
#include "net.h"

#define IFNAMSIZE	16
#define ETH_ALEN	6
#define MAC_SIZE	3*ETH_ALEN - 1
#define VZNETCFG	"/usr/sbin/vznetcfg"

#define PROC_VETH	"/proc/vz/veth"

/* #define SW_OUI		0x001851 */
#define VZ_OUI		0xC43772

#define VETH_ACTIVE		0x0001

/** Data structure for devices.
 */
struct vzctl_veth_dev {
	list_elem_t list;		/**< next element. */
	list_head_t ip_list;		/**< ip addresses. */
	list_head_t ip_del_list;
	char *mac	;		/**< device MAC address. */
	char dev_name[IFNAMSIZE+1];	/**< device name. */
	char *mac_ve;			/**< device MAC address in VE. */
	char dev_name_ve[IFNAMSIZE+1];	/**< device name in VE. */
	char *gw;			/**< gateway ip */
	char *network;			/**< connect virtual interface to virtual network. */
	int dhcp;			/**< DHCP4 oh/off. */
	int mac_filter;
	int ip_filter;
	int flags;
	int ip_delall;
	int dhcp6;			/**< DHCP6 oh/off. */
	char *gw6;			/**< gateway ip6 */
	int configure_mode;		/*** VZCTL_VETH_CONFIGURE_* */
	int nettype;
	int vporttype;
	char *ifaceid;
};

/** Devices list.
 */
struct vzctl_veth_param {
	list_head_t dev_list;
	list_head_t dev_del_list;
	int delall;
	struct vzctl_veth_dev *ifname;
};

struct vzctl_env_handle;
struct vzctl_env_param;

int apply_veth_param(struct vzctl_env_handle *h, struct vzctl_env_param *env,
	int flags);
int apply_venet_param(struct vzctl_env_handle *h, struct vzctl_env_param *env,
		int flags);
struct vzctl_veth_param *alloc_veth_param(void);
void free_veth_dev(struct vzctl_veth_dev *dev);
int parse_netif(struct vzctl_env_handle *h, list_head_t *head, const char *val);
int parse_netif_cmd(struct vzctl_env_handle *h, list_head_t *head, const char *val);
int parse_netif_ifname(struct vzctl_veth_param *veth, const char *str, int op,
		int replace);
char *veth2str(struct vzctl_env_param *env, struct vzctl_veth_param *new,
		int renew);
int add_veth_param(list_head_t *head, struct vzctl_veth_dev *dev);
struct vzctl_veth_dev *alloc_veth_dev(void);
void free_veth_param(struct vzctl_veth_param *veth);

int merge_veth_ifname_param(struct vzctl_env_handle *h,
		struct vzctl_env_param *env);
void generate_mac(char **mac, int fix);
void generate_veth_name(struct vzctl_veth_dev *dev);
int do_veth_ctl(struct vzctl_env_handle *h, int op, struct vzctl_veth_dev *it, int flags);
#endif	/* __VETH_H__ */
