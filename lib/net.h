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

#ifndef __NET_H__
#define __NET_H__

#define HAVE_VZLIST_IOCTL	1

#include "list.h"

struct vzctl_ip_param {
	list_elem_t list;
	char *ip;
	unsigned int mask;
};

struct vzctl_net_param {
	list_head_t ip;
	list_head_t ip_del;
	int ipv6;
	int delall;
	int rps;
};

struct vzctl_netdev_param {
	list_head_t dev;
	list_head_t dev_del;
};

struct vzctl_net_param *alloc_net_param(void);
void free_net_param(struct vzctl_net_param *net);
struct vzctl_netdev_param *alloc_netdev_param(void);
void free_netdev_param(struct vzctl_netdev_param *param);
int apply_venet_param(struct vzctl_env_handle *h, struct vzctl_env_param *env, int flags);
int apply_netdev_param(struct vzctl_env_handle *h, struct vzctl_env_param *env, int flags);
struct vzctl_ip_param *add_ip_param_str(list_head_t *head, char *str);
void free_ip(list_head_t *head);
struct vzctl_ip_param *add_ip_param(list_head_t *head,
	const struct vzctl_ip_param *ip);
int copy_ip_param(list_head_t *dst, list_head_t *src);
void free_ip_param(struct vzctl_ip_param *ip);
char *ip_param2str(list_head_t *head);
char *ip2str(const char *prefix, list_head_t *ip, int use_netmask);
int run_net_script(struct vzctl_env_handle *h, const char *script,
		list_head_t *ip, int skip_arpdetect);
int vzctl_get_env_ip(struct vzctl_env_handle *h, list_head_t *ip);
int parse_netdev(list_head_t *netdev, const char *val, int replace);
char *netdev2str(struct vzctl_netdev_param *old, struct vzctl_netdev_param *new);
int read_proc_veip(struct vzctl_env_handle *h, list_head_t *ip);
int get_ip_str(struct vzctl_ip_param *ip, char *str, int len);
const struct vzctl_ip_param *find_ip(list_head_t *head,
	struct vzctl_ip_param *ip);
int invert_ip_op(int op);
void configure_net_rps(const char *ve_root, const char *dev);
int vz_ip_ctl(struct vzctl_env_handle *h, int op, const char *ipstr, int flags);
int vz_netdev_ctl(struct vzctl_env_handle *h, int add, const char *dev);
int get_env_ip_proc(struct vzctl_env_handle *h, list_head_t *ip);
int relase_venet_ips(struct vzctl_env_handle *h);
#endif /* _NET_H_ */

