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

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <string.h>
#include <time.h>
#include <uuid/uuid.h>

#include "libvzctl.h"
#include "vzerror.h"
#include "util.h"
#include "veth.h"
#include "env.h"
#include "logger.h"
#include "vz.h"
#include "exec.h"
#include "vzctl_param.h"
#include "config.h"
#include "net.h"
#include "env_ops.h"


void free_veth_dev(struct vzctl_veth_dev *dev)
{
	free(dev->mac);
	free(dev->mac_ve);
	free(dev->gw);
	free(dev->gw6);
	free(dev->network);
	free_ip(&dev->ip_list);
	free_ip(&dev->ip_del_list);
	free(dev->ifaceid);

	free(dev);
}

struct vzctl_veth_dev *alloc_veth_dev(void)
{
	struct vzctl_veth_dev *new;

	new = calloc(1, sizeof(struct vzctl_veth_dev));
	if (new == NULL)
		return NULL;
	list_head_init(&new->ip_list);
	list_head_init(&new->ip_del_list);
	return new;
}

void free_veth(list_head_t *head)
{
	struct vzctl_veth_dev *tmp, *it;

	if (list_empty(head))
		return;
	list_for_each_safe(it, tmp, head, list) {
		list_del(&it->list);
		free_veth_dev(it);
	}
	list_head_init(head);
}

void free_veth_param(struct vzctl_veth_param *veth)
{
	free_veth(&veth->dev_list);
	free_veth(&veth->dev_del_list);
	if (veth->ifname != NULL)
		free_veth_dev(veth->ifname);
	free(veth);
}

struct vzctl_veth_param *alloc_veth_param(void)
{
	struct vzctl_veth_param *new;

	new = calloc(1, sizeof(struct vzctl_veth_param));
	if (new == NULL)
		return NULL;
	list_head_init(&new->dev_list);
	list_head_init(&new->dev_del_list);

	return new;
}

static int fill_veth_dev(struct vzctl_veth_dev *dst,
		struct vzctl_veth_dev *src)
{
	if (src->dev_name[0] != 0)
		strcpy(dst->dev_name, src->dev_name);
	if (src->mac != NULL) {
		set_hwaddr(src->mac, &dst->mac);
	}
	if (src->dev_name_ve[0] != 0)
		strcpy(dst->dev_name_ve, src->dev_name_ve);
	if (src->mac_ve != 0) {
		set_hwaddr(src->mac_ve, &dst->mac_ve);
	}
	if (src->network != NULL) {
		free(dst->network);
		dst->network = strdup(src->network);
	}
	if (src->gw) {
		free(dst->gw);
		dst->gw = strdup(src->gw);
	}
	if (src->gw6) {
		free(dst->gw6);
		dst->gw6 = strdup(src->gw6);
	}
	if (src->dhcp)
		dst->dhcp = src->dhcp;
	if (src->dhcp6)
		dst->dhcp6 = src->dhcp6;
	if (src->mac_filter)
		dst->mac_filter = src->mac_filter;
	if (src->ip_filter)
		dst->ip_filter = src->ip_filter;
	if (src->configure_mode)
		dst->configure_mode = src->configure_mode;
	if (!list_empty(&src->ip_list))
		copy_ip_param(&dst->ip_list, &src->ip_list);
	if (!list_empty(&src->ip_del_list))
		copy_ip_param(&dst->ip_del_list, &src->ip_del_list);
	dst->ip_delall = src->ip_delall;
	if (src->nettype)
		dst->nettype = src->nettype;
	if (src->vporttype)
		dst->vporttype = src->vporttype;
	if (src->ifaceid)
		xstrdup(&dst->ifaceid, src->ifaceid);

	return 0;
}

int add_veth_param(list_head_t *head, struct vzctl_veth_dev *dev)
{
	int ret;
	struct vzctl_veth_dev *new;

	new = alloc_veth_dev();
	if (new == NULL)
		return VZCTL_E_NOMEM;
	ret = fill_veth_dev(new, dev);
	if (ret) {
		free_veth_dev(new);
		return ret;
	}
	list_add_tail(&new->list, head);

	return 0;
}

static unsigned int hash32(uuid_t u)
{   
	unsigned int h = 0, i;

	for (i = 0; i < sizeof(uuid_t); ++i) {
		h += u[i]; 
		h += (h << 10);
		h ^= (h >> 6);
	}
	h += (h << 3);
	h ^= (h >> 11);
	return h + (h << 15);
}

void generate_mac(char **mac, int fix)
{
	unsigned int hash;
	char hwaddr[ETH_ALEN];
	uuid_t u;

	uuid_generate(u);
	hash = hash32(u);

	hwaddr[0] = (char) (VZ_OUI >> 0x10);
	hwaddr[1] = (char) (VZ_OUI >> 0x8);
	hwaddr[2] = (char) VZ_OUI;
	hwaddr[3] = (char) hash;
	hwaddr[4] = (char) (hash >> 0x8);
	hwaddr[5] = (char) (hash >> 0xf);
	/* To avoid assign veth mac to bridge.
	 * Set it max by change first byte to 'fe'
	 */
	if (fix)
		hwaddr[0] = 0xfe;
	*mac = hwaddr2str(hwaddr);
}

void generate_veth_name(struct vzctl_veth_dev *dev)
{
	char s[9], o[9];

	if (dev->mac_ve == NULL)
		generate_mac(&dev->mac_ve, 0);

	sprintf(s, "%c%c%c%c%c%c%c%c",
			dev->mac_ve[6],
			dev->mac_ve[7],
			dev->mac_ve[9],
			dev->mac_ve[10],
			dev->mac_ve[12],
			dev->mac_ve[13],
			dev->mac_ve[15],
			dev->mac_ve[16]);

	str_tolower(s, o);
	snprintf(dev->dev_name, sizeof(dev->dev_name), "veth%s", o);

}

static struct vzctl_veth_dev *find_veth_by_ifname_ve(list_head_t *head,
		const char *name)
{
	struct vzctl_veth_dev *it;

	list_for_each(it, head, list) {
		if (!strcmp(it->dev_name_ve, name))
			return it;
	}
	return NULL;
}

static void fill_empty_veth_dev_param(struct vzctl_env_handle *h,
		struct vzctl_veth_dev *dev)
{
	struct vzctl_veth_dev *d = NULL;

	if (h)
		d = find_veth_by_ifname_ve(&h->env_param->veth->dev_list,
			dev->dev_name_ve);

	if (dev->mac == NULL)
		d ? set_hwaddr(d->mac, &dev->mac) : generate_mac(&dev->mac, 1);

	if (dev->mac_ve == NULL)
		d ? set_hwaddr(d->mac_ve, &dev->mac_ve):  generate_mac(&dev->mac_ve, 0);
	if (dev->dev_name[0] == '\0')
		generate_veth_name(dev);
	if (dev->mac_filter == 0)
		dev->mac_filter = VZCTL_PARAM_ON;
}

static int run_vznetcfg(struct vzctl_env_handle *h, struct vzctl_veth_dev *dev)
{
	char fname[PATH_MAX];
	char veid[sizeof(ctid_t) + sizeof("VEID=")];
	char ifaceid[sizeof(ctid_t) + sizeof("IFACEID=")];
	char mac[STR_SIZE];
	char *env[6];
	int i = 0;
	char *arg[] = {
		fname,
		dev->network[0] == '\0' ? "delif" : "addif",
		dev->dev_name,
		dev->network,
		NULL
	};

	snprintf(veid, sizeof(veid), "VEID=%s", h->ctid);
	env[i++] = veid;
	if (dev->nettype == VZCTL_NETTYPE_BRIDGE)
		env[i++] = "NETWORK_TYPE=bridge";
	if (dev->vporttype == VZCTL_VPORTTYPE_OVS) {
		env[i++] = "VPORT_TYPE=ovs";
		if (dev->ifaceid) {
			snprintf(ifaceid, sizeof(ifaceid), "IFACEID=%s", dev->ifaceid);
			env[i++] = ifaceid;
		}
		snprintf(mac, sizeof(mac), "MAC=%s", dev->mac_ve);
		env[i++] = mac;
	}
	env[i] = NULL;

	get_script_path("vznetcfg", fname, sizeof(fname));
	if (access(fname, F_OK))
		return 0;

	if (vzctl2_wrap_exec_script(arg, env, 0))
		return vzctl_err(VZCTL_E_VETH, 0, "%s exited with error",
				fname);
	return 0;
}

static void fill_veth_dev_name(struct vzctl_env_handle *h,
		struct vzctl_veth_dev *dev)
{
	struct vzctl_veth_dev *d;

	if (dev->dev_name[0] != '\0')
		return;

	d = find_veth_by_ifname_ve(&h->env_param->veth->dev_list,
			dev->dev_name_ve);
	if (d != NULL)
		strncpy(dev->dev_name, d->dev_name, sizeof(dev->dev_name));
	else
		generate_veth_name(dev);
}

static int veth_ctl(struct vzctl_env_handle *h, int op, list_head_t *head,
		int flags, int rollback)
{
	int ret = 0;
	char buf[256];
	char *p, *ep;
	struct vzctl_veth_dev *it;

	if (list_empty(head))
		return 0;

	if (!is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_NOT_RUN, 0,
				"Unable to %s veth: container is not running",
				op == ADD ? "create" : "remove");
	buf[0] = 0;
	p = buf;
	ep = buf + sizeof(buf) - 1;
	list_for_each(it, head, list) {
		p += snprintf(p, ep - p, "%s ", it->dev_name_ve);
		if (p >= ep)
			break;
	}
	logger(0, 0, "%s veth device(s): %s",
			 (op == ADD) ? "Configure" : "Deleting", buf);
	list_for_each(it, head, list) {
		fill_veth_dev_name(h, it);
		if (op == ADD) {
			ret = get_env_ops()->env_veth_ctl(h, ADD, it, flags);
			if (ret)
				break;
			if (it->network != NULL && (ret = run_vznetcfg(h, it)))
				break;
			if (h->env_param->net->rps != VZCTL_PARAM_OFF)
				configure_net_rps(h->env_param->fs->ve_root, it->dev_name_ve);
		} else {
			ret = get_env_ops()->env_veth_ctl(h, DEL, it, flags);
			if (ret)
				break;
		}
	}

	/* If operation failed remove devices were added. */
	if (ret && rollback) {
		list_for_each_prev_continue(it, head, list) {
			if (op == ADD && !(it->flags & VETH_ACTIVE))
				get_env_ops()->env_veth_ctl(h, DEL, it, flags);
		}
		/* Remove devices from list to skip saving. */
		free_veth(head);
	}
	return ret;
}

struct vzctl_veth_dev *find_veth_dev(list_head_t *head,
		const struct vzctl_veth_dev *dev)
{
	struct vzctl_veth_dev *it;

	list_for_each(it, head, list) {
		if (!strcmp(it->dev_name, dev->dev_name))
			return it;
	}
	return NULL;
}

static int merge_veth_dev(struct vzctl_veth_dev *old, struct vzctl_veth_dev *new,
		struct vzctl_veth_dev *merged)
{
	struct vzctl_ip_param *ip;

	fill_veth_dev(merged, old);
	fill_veth_dev(merged, new);

	/* merge ips */
	if (!new->ip_delall) {
		list_head_t *old_ip_list = &old->ip_list;
		list_head_t *new_ip_list = &new->ip_list;

		free_ip(&merged->ip_list);
		// Copy old ips
		list_for_each(ip, old_ip_list, list) {
			if (find_ip(new_ip_list, ip) != NULL)
				continue;
			add_ip_param(&merged->ip_list, ip);
		}
		list_for_each(ip, new_ip_list, list) {
			if (find_ip(&new->ip_del_list, ip) != NULL)
				continue;
			add_ip_param(&merged->ip_list, ip);
		}
	} else {
		// Clean ip list in case ip_delall & empty ip list specified
		if (list_empty(&new->ip_list))
			free_ip(&merged->ip_list);
	}

	return 0;
}

static int merge_veth_list(list_head_t *old, list_head_t *add, list_head_t *del,
	list_head_t *merged)
{
	int ret;
	struct vzctl_veth_dev *it;
	list_head_t empty;

	list_head_init(&empty);
	if (old == NULL)
		old = &empty;
	if (add == NULL)
		add = &empty;
	if (del == NULL)
		del = &empty;

	list_for_each(it, old, list) {
		struct vzctl_veth_dev *new_dev;
		/* Skip old devices that was deleted */
		if (find_veth_by_ifname_ve(del, it->dev_name_ve) != NULL)
			continue;
		new_dev = find_veth_by_ifname_ve(add, it->dev_name_ve);
		if (new_dev != NULL) {
			struct vzctl_veth_dev *merged_dev;


			merged_dev = alloc_veth_dev();
			if (merged_dev == NULL)
				return VZCTL_E_NOMEM;
			/* Merge new parameters with old one */
			merge_veth_dev(it, new_dev, merged_dev);
			ret = add_veth_param(merged, merged_dev);

			free_veth_dev(merged_dev);

			if (ret)
				return ret;
		} else {
			/* Add old devices */
			ret = add_veth_param(merged, it);
			if (ret)
				return ret;
		}
	}
	/* Add rest of new devices */
	list_for_each(it, add, list) {
		if (find_veth_by_ifname_ve(old, it->dev_name_ve) == NULL) {
			if (add_veth_param(merged, it))
				return VZCTL_E_NOMEM;
		}
	}
	return 0;
}

int merge_veth_ifname_param(struct vzctl_env_handle *h,
		struct vzctl_env_param *env)
{
	struct vzctl_veth_dev *d, *veth = env->veth->ifname;
	struct vzctl_ip_param *it;

	if (veth == NULL || veth->dev_name_ve[0] == '\0')
		return 0;

	d = find_veth_by_ifname_ve(&env->veth->dev_list, veth->dev_name_ve);
	if (d != NULL) {
		/* merge netif + ifname */
		fill_veth_dev(d, veth);
		fill_empty_veth_dev_param(h, d);
		return 0;
	}

	d = find_veth_by_ifname_ve(&h->env_param->veth->dev_list,
				veth->dev_name_ve);
	if (d == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0, "Virtual adapter %s"
				" is not configured", veth->dev_name_ve);
	if (veth->dev_name[0] == '\0')
		strcpy(veth->dev_name, d->dev_name);

	/* trun dhcp off on ip address set*/
	list_for_each(it, &veth->ip_list, list) {
		if (is_ip6(it->ip))
			veth->dhcp6 = VZCTL_PARAM_OFF;
		else
			veth->dhcp = VZCTL_PARAM_OFF;
	}

	return add_veth_param(&env->veth->dev_list, veth);
}

static int env_veth_configure(struct vzctl_env_handle *h, int add,
		list_head_t *phead, int flags)
{
	struct vzctl_veth_dev *it_dev;
	struct vzctl_ip_param *it_ip;
	char buf[STR_SIZE];
	char ip_buf[STR_SIZE * 100];
	char *env[MAX_ARGS];
	int ret, r, i = 0;
	int changed = 0;
	const char *script;
	int ipv6 = 0;
	char *ip_p, *ip_e = ip_buf +  sizeof(ip_buf);

	if (flags & (VZCTL_SKIP_CONFIGURE | VZCTL_RESTORE))
		return 0;

	if ((ret = read_dist_actions(h)))
		return ret;

	if (add) {
		script = h->dist_actions->netif_add;
		if (script == NULL) {
			logger(-1, 0, "Warning: NETIF_ADD action not is"
					" specified");
			return 0;
		}
	} else {
		script = h->dist_actions->netif_del;
		if (script == NULL) {
			logger(-1, 0, "Warning: NETIF_DEL action not is"
					" specified");
			return 0;
		}
	}
	if (vzctl2_env_get_param_bool(h, "IPV6") == VZCTL_PARAM_ON)
		ipv6 = 1;

	list_for_each(it_dev, phead, list) {
		list_head_t *ip_list_head;

		if (it_dev->configure_mode == VZCTL_VETH_CONFIGURE_NONE)
			continue;

		if (!add)
			changed++;

		i = 0;
		snprintf(buf, sizeof(buf), "VE_STATE=%s", get_state(h));
		env[i++] = strdup(buf);

		snprintf(buf, sizeof(buf), "DEVICE=%s", it_dev->dev_name_ve);
		env[i++] = strdup(buf);
		if (ipv6)
			env[i++] = strdup("IPV6=yes");
		if (it_dev->gw != NULL) {
			changed++;
			if (*it_dev->gw == 0)
				snprintf(buf, sizeof(buf), "GWDEL=%s", it_dev->dev_name_ve);
			else
				snprintf(buf, sizeof(buf), "GW=%s", it_dev->gw);

			env[i++] = strdup(buf);
		}
		if (it_dev->gw6 != NULL) {
			changed++;
			if (*it_dev->gw6 == 0)
				snprintf(buf, sizeof(buf), "GW6DEL=%s", it_dev->dev_name_ve);
			else
				snprintf(buf, sizeof(buf), "GW6=%s", it_dev->gw6);

			env[i++] = strdup(buf);
		}

		if (it_dev->dhcp) {
			changed++;
			snprintf(buf, sizeof(buf), "DHCP4=%s",
					it_dev->dhcp == VZCTL_PARAM_ON ? "yes" : "no");
			env[i++] = strdup(buf);
		}
		if (it_dev->dhcp6) {
			changed++;
			snprintf(buf, sizeof(buf), "DHCP6=%s",
					it_dev->dhcp6 == VZCTL_PARAM_ON ? "yes" : "no");
			env[i++] = strdup(buf);
		}
		if (it_dev->ip_delall) {
			changed++;
			snprintf(buf, sizeof(buf), "IPDEL=all");
			env[i++] = strdup(buf);
		} else if (!list_empty(&it_dev->ip_del_list)) {
			r = sprintf(ip_buf, "IPDEL=");
			ip_p = ip_buf + r;
			ip_list_head = &it_dev->ip_del_list;
			list_for_each(it_ip, ip_list_head, list) {
				changed++;
				r = snprintf(ip_p, ip_e - ip_p, "%s ", it_ip->ip);
				ip_p += r;
				if (r < 0 || ip_p > ip_e)
					break;
			}
			env[i++] = strdup(ip_buf);
		}

		if (!list_empty(&it_dev->ip_list)) {
			r = sprintf(ip_buf, "IPADD=");
			ip_p = ip_buf + r;
			ip_list_head = &it_dev->ip_list;
			list_for_each(it_ip, ip_list_head, list) {
				unsigned int addr[4];
				int family;

				family = get_netaddr(it_ip->ip, addr);
				if (it_dev->dhcp == VZCTL_PARAM_ON && family == AF_INET)
					continue;
				if (it_dev->dhcp6 == VZCTL_PARAM_ON && family == AF_INET6)
					continue;

				changed++;
				r = snprintf(ip_p, ip_e - ip_p, "%s", it_ip->ip);
				ip_p += r;
				if (r < 0 || ip_p > ip_e)
					break;
				if (it_ip->mask) {

					if (family == AF_INET6)
						ip_p += snprintf(ip_p, ip_e - ip_p, "/%d",
								it_ip->mask);
					else
						ip_p += snprintf(ip_p, ip_e - ip_p, "/%s",
								get_ip4_name(it_ip->mask));
				}
				r = snprintf(ip_p, ip_e - ip_p, " ");
				ip_p += r;
				if (r < 0 || ip_p > ip_e)
					break;
			}
			env[i++] = strdup(ip_buf);
		}
		env[i++] = NULL;
		do {
			if (it_dev->configure_mode == VZCTL_VETH_CONFIGURE_NONE)
				break;
			if (h->ctx->state & VZCTL_STATE_STARTING) {
				/* Compatibility: no parameters set */
				if (it_dev->configure_mode == 0 && !changed)
					break;
			} else if (!changed)
				break;

			ret = vzctl2_wrap_env_exec_vzscript(h, NULL, env,
				script, VZCTL_SCRIPT_EXEC_TIMEOUT, EXEC_LOG_OUTPUT);
			if (ret) {
				logger(-1, 0, "veth network configuration"
						" script exited with error %d", ret);
				free_ar_str(env);
				goto out;
			}
		} while(0);

		changed = 0;
		free_ar_str(env);
	}
out:
	return ret;
}

int apply_veth_param(struct vzctl_env_handle *h, struct vzctl_env_param *env,
		int flags)
{
	struct vzctl_veth_param *veth = env->veth;
	int ret = 0;

	if (list_empty(&veth->dev_list) &&
		list_empty(&veth->dev_del_list) &&
		!veth->delall)
	{
		return 0;
	}

	if (veth->delall) {
		env_veth_configure(h, 0, &h->env_param->veth->dev_list, flags);
		veth_ctl(h, DEL, &h->env_param->veth->dev_list, flags, 0);
	} else if (!list_empty(&veth->dev_del_list)) {
		env_veth_configure(h, 0, &veth->dev_del_list, flags);
		veth_ctl(h, DEL, &veth->dev_del_list, flags, 0);
	}
	if (!list_empty(&veth->dev_list)) {
		ret = veth_ctl(h, ADD, &veth->dev_list, flags, 1);
		if (ret == 0)
			env_veth_configure(h, 1, &veth->dev_list, flags);
	}

	return ret;
}

/**************************** Config functions ***************************/
char *veth2str(struct vzctl_env_param *env, struct vzctl_veth_param *new,
		int renew)
{
	char buf[STR_SIZE * 10];
	list_head_t *phead;
	struct vzctl_veth_dev *it;
	list_head_t merged;
	struct vzctl_ip_param *ip;
	char *sp, *ep, *prev;
	struct vzctl_veth_param *old = env->veth;
	unsigned int addr[4];
	int f;

	if (list_empty(&new->dev_list) &&
	    list_empty(&new->dev_del_list) &&
	    !new->delall)
		return NULL;

	if (new->delall) {
		phead = &new->dev_list;
	} else {
		phead = &merged;
		list_head_init(phead);
		if (merge_veth_list(&old->dev_list, &new->dev_list, &new->dev_del_list,
					phead))
			return NULL;
	}

	*buf = 0;
	sp = buf;
	ep = buf + sizeof(buf) - 2;
	prev = sp;
	list_for_each(it, phead, list) {
		if (prev != sp)
			*(sp-1) = ';';
		prev = sp;
		if (it->dev_name_ve[0] != 0) {
			sp += snprintf(sp, ep - sp, "ifname=%s,",
				it->dev_name_ve);
			if (sp >= ep)
				break;
		} else {
			continue;
		}
		if (it->mac_ve == NULL)
			generate_mac(&it->mac_ve, 0);
		if (it->mac_ve != NULL) {
			sp += snprintf(sp, ep - sp, "mac=%s,",
				it->mac_ve);
			if (sp >= ep)
				break;
		}
		if ((renew & VZ_REG_RENEW_NETIF_MAC) || it->mac == NULL)
			generate_mac(&it->mac, 1);

		if (it->mac != NULL) {
			sp += snprintf(sp, ep - sp, "host_mac=%s,",
				it->mac);
			if (sp >= ep)
				break;
		}

		if (it->dev_name[0] != 0) {
			if (renew & VZ_REG_RENEW_NETIF_IFNAME)
				generate_veth_name(it);

			sp += snprintf(sp, ep - sp, "host_ifname=%s,",
				it->dev_name);
			if (sp >= ep)
				break;
		}
		if (it->network != NULL && it->network[0] != 0) {
			sp += snprintf(sp, ep - sp, "network=%s,",
					it->network);
			if (sp >= ep)
				break;
		}
		if (it->nettype == VZCTL_NETTYPE_BRIDGE) {
			sp += snprintf(sp, ep - sp, "type=bridge,");
			if (sp >= ep)
				break;
		}
		if (it->vporttype == VZCTL_VPORTTYPE_OVS) {
			sp += snprintf(sp, ep - sp, "vport=ovs,");
			if (sp >= ep)
				break;
		}

		if (it->gw != NULL && it->gw[0] != 0) {
			sp += snprintf(sp, ep - sp, "gw=%s,", it->gw);
			if (sp >= ep)
				break;
		}
		if (it->gw6 != NULL && it->gw6[0] != 0) {
			sp += snprintf(sp, ep - sp, "gw6=%s,", it->gw6);
			if (sp >= ep)
				break;
		}
		if (it->mac_filter == VZCTL_PARAM_OFF) {
			sp += snprintf(sp, ep - sp, "mac_filter=%s,",
				id2onoff(it->mac_filter));
			if (sp >= ep)
				break;
		}
		if (it->ip_filter == VZCTL_PARAM_OFF) {
			sp += snprintf(sp, ep - sp, "ip_filter=%s,",
				id2onoff(it->ip_filter));
			if (sp >= ep)
				break;
		}
		if (it->ifaceid) {
			sp += snprintf(sp, ep - sp, "ifaceid=%s,",
				it->ifaceid);
			if (sp >= ep)
				break;
		}

		if (it->configure_mode) {
			sp += snprintf(sp, ep - sp, "configure=%s,",
					it->configure_mode == VZCTL_VETH_CONFIGURE_NONE ? "none" : "all");
			if (sp >= ep)
				break;
		}
		if (it->dhcp == VZCTL_PARAM_ON ) {
			sp += snprintf(sp, ep - sp, "dhcp=%s,",
				it->dhcp == VZCTL_PARAM_ON ? "yes" : "no");
			if (sp >= ep)
				break;
		} else if (!list_empty(&it->ip_list)) {
			list_head_t *head = &it->ip_list;

			sp += snprintf(sp, ep - sp, "ip=");
			if (sp >= ep)
				break;
			list_for_each(ip, head, list) {
				f = get_netaddr(ip->ip, addr);
				if (f == -1)
					logger(1, 0, "Waring: invalid veth ip address: %s",
							ip->ip);
				if (f != AF_INET)
					continue;
				sp += snprintf(sp, ep - sp, "%s", ip->ip);
				if (sp >= ep)
					break;
				if (ip->mask != 0) {
					sp += snprintf(sp, ep - sp, "/%s",
							get_ip4_name(ip->mask));
					if (sp >= ep)
						break;
				}
				sp += snprintf(sp, ep - sp, ":");
				if (sp >= ep)
					break;
			}
			if (*(sp - 1) == '=')
				sp += snprintf(sp, ep - sp, ",");
			else if (*(sp - 1) == ':')
				*(sp - 1) = ',';
		}
		if (it->dhcp6 == VZCTL_PARAM_ON) {
			sp += snprintf(sp, ep - sp, "dhcp6=%s,",
				it->dhcp6 == VZCTL_PARAM_ON ? "yes" : "no");
			if (sp >= ep)
				break;
		} else if (!list_empty(&it->ip_list)) {
			list_head_t *head = &it->ip_list;

			sp += snprintf(sp, ep - sp, "ip6=");
			if (sp >= ep)
				break;
			list_for_each(ip, head, list) {
				f = get_netaddr(ip->ip, addr);
				if (f == -1)
					logger(1, 0, "Waring: invalid veth ip address: %s",
							ip->ip);
				if (f != AF_INET6)
					continue;
				sp += snprintf(sp, ep - sp, "%s", ip->ip);
				if (sp >= ep)
					break;
				if (ip->mask != 0) {
					sp += snprintf(sp, ep - sp, "/%d",
							ip->mask);
					if (sp >= ep)
						break;
				}
				sp += snprintf(sp, ep - sp, ",");
				if (sp >= ep)
					break;
			}
		}
		if (*(sp - 1) == ',')
			*(sp - 1) = 0;
		if (sp >= ep)
			break;
	}
	if (phead == &merged)
		free_veth(&merged);
	return strdup(buf);
}

static int get_nettype(const char *str, int *type)
{
	if (strcmp("bridge", str) == 0)
		*type = VZCTL_NETTYPE_BRIDGE;
	else
		return VZCTL_E_INVAL;

	return 0;
}

static int get_vporttype(const char *str, int *type)
{
	if (strcmp("ovs", str) == 0)
		*type = VZCTL_VPORTTYPE_OVS;
	else
		return VZCTL_E_INVAL;

	return 0;
}

static int parse_netif_str(struct vzctl_env_handle *h, const char *str,
		struct vzctl_veth_dev *dev)
{
	const char *p, *next, *e_ip, *ep;
	int len, err, id;
	char tmp[256];
	struct vzctl_ip_param *ip;

	next = p = str;
	ep = p + strlen(str);
	do {
		while (*next != '\0' && *next != ',') next++;
		if (!strncmp("ifname=", p, 7)) {
			p += 7;
			len = next - p;
			if (len == 0)
				continue;
			if (len > IFNAMSIZE)
				return VZCTL_E_INVAL;
			if (dev->dev_name_ve[0] == '\0')
				strncpy(dev->dev_name_ve, p, len);
		} else if (!strncmp("host_ifname=", p, 12)) {
			p += 12;
			len = next - p;
			if (len == 0)
				continue;
			if (len > IFNAMSIZE)
				return VZCTL_E_INVAL;
			if (dev->dev_name[0] == '\0')
				strncpy(dev->dev_name, p, len);
		} else if (!strncmp("mac=", p, 4)) {
			p += 4;
			len = next - p;
			if (len == 0)
				continue;
			if (len >= sizeof(tmp))
				return VZCTL_E_INVAL;
			strncpy(tmp, p, len);
			tmp[len] = 0;
			err = set_hwaddr(tmp, &dev->mac_ve);
			if (err) {
				logger(-1, 0, "Incorrect mac=%s", tmp);
				return err;
			}
		} else if (!strncmp("host_mac=", p, 9)) {
			p += 9;
			len = next - p;
			if (len == 0)
				continue;
			if (len >= sizeof(tmp))
				return VZCTL_E_INVAL;
			strncpy(tmp, p, len);
			tmp[len] = 0;
			err = set_hwaddr(tmp, &dev->mac);
			if (err) {
				logger(-1, 0, "Incorrect host_mac=%s", tmp);
				return err;
			}
		} else if (!strncmp("gw=", p, 3)) {
			p += 3;
			len = next - p;
			if (len == 0 || dev->gw != NULL)
				continue;
			if (len >= sizeof(tmp))
				return VZCTL_E_INVAL;
			strncpy(tmp, p, len);
			tmp[len] = 0;
			err = parse_ip(tmp, &ip);
			free_ip_param(ip);
			if (err)
				return VZCTL_E_INVAL;
			dev->gw = strdup(tmp);
		} else if (!strncmp("gw6=", p, 4)) {
			p += 4;
			len = next - p;
			if (len == 0 || dev->gw6 != NULL)
				continue;
			if (len >= sizeof(tmp))
				return VZCTL_E_INVAL;
			strncpy(tmp, p, len);
			tmp[len] = 0;
			err = parse_ip(tmp, &ip);
			free_ip_param(ip);
			if (err)
				return VZCTL_E_INVAL;
			dev->gw6 = strdup(tmp);
		} else if (!strncmp("dhcp=", p, 5)) {
			p += 5;
			len = next - p;
			if (len == 0)
				continue;
			if (len >= sizeof(tmp))
				return VZCTL_E_INVAL;
			strncpy(tmp, p, len);
			tmp[len] = 0;
			if ((id = yesno2id(tmp)) < 0)
				return VZCTL_E_INVAL;
			dev->dhcp = id;
		} else if (!strncmp("dhcp6=", p, 6)) {
			p += 6;
			len = next - p;
			if (len == 0)
				continue;
			if (len >= sizeof(tmp))
				return VZCTL_E_INVAL;
			strncpy(tmp, p, len);
			tmp[len] = 0;
			if ((id = yesno2id(tmp)) < 0)
				return VZCTL_E_INVAL;
			dev->dhcp6 = id;
                } else if (!strncmp("mac_filter=", p, 11)) {
                        p += 11;
                        len = next - p;
                        if (len == 0)
                                continue;
                        if (len >= sizeof(tmp))
                                return VZCTL_E_INVAL;
                        strncpy(tmp, p, len);
                        tmp[len] = 0;
			if ((id = onoff2id(tmp)) < 0)
				return VZCTL_E_INVAL;
			dev->mac_filter = id;
		} else if (!strncmp("ip_filter=", p, 10)) {
			p += 10;
			len = next - p;
			if (len == 0)
				continue;
			if (len >= sizeof(tmp))
				return VZCTL_E_INVAL;
			strncpy(tmp, p, len);
			tmp[len] = 0;
			if ((id = onoff2id(tmp)) < 0)
				return VZCTL_E_INVAL;
			dev->ip_filter = id;
		} else if (!strncmp("ifaceid=", p, 8)) {
			p += 8;
			len = next - p;
			if (len == 0)
				continue;
			if (len >= sizeof(tmp))
				return VZCTL_E_INVAL;
			strncpy(tmp, p, len);
			tmp[len] = 0;
			err = xstrdup(&dev->ifaceid, tmp);
			if (err)
				return err;
                } else if (!strncmp("configure=", p, 10)) {
                        p += 10;
                        len = next - p;
                        if (len == 0)
                                continue;
                        if (len >= sizeof(tmp))
                                return VZCTL_E_INVAL;
                        strncpy(tmp, p, len);
                        tmp[len] = 0;
			if (!strcmp(tmp, "none"))
				dev->configure_mode = VZCTL_VETH_CONFIGURE_NONE;
			else if (!strcmp(tmp, "all"))
				dev->configure_mode = VZCTL_VETH_CONFIGURE_ALL;
		} else if (!strncmp("network=", p, 8)) {
			p += 8;
			len = next - p;
			if (len == 0 || dev->network != NULL)
				continue;
			dev->network = malloc(len + 1);
			if (dev->network == NULL)
				return VZCTL_E_NOMEM;
			strncpy(dev->network, p, len);
			dev->network[len] = 0;
			if (!vzctl2_is_networkid_valid(dev->network))
				return vzctl_err(VZCTL_E_INVAL, 0,
						"Incorrect veth network '%s' parameter",
						dev->network);
		} else if (!strncmp("type=", p, 5)) {
			p += 5;
			len = next - p;
			strncpy(tmp, p, len);
			tmp[len] = 0;
			if (get_nettype(tmp, &dev->nettype))
				return vzctl_err(VZCTL_E_INVAL,	0, "Incorrect"
					" veth network type '%s'", tmp);
		} else if (!strncmp("vport=", p, 6)) {
			p += 6;
			len = next - p;
			strncpy(tmp, p, len);
			tmp[len] = 0;
			if (get_vporttype(tmp, &dev->vporttype))
				return vzctl_err(VZCTL_E_INVAL,	0, "Incorrect"
					" virtual port type '%s'", tmp);
		} else if (!strncmp("ip=", p, 3)) {
			p += 3;
			do {
				e_ip = p;
				while (*e_ip != ':' && e_ip < next) e_ip++;
				len = e_ip - p;
				if (len > 0 && len < sizeof(tmp)) {
					strncpy(tmp, p, len);
					tmp[len] = 0;
					if (parse_ip(tmp, &ip)) {
						logger(-1, 0, "Incorrect veth"
							" ip %s, skipped", tmp);
					} else {
						list_add_tail(&ip->list, &dev->ip_list);
					}
				}
				p = ++e_ip;
			} while (p < next);
		} else if (!strncmp("ip6=", p, 4)) {
			p += 4;
			do {
				// ip6= have to be last as far as the ',' is separator
				e_ip = p;
				while (*e_ip != ',' && e_ip < ep) e_ip++;
				len = e_ip - p;
				if (len > 0 && len < sizeof(tmp)) {
					strncpy(tmp, p, len);
					tmp[len] = 0;
					if (parse_ip(tmp, &ip)) {
						logger(-1, 0, "Incorrect veth"
							" ip6 %s, skipped", tmp);
					} else {
						list_add_tail(&ip->list, &dev->ip_list);
					}
				}
				p = ++e_ip;
			} while (p < ep);
		}
	} while ((p = ++next) < ep);
	if (dev->dev_name_ve[0] == 0)
		return VZCTL_E_INVAL;
	if (h)
		fill_empty_veth_dev_param(h, dev);

	return 0;
}

int parse_netif_ifname(struct vzctl_veth_param *veth, const char *str, int op,
		int replace)
{
	int len, id, ret;
	struct vzctl_veth_dev *dev;
	int update_configure = 0;

	if (veth->ifname == NULL) {
		veth->ifname = alloc_veth_dev();
		if (veth->ifname == NULL)
			return VZCTL_E_NOMEM;
	}
	dev = veth->ifname;
	switch (op) {
	case VZCTL_PARAM_NETIF_IFNAME:
		if (dev->dev_name_ve[0] != 0) {
			logger(-1, 0,"Multiple use of --ifname option not"
				" allowed");
			return VZCTL_E_INVAL;
		}
		len = strlen(str);
		if (len > IFNAMSIZE)
			return VZCTL_E_INVAL;
		strcpy(dev->dev_name_ve, str);
		break;
	case VZCTL_PARAM_NETIF_MAC:
		if (set_hwaddr(str, &dev->mac_ve))
			return VZCTL_E_INVAL;
		break;
	case VZCTL_PARAM_NETIF_HOST_IFNAME:
		len = strlen(str);
		if (len > IFNAMSIZE)
			return VZCTL_E_INVAL;
		strcpy(dev->dev_name, str);
		break;
	case VZCTL_PARAM_NETIF_HOST_MAC:
		if (set_hwaddr(str, &dev->mac))
			return VZCTL_E_INVAL;
		break;
	case VZCTL_PARAM_NETIF_GW:
		free(dev->gw);
		dev->gw = strdup(str);
		update_configure = 1;
		break;
	case VZCTL_PARAM_NETIF_GW6:
		free(dev->gw6);
		dev->gw6 = strdup(str);
		break;
	case VZCTL_PARAM_NETIF_DHCP:
		if ((id = yesno2id(str)) == -1)
			return VZCTL_E_INVAL;
		dev->dhcp = id;
		update_configure = 1;
		break;
	case VZCTL_PARAM_NETIF_DHCP6:
		if ((id = yesno2id(str)) == -1)
			return VZCTL_E_INVAL;
		dev->dhcp6 = id;
		update_configure = 1;
		break;
	case VZCTL_PARAM_NETIF_NETWORK:
		if (str[0] != 0 && !vzctl2_is_networkid_valid(str))
			return VZCTL_E_INVAL;
		if (dev->network == NULL)
			dev->network = strdup(str);
		break;
	case VZCTL_PARAM_NETIF_MAC_FILTER:
		if ((id = onoff2id(str)) == -1)
			return VZCTL_E_INVAL;
		dev->mac_filter = id;
		break;
	case VZCTL_PARAM_NETIF_IP_FILTER:
		if ((id = onoff2id(str)) == -1)
			return VZCTL_E_INVAL;
		dev->ip_filter = id;
		break;
	case VZCTL_PARAM_NETIF_CONFIGURE_MODE:
		if (!strcmp(str, "none") ||
				!strcmp(str, "no"))
			dev->configure_mode = VZCTL_VETH_CONFIGURE_NONE;
		else if (!strcmp(str, "all") ||
				!strcmp(str, "yes"))
			dev->configure_mode = VZCTL_VETH_CONFIGURE_ALL;
		else
			return VZCTL_E_INVAL;
		break;
	case VZCTL_PARAM_NETIF_IPADD:
		ret = parse_ip_str(&dev->ip_list, str, replace);
		if (ret)
			return ret;
		update_configure = 1;
		break;
	case VZCTL_PARAM_NETIF_IPDEL:
		if (strcmp(str, "all") == 0)
			dev->ip_delall = 1;
		else {
			ret = parse_ip_str(&dev->ip_del_list, str, replace);
			if (ret)
				return ret;
		}
		break;
	case VZCTL_PARAM_NETIF_NETTYPE:
		ret = get_nettype(str, &dev->nettype);
		if (ret)
			return ret;
		break;
	case VZCTL_PARAM_NETIF_VPORT_TYPE:
		ret = get_vporttype(str, &dev->vporttype);
		if (ret)
			return ret;
		break;
	case VZCTL_PARAM_NETIF_IFACEID:
		ret = xstrdup(&dev->ifaceid, str);
		if (ret)
			return ret;
		break;
	default :
		debug(DBG_CFG, "parse_netif_ifname: unhandled op %d", op);
		break;
	}
	/* set VZCTL_VETH_CONFIGURE_ALL mode on parameters set */
	if (!dev->configure_mode && update_configure)
		dev->configure_mode = VZCTL_VETH_CONFIGURE_ALL;
	return 0;
}

int parse_netif(struct vzctl_env_handle *h, list_head_t *head, const char *val)
{
	int ret = 0;
	char *token, *p;
	struct vzctl_veth_dev *dev;
	char *tmp = NULL;
	char *savedptr;

	ret = xstrdup(&tmp, val);
	if (ret)
		return ret;

	free_veth(head);

	if ((token = strtok_r(tmp, ";", &savedptr)) == NULL) {
		free(tmp);
		return 0;
	}
	do {
		if ((dev = alloc_veth_dev()) == NULL) {
			ret = VZCTL_E_NOMEM;
			break;
		}
		if (parse_netif_str(h, token, dev) == 0) {
			if (find_veth_by_ifname_ve(head, dev->dev_name_ve) == NULL)
			{
				list_add_tail(&dev->list, head);
				dev = NULL;
			}
		} else {
			if ((p = strchr(token, ';')) != NULL)
				*p = 0;
			logger(-1, 0, "Incorrect netif parameter %s", token);
			if (p != NULL)
				*p = ';';
			ret = VZCTL_E_INVAL;
		}
		if (dev != NULL)
			free_veth_dev(dev);
	} while ((token = strtok_r(NULL, ";", &savedptr)) != NULL);
	free(tmp);
	return ret;
}

static int parse_netif_str_cmd(struct vzctl_env_handle *h, const char *str,
		struct vzctl_veth_dev *dev)
{
	const char *ch, *tmp, *ep;
	int len, err;

	ep = str + strlen(str);
	/* Parsing veth device name in Container */
	if ((ch = strchr(str, ',')) == NULL) {
		ch = ep;
		len = ep - str;
	} else {
		len = ch - str;
		ch++;
	}
	if (len > IFNAMSIZE)
		return VZCTL_E_INVAL;
	dev->mac_filter = VZCTL_PARAM_ON;
	snprintf(dev->dev_name_ve, len + 1, "%s", str);
	tmp = ch;
	if (ch == ep)
		return 0;

	/* Parsing veth MAC address in Container */
	if ((ch = strchr(tmp, ',')) == NULL) {
		ch = ep;
		len = ch - tmp;
	} else {
		len = ch - tmp;
		ch++;
	}
	if (len != MAC_SIZE) {
		logger(-1, 0, "Invalid Container MAC address length: %s", tmp);
		return VZCTL_E_INVAL;
	}
	err = set_hwaddr(tmp, &dev->mac_ve);
	if (err) {
		logger(-1, 0, "Invalid Container MAC address format");
		return VZCTL_E_INVAL;
	}
	tmp = ch;
	if (ch == ep) {
		if (dev->mac_ve != NULL)
			set_hwaddr(dev->mac_ve, &dev->mac);
		generate_veth_name(dev);
		return 0;
	}
	/* Parsing veth name in VE0 */
	if ((ch = strchr(tmp, ',')) == NULL) {
		ch = ep;
		len = ch - tmp;
	} else {
		len = ch - tmp;
		ch++;
	}
	if (len > IFNAMSIZE)
		return VZCTL_E_INVAL;
	snprintf(dev->dev_name, len + 1, "%s", tmp);
	if (ch == ep) {
		if (dev->mac_ve != NULL)
			set_hwaddr(dev->mac_ve, &dev->mac);
		return 0;
	}
	/* Parsing veth MAC address in Container */
	len = strlen(ch);
	if (len != MAC_SIZE) {
		logger(-1, 0, "Invalid host MAC address");
		return VZCTL_E_INVAL;
	}
	err = set_hwaddr(ch, &dev->mac);
	if (err) {
		logger(-1, 0, "Invalid host MAC address");
		return VZCTL_E_INVAL;
	}
	return 0;
}

int parse_netif_cmd(struct vzctl_env_handle *h, list_head_t *head, const char *val)
{
	int ret = 0;
	char *token;
	struct vzctl_veth_dev *dev;
	char *tmp = NULL;
	char *savedptr;

	ret = xstrdup(&tmp, val);
	if (ret)
		return ret;

	if ((token = strtok_r(tmp, " ", &savedptr)) == NULL) {
		free(tmp);
		return 0;
	}
	do {
		if ((dev = alloc_veth_dev()) == NULL) {
			ret =  VZCTL_E_NOMEM;
			break;
		}

		if ((ret = parse_netif_str_cmd(h, token, dev)) == 0) {
			if (find_veth_by_ifname_ve(head,
						dev->dev_name_ve) == NULL)
			{
				list_add_tail(&dev->list, head);
				dev = NULL;
			}
		}
		if (dev != NULL)
			free_veth_dev(dev);
	} while ((token = strtok_r(NULL, " ", &savedptr)) != NULL);
	free(tmp);
	return ret;
}
