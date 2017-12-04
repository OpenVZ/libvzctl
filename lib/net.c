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
 */

#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <linux/vzcalluser.h>
#include <linux/vzctl_venet.h>
#include <linux/vzctl_netstat.h>
#include <linux/vzlist.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <linux/if.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>

#include "env.h"
#include "env_configure.h"
#include "vzerror.h"
#include "logger.h"
#include "config.h"
#include "util.h"
#include "list.h"
#include "vz.h"
#include "env_ops.h"
#include "exec.h"

void free_ip_param(struct vzctl_ip_param *ip)
{
	if (ip != NULL) {
		free(ip->ip);
		free(ip);
	}
}

void free_ip(list_head_t *head)
{
	struct vzctl_ip_param *tmp, *it;

	list_for_each_safe(it, tmp, head, list) {
		list_del(&it->list);
		free_ip_param(it);
	}
	list_head_init(head);
}

const struct vzctl_ip_param *find_ip(list_head_t *head,
	struct vzctl_ip_param *ip)
{
	struct vzctl_ip_param *it;

	list_for_each(it, head, list) {
		if (!strcmp(it->ip, ip->ip))
			return it;
	}
	return NULL;
}

void add_ip_param2(list_head_t *head, struct vzctl_ip_param *ip)
{
	list_add_tail(&ip->list, head);
}

struct vzctl_ip_param *new_ip_param(const struct vzctl_ip_param *ip)
{
	struct vzctl_ip_param *new;

	if ((new = calloc(1, sizeof(struct vzctl_ip_param))) == NULL)
		return NULL;

	if (ip != NULL) {
		memcpy(new, ip, sizeof(struct vzctl_ip_param));
		new->ip = strdup(ip->ip);
	}
	return new;
}

struct vzctl_ip_param *add_ip_param(list_head_t *head,
		const struct vzctl_ip_param *ip)
{
	struct vzctl_ip_param *new;

	if ((new = new_ip_param(ip)) != NULL)
		list_add_tail(&new->list, head);
	return new;
}

struct vzctl_ip_param *add_ip_param_str(list_head_t *head, char *str)
{
	struct vzctl_ip_param tmp;

	bzero(&tmp, sizeof(struct vzctl_ip_param));
	tmp.ip = (char *)str;
	return add_ip_param(head, &tmp);
}

int copy_ip_param(list_head_t *dst, list_head_t *src)
{
	struct vzctl_ip_param *it;

	free_ip(dst);
	list_for_each(it, src, list) {
		if (add_ip_param(dst, it) == NULL)
			return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "add_ip_param");
	}
	return 0;
}

int get_ip_str(struct vzctl_ip_param *ip, char *str, int len)
{
	char *sp, *ep;
	int r;

	sp = str;
	ep = str + len;
	r = snprintf(sp, ep - sp, "%s", ip->ip);
	if (r < 0 || sp + r >= ep)
		return VZCTL_E_INVAL;
	sp += r;
	if (ip->mask != 0) {
		if (check_ipv4(ip->ip)) {
			r = snprintf(sp, ep - sp, "/%s",
				get_ip4_name(ip->mask));
		} else {
			r = snprintf(sp, ep - sp, "/%d",
				ip->mask);
		}
		sp += r;
		if (r < 0 || sp + r >= ep)
			return VZCTL_E_INVAL;
	}
	return 0;
}

char *ip2str(const char *prefix, list_head_t *ip, int use_nemask)
{
	struct vzctl_ip_param *it;
	int r, len = 0;
	char ip_str[128];
	char *buf, *sp, *se;

	if (prefix != NULL)
		len = strlen(prefix);
	list_for_each(it, ip, list) {
		len += strlen(it->ip) * 16 + 1;
	}
	if ((buf = malloc(len + 1)) == NULL)
		return NULL;
	*buf = 0;
	sp = buf;
	se = buf + len;
	if (prefix != NULL)
		sp += sprintf(sp, "%s", prefix);
	list_for_each(it, ip, list) {
		if (use_nemask) {
	                if (get_ip_str(it, ip_str, sizeof(ip_str)))
		                continue;
			r = sprintf(sp, "%s ", ip_str);
		} else {
			r = sprintf(sp, "%s ", it->ip);
		}
		sp += r;
		if ((r < 0) || (sp >= se))
			break;
	}
	if (sp > buf && sp[-1] == ' ')
		sp[-1] = '\0';
	return buf;
}

char *ip_param2str(list_head_t *head)
{
	return ip2str(NULL, head, 0);
}

static int do_ip_ctl(unsigned veid, int op, int family, unsigned int *addr)
{
	int addrlen, ret;
	struct sockaddr_in6 sa;

	make_sockaddr(family, addr, (struct sockaddr *)&sa);

	if (family == AF_INET) {
		addrlen = sizeof(struct sockaddr_in);
	} else if (family == AF_INET6) {
		addrlen = sizeof(struct sockaddr_in6);
	} else {
		return -EAFNOSUPPORT;
	}

	switch (op) {
	case VE_IP_ADD:
	case VE_IP_DEL: {
		struct vzctl_ve_ip_map ip_map;

		ip_map.veid = veid;
		ip_map.op = op;
		ip_map.addr = (struct sockaddr *)&sa;
		ip_map.addrlen = addrlen;

		ret = ioctl(get_vzctlfd(), VENETCTL_VE_IP_MAP, &ip_map);
		break;
	}
	default:
		ret = -1;
		break;
	}
	return ret;
}

int vz_ip_ctl(struct vzctl_env_handle *h, int op, const char *ipstr, int flags)
{
	int ret;
	unsigned int addr[4];
	int family;
	const char *mes;

	family = get_netaddr(ipstr, addr);
	if (family == -1)
		return 0;

	ret = do_ip_ctl(h->veid, op, family, addr);
	if (ret) {
		switch (op) {
		case VE_IP_ADD:
			mes = "to add IP address";
			break;
		case VE_IP_DEL:
			if (errno == EADDRNOTAVAIL)
				return 0;
			mes = "to del IP address";
			break;
		default:
			mes = "to process IP";
			break;
		}

		switch (errno) {
		case EADDRNOTAVAIL:
		case EADDRINUSE	:
			logger(-1, 0, "Unable %s %s: address already in use",
				mes, ipstr);
			ret = VZCTL_E_IP_INUSE;
			break;
		case ENOTTY	:
                        logger(-1, 0, "Unable %s %s: modules are not loaded",
				mes, ipstr);
			ret = VZCTL_E_CANT_ADDIP;
			break;
		case ESRCH	:
			logger(-1, 0, "Unable %s %s: Container is not running",
				mes, ipstr);
                        ret = VZCTL_E_ENV_NOT_RUN;
			break;
		default:
			logger(-1, errno, "Unable %s %s", mes, ipstr);
			ret = VZCTL_E_CANT_ADDIP;
			break;
		}
	}
	return ret;
}

#define	PROC_VEINFO	"/proc/vz/veinfo"
int get_env_ip_proc(struct vzctl_env_handle *h, list_head_t *ip)
{
	FILE *fd;
	char str[16384];
	char ip_str[65];
	char *token;
	int cnt = 0;
	char *savedptr;

	if ((fd = fopen(PROC_VEINFO, "r")) == NULL) {
		logger(-1, errno, "Unable to open %s", PROC_VEINFO);
		return -1;
	}
	while (!feof(fd)) {
		if (fgets(str, sizeof(str), fd) == NULL)
			break;
		token = strtok_r(str, " ", &savedptr);
		if (token == NULL)
			continue;
		if (strcmp(EID(h), token))
			continue;
		if ((token = strtok_r(NULL, " ", &savedptr)) != NULL)
			token = strtok_r(NULL, " ", &savedptr);
		if (token == NULL)
			break;
		while ((token = strtok_r(NULL, " \t\n", &savedptr)) != NULL) {
			if (get_ip_name(token, ip_str, sizeof(ip_str)))
				continue;
			if (add_ip_param_str(ip, ip_str) == NULL) {
				free_ip(ip);
				cnt = -1;
				break;
			}
			cnt++;
		}
		break;
	}
	fclose(fd);
	return cnt;
}

int vzctl_get_env_ip(struct vzctl_env_handle *h, list_head_t *ip)
{
	return get_env_ops()->env_get_veip(h, ip);
}

struct vzctl_net_param *alloc_net_param(void)
{
	struct vzctl_net_param *net;

	net = calloc(1, sizeof(struct vzctl_net_param));
	if (net == NULL)
		return NULL;
	list_head_init(&net->ip);
	list_head_init(&net->ip_del);

	return net;
}

void free_net_param(struct vzctl_net_param *net)
{
        free_ip(&net->ip);
        free_ip(&net->ip_del);
        free(net);
}

int run_net_script(struct vzctl_env_handle *h, const char *script,
		list_head_t *ip, int flags)
{
	char *argv[2];
	char *envp[5];
	char veid_str[64];
	char *ip_str;
	char buf[STR_SIZE];
	char s_state[STR_SIZE];
	int ret = 0, i = 0;

	if (list_empty(ip))
		return 0;
	snprintf(veid_str, sizeof(veid_str), "VEID=%s", EID(h));
	envp[i++] = veid_str;
	ip_str = ip2str("IP_ADDR=", ip, 0);
	envp[i++] = ip_str;
	if (flags & VZCTL_SKIP_ARPDETECT)
		envp[i++] = "SKIP_ARPDETECT=yes";
	snprintf(s_state, sizeof(s_state), "VE_STATE=%s", get_state(h));
	envp[i++] = s_state;
	envp[i] = NULL;

	argv[0] = get_script_path(script, buf, sizeof(buf));
	argv[1] = NULL;
	ret = vzctl2_wrap_exec_script(argv, envp, 0);
	free(ip_str);

	return ret;
}

int invert_ip_op(int op)
{
	switch (op) {
	case VE_IP_ADD :
		return VE_IP_DEL;
	case VE_IP_DEL :
		return VE_IP_ADD;
	default:
		assert(0);
	}
	return -1;
}

static int env_ip_ctl(struct vzctl_env_handle *h, int op, list_head_t *head,
		int rollback, int flags)
{
	char *str;
	int ret = 0;
	struct vzctl_ip_param *it;
	int inv_op;

	if ((str = ip2str(NULL, head, 0)) != NULL) {
		logger(0, 0, "%s ip address(es): %s",
			op == VE_IP_ADD ? "Adding" : "Deleting",
			str);
		free(str);
	}

	list_for_each(it, head, list) {
		if ((ret = get_env_ops()->env_ip_ctl(h, op, it->ip, flags)))
			break;
	}
	if (ret && rollback) {
		/* restore original ip state op of error */
		inv_op = invert_ip_op(op);
		for (it = list_entry(it->list.prev, struct vzctl_ip_param,
				list);
			&it->list != (list_elem_t*) head;
			it = list_entry(it->list.prev, struct vzctl_ip_param,
				list))
		{
			get_env_ops()->env_ip_ctl(h, inv_op, it->ip, flags);
		}
	}
	return ret;
}

#define PROCVEIP	"/proc/vz/veip"
int read_proc_veip(struct vzctl_env_handle *h, list_head_t *ip)
{
        char str[STR_SIZE];
        char tmp[65];
        int id, ret;
        FILE *fp;

        if ((fp = fopen(PROCVEIP, "r")) == NULL)
                return -1;
	ret = 0;
        while (!feof(fp)) {
		if (fgets(str, sizeof(str), fp) == NULL)
			break;

                if (sscanf(str, "%64s %d", tmp, &id) != 2)
                        continue;

                if (id != h->veid)
			continue;

//		if (get_ip_name(tmp, ip_str, sizeof(ip_str)))
//			continue;
		if (add_ip_param_str(ip, tmp) == NULL) {
			free_ip(ip);
			break;
		}
        }
        fclose(fp);
        return ret;
}

static int add_ip(struct vzctl_env_handle *h, struct vzctl_env_param *env, int flags)
{
	int ret = 0;
	struct vzctl_ip_param *it;
	struct vzctl_net_param *net = env->net;
	int delall = net->delall;
	LIST_HEAD(ipadd);
	LIST_HEAD(iprun);

	if (list_empty(&net->ip))
		return 0;

	if (vzctl_get_env_ip(h, &iprun) < 0)
		return vzctl_err(-1, 0, "Unable to get the list of assigned"
			" ip addresses");
	/* Skip already assigned ips */
	list_for_each(it, &net->ip, list) {
		if (find_ip(&iprun, it) == NULL) {
			if (add_ip_param(&ipadd, it) == NULL) {
				ret = VZCTL_E_NOMEM;
				goto out;
			}
		}
	}
	/* Setup in kernel */
	if ((ret = env_ip_ctl(h, VE_IP_ADD, &ipadd, 1, flags)))
		goto err_pool;
	/* Setup on node */
	if ((ret = run_net_script(h, VZCTL_NET_ADD, &ipadd, flags)))
		goto err_hn;

	/* Setup inside Container */
	if ((ret = env_ip_configure(h, VZCTL_IP_ADD_CMD, &ipadd, delall, flags)))
		goto err_hn;

out:
	free_ip(&ipadd);
	free_ip(&iprun);
	return ret;

err_hn:
	/* remove from HN */
	run_net_script(h, VZCTL_NET_DEL, &ipadd, flags);

	/* remove from kernel */
	env_ip_ctl(h, VE_IP_DEL, &net->ip, 0, flags);

err_pool:
	free_ip(&ipadd);
	free_ip(&iprun);
	return ret;
}

static int del_ip(struct vzctl_env_handle *h, struct vzctl_env_param *env, int flags)
{
	int ret = 0;
	struct vzctl_ip_param *it;
	struct vzctl_net_param *net = env->net;
	int delall = net->delall || h->ctx->state == VZCTL_STATE_STARTING;
	list_head_t *ip = &net->ip_del;
	LIST_HEAD(ipdel);
	LIST_HEAD(iprun);

	if (list_empty(ip) && !delall)
		return 0;

	vzctl_get_env_ip(h, &iprun);
	if (delall)
		ip = &iprun; // use configured
	if (list_empty(ip))
		goto out;

	list_for_each(it, ip, list) {
		if (find_ip(&iprun, it) == NULL) {
			logger(0, 0, "Container doesn't have IP %s", it->ip);
			continue;
		}
		if (add_ip_param(&ipdel, it) == NULL) {
			ret = VZCTL_E_NOMEM;
			goto out;
		}
	}
	/* Setup on node */
	run_net_script(h, VZCTL_NET_DEL, &ipdel, flags);
	/* Setup inside Container */
	if (!(flags & VZCTL_SKIP_CONFIGURE))
		env_ip_configure(h, VZCTL_IP_DEL_CMD, &ipdel, delall, flags);
	/* Setup in kernel */
	env_ip_ctl(h, VE_IP_DEL, &ipdel, 1, flags);
out:
        free_ip(&ipdel);
        free_ip(&iprun);
	return ret;
}

static int check_netdev(const char *devname)
{
	int i, len;
	const char *name;
	static char *netdev_strict[] = {"venet", "tun", "tap", "lo", NULL};

	for (i = 0; netdev_strict[i] != NULL; i++) {
		name = netdev_strict[i];
		len = strlen(name);
		if (!strncmp(name, devname, len))
			return 1;
	}
	return 0;
}

int parse_netdev(list_head_t *netdev, const char *val, int replace)
{
	char *token;
	char *buf;
	int ret = 0;
	char *savedptr;

	if (replace)
		free_str(netdev);

	buf = strdup(val);
	if ((token = strtok_r(buf, LIST_DELIMITERS, &savedptr)) != NULL) {
		do {
			if (check_netdev(token))
				return VZCTL_E_INVAL;
			if (add_str_param(netdev, token) == NULL) {
				ret = VZCTL_E_NOMEM;
				break;
			}
		} while ((token = strtok_r(NULL, LIST_DELIMITERS, &savedptr)));
	}
	free(buf);
	return ret;
}

char *netdev2str(struct vzctl_netdev_param *old, struct vzctl_netdev_param *new)
{
	char *buf;
	LIST_HEAD(merged);

	if (list_empty(&new->dev) &&
			list_empty(&new->dev_del))
		return NULL;

	merge_str_list(&old->dev, &new->dev, &new->dev_del, 0, &merged);

	buf = list2str(NULL, &merged);

	free_str(&merged);

	return buf;
}

struct vzctl_netdev_param *alloc_netdev_param(void)
{
	struct vzctl_netdev_param *new;

	new = malloc(sizeof(struct vzctl_netdev_param));
	if (new == NULL)
		return NULL;
	list_head_init(&new->dev);
	list_head_init(&new->dev_del);
	return new;
}

void free_netdev_param(struct vzctl_netdev_param *param)
{
	free_str(&param->dev);
	free(param);
}

int vz_netdev_ctl(struct vzctl_env_handle *h, int add, const char *dev)
{
	struct vzctl_ve_netdev netdev = {
		.veid = h->veid,
		.op = add ? VE_NETDEV_ADD : VE_NETDEV_DEL,
		.dev_name = (char *)dev
	};

	if (ioctl(get_vzctlfd(), VZCTL_VE_NETDEV, &netdev))
		return vzctl_err(VZCTL_E_NETDEV, errno,	"Unable to %s netdev %s",
				add ? "add": "del", dev);

	return 0;
}

static int netdev_ctl(struct vzctl_env_handle *h, int add, list_head_t *netdev)
{
	int ret;
	struct vzctl_str_param *it;

	list_for_each(it, netdev, list) {
		logger(0, 0, "%s the network device: %s",
				add ? "Add": "Del", it->str);
		ret = get_env_ops()->env_netdev_ctl(h, add, it->str);
		if (ret)
			return ret;
	}

	return 0;
}

int apply_netdev_param(struct vzctl_env_handle *h, struct vzctl_env_param *env,
		int flags)
{
	int ret;

	if (!is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_NOT_RUN, 0, "Unable to setup"
				" network devices: Container is not running");

	ret = netdev_ctl(h, 0, &env->netdev->dev_del);
	if (ret == 0)
		ret = netdev_ctl(h, 1, &env->netdev->dev);

	return ret;
}

static int remove_ipv6_addr(struct vzctl_net_param *net)
{
	list_head_t *head = &net->ip;
	struct vzctl_ip_param *it, *tmp;
	int cnt;

	cnt = 0;
	list_for_each_safe(it, tmp, head, list) {
		if (strchr(it->ip, ':')) {
			free(it->ip);
			list_del(&it->list);
			free(it);
			cnt++;
		}
	}
	return cnt;
}

int apply_venet_param(struct vzctl_env_handle *h, struct vzctl_env_param *env, int flags)
{
	int ret;
	struct vzctl_net_param *net = env->net;

	if (list_empty(&net->ip) &&
	    list_empty(&net->ip_del) &&
	    !net->delall)
		return 0;

	if (!is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_NOT_RUN, 0, "Unable to apply ip"
				" parameters: Container is not running");
	if (vzctl2_env_get_param_bool(h, "IPV6") != VZCTL_PARAM_ON) {
		if (remove_ipv6_addr(net))
			logger(0, 0, "Warning: ipv6 support disabled");
	}

	if ((ret = del_ip(h, env, flags)))
		return ret;
	if ((ret = add_ip(h, env, flags)))
		return ret;

	return 0;
}

int relase_venet_ips(struct vzctl_env_handle *h)
{
	int ret;
	LIST_HEAD(ip);

	vzctl_get_env_ip(h, &ip);
	if (list_empty(&ip))
		return 0;

	ret = env_ip_ctl(h, VE_IP_DEL, &ip, 0, 0);
	free_ip(&ip);

	return ret;
}

int set_net_hwcsum(const char *devname, int on)
{
	int fd, err;
	struct ifreq ifr;
	struct ethtool_value val;

	if (strlen(devname) >= IFNAMSIZ) {
		logger(-1, 0, "Invalid device name %s", devname);
		return -1;
	}

	logger(2, 0, "Set csum on for %s", devname);
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		logger(-1, errno, "Unable to create socket");
		return -1;
	}

	strcpy(ifr.ifr_name, devname);
	val.cmd = ETHTOOL_SRXCSUM;
	val.data = on;
	ifr.ifr_data = &val;
	if ((err = ioctl(fd, SIOCETHTOOL, &ifr)))
		goto err;

	val.cmd = ETHTOOL_STXCSUM;
	val.data = on;
	ifr.ifr_data = &val;
	if ((err = ioctl(fd, SIOCETHTOOL, &ifr)))
		goto err;

	val.cmd = ETHTOOL_SSG;
	val.data = on;
	ifr.ifr_data = &val;
	ioctl(fd, SIOCETHTOOL, &ifr);

err:
	close(fd);
	if (err) {
		logger(-1, errno, "Unable to turn on csum");
		return -1;
	}
	return 0;
}

void configure_net_rps(const char *ve_root, const char *dev)
{
	char fname[PATH_MAX];
	struct vzctl_cpumask cpumask = {};
	int fd, n;

	if (get_online_cpumask(&cpumask))
		return;

	logger(10, 0, "Configure RPS: %s cpus=%lx", dev, cpumask.mask[0]);
	snprintf(fname, sizeof(fname),
			"%s/sys/class/net/%s/queues/rx-0/rps_cpus",
			ve_root, dev);
	fd = open(fname, O_RDWR);
	if (fd == -1)
		return;

	n = dprintf(fd, "%lx", cpumask.mask[0]);
	if (n == -1)
		logger(-1, errno, "Failed to write '%lx' to %s",
				cpumask.mask[0], fname);
	close(fd);
}

int vzctl2_clear_ve_netstat(struct vzctl_env_handle *h)
{
	int rc;

	rc = ioctl(get_vzctlfd(), VZCTL_TC_CLEAR_STAT, h->veid);

	if (rc && errno == ENOTTY)
		rc = ioctl(get_vzctlfd(), VZCTL_TC_DESTROY_STAT, h->veid);

	if (rc == 0 || errno == ESRCH)
		return 0;

	return -1;
}

int vzctl2_clear_all_ve_netstat(void)
{
	int rc;

	rc = ioctl(get_vzctlfd(), VZCTL_TC_CLEAR_ALL_STAT);

	if (rc && errno == ENOTTY)
		rc = ioctl(get_vzctlfd(), VZCTL_TC_DESTROY_ALL_STAT);

	return rc;
}

int vzctl2_get_env_tc_netstat(struct vzctl_env_handle *h,
		struct vzctl_tc_netstat *stat, int v6)
{
	int ret;

	if (h == NULL || stat == NULL)
		return -1;

	struct vzctl_tc_get_stat s = {
		.veid = h->veid,
		.incoming = stat->incoming,
		.outgoing = stat->outgoing,
		.incoming_pkt = stat->incoming_pkt,
		.outgoing_pkt = stat->outgoing_pkt,
		.length = TC_MAX_CLASSES,
	};

	bzero(stat, sizeof(struct vzctl_tc_netstat));
	ret = ioctl(get_vzctlfd(),
			v6 ? VZCTL_TC_GET_STAT_V6 : VZCTL_TC_GET_STAT, &s);
	if (ret == -1 && errno != ESRCH && errno != ENOTTY)
		return -1;

	return 0;
}

static int get_netstat(const char *dir, const char *name, unsigned long long* out)
{
	char path[PATH_MAX];
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	f = fopen(path, "r");
	if (f == NULL)
		return -1;

	if (fscanf(f, "%llu", out) != 1)
		*out = 0;
	fclose(f);

	return 0;
}

int vzctl2_get_env_netstat(const ctid_t ctid, const char *dev,
		struct vzctl_netstat *stat, int size)
{
	char d[PATH_MAX];
	struct vzctl_netstat s = {};

	if (strcmp(dev, "venet0") == 0) {
		pid_t pid;

		if (read_init_pid(ctid, &pid))
			return -1;
		snprintf(d, sizeof(d), "/proc/%d/root/sys/class/net/%s/statistics",
				(int) pid, dev);
	} else {
		snprintf(d, sizeof(d), "/sys/class/net/%s/statistics", dev);
	}

	if (get_netstat(d, "rx_bytes", &s.incoming) ||
			get_netstat(d, "rx_packets", &s.incoming_pkt) ||
			get_netstat(d, "tx_bytes", &s.outgoing) ||
			get_netstat(d, "tx_packets", &s.outgoing_pkt))
		return -1;

	memcpy(stat, &s, size);

	return 0;
}

void vzctl2_release_net_info(struct vzctl_net_info *info)
{
	if (info == NULL)
		return;

	free(info->if_ips);
	free(info);
}

static int get_net_info(ctid_t ctid, const char *ifname,
		struct vzctl_net_info *info)
{
	int ret = 0;
	FILE *fp;
	char ip[STR_SIZE];
	char buf[STR_SIZE];
	LIST_HEAD(ips);
	char *arg[] = {"/usr/sbin/ip", "netns", "exec", ctid, "ip", "a", "l",
			"dev", (char *) ifname, NULL};

	fp = vzctl_popen(arg, NULL, 0);
	if (fp == NULL)
		return VZCTL_E_SYSTEM;

	while (fgets(buf, sizeof(buf), fp)) {
		int n;

		if (sscanf(buf, "%d:", &n) == 1 && strstr(buf, ",UP")) {
			info->if_up = 1;
			continue;
		} else if (sscanf(buf, "%*[\t ]inet%*[6 ] %s", ip) != 1)
			continue;

		if (strncmp(ip, "127.", 4) == 0 ||
				strncmp(ip, "::1/", 4) == 0 ||
				strncmp(ip, "::2/", 4) == 0 ||
				strncmp(ip, "fe80:", 5) == 0)
			continue;

		if (add_str_param(&ips, ip) == NULL) {
			ret = VZCTL_E_NOMEM;
			goto err;
		}
	}

	info->if_ips = list2str(NULL, &ips);

err:
	free_str(&ips);
	vzctl_pclose(fp);

	return ret;
}

int vzctl2_get_net_info(struct vzctl_env_handle *h, const char *ifname,
		struct vzctl_net_info **info)
{
	int ret;

	if (ifname == NULL)
		return VZCTL_E_INVAL;

	if (!is_env_run(h))
		return VZCTL_E_ENV_NOT_RUN;

	*info = calloc(1, sizeof(struct vzctl_net_info));
	if (*info == NULL)
		return VZCTL_E_NOMEM;

	ret = get_net_info(EID(h), ifname, *info);
	if (ret) {
		vzctl2_release_net_info(*info);
		*info = NULL;
	}

	return ret;
}
