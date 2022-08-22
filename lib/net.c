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
 */

#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <linux/vzctl_netstat.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <linux/if.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <json-c/json.h>

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
#include "cgroup.h"

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

static int netdev_ctl(struct vzctl_env_handle *h, int add, list_head_t *netdev)
{
	int ret;
	struct vzctl_str_param *it;

	list_for_each(it, netdev, list) {
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

#define NFT_CMD "/usr/sbin/nft"

static int run_nft_cmd(char **argv, char **out)
{
	int ret = VZCTL_E_SYSTEM;
	int status, exitcode;
	size_t size = STR_MAX;
	char *buf = NULL;
	FILE *fd = NULL;

	if ((fd = vzctl_popen(argv, NULL, 0)) == NULL)
		return vzctl_err(ret, errno, "Unable to start %s command",
			argv[0]);

	if (out) {
		char *p;
		size_t n, sz;

		if ((buf = malloc(size)) == NULL) {
			ret = VZCTL_E_NOMEM;
			goto err;
		}

		p = buf;
		sz = size;
		while ((n = fread(p, 1, sz, fd)) == sz) {
			n = (p - buf) + sz;
			size *= 2;
			sz = size - n;

			if ((buf = realloc(buf, size)) == NULL) {
				ret = VZCTL_E_NOMEM;
				goto err;
			}

			p = buf + n;
		}

		if (ferror(fd)) {
			ret = vzctl_err(VZCTL_E_PIPE, errno,
				"Reading failed with code %d",
				errno);
			goto err;
		}

		p[n] = '\0';
	}

	status = vzctl_pclose(fd);
	fd = NULL;

	if ((exitcode = WEXITSTATUS(status))) {
		vzctl_err(ret, errno, "Command %s failed with code %d",
			argv[0], exitcode);
		goto err;
	}

	ret = VZCTL_E_OK;

	if (out) {
		*out = buf;
		buf = NULL;
	}

err:
	free(buf);
	if (fd)
		vzctl_pclose(fd);

	return ret;
}

/*
 * ctid2nft()
 * Compute and return CTID without possible symbols "-".
 * ATTENTION! If you modify this function you MUST also  modify
 * the same code in file "vz-functions" in function "vzget_nft"!
 */
static char *ctid2nft(struct vzctl_env_handle *h, ctid_t nft)
{
	char *p = nft;

	strncpy(nft, EID(h), sizeof(ctid_t));
	nft[sizeof(ctid_t) - 1] = '\0';

	while ((p = strchr(p, '-')) != NULL)
		memmove(p, p+1, strlen(p) + 1);

	return nft;
}

static int exist_nft_table(struct vzctl_env_handle *h)
{
	ctid_t ctid;
	char ve[STR_SIZE];
	char *argv[] = {NFT_CMD, "list", "counters", "table", "netdev", ve, NULL};

	snprintf(ve, sizeof(ve), "ve_%s", ctid2nft(h, ctid));

	return run_nft_cmd(argv, NULL);
}

int vzctl2_clear_ve_netstat(struct vzctl_env_handle *h)
{
	ctid_t ctid;
	char ve[STR_SIZE];
	char *argv[] = {NFT_CMD, "reset", "counters", "table", "netdev", ve, NULL};

	if (exist_nft_table(h))
		return 0;

	snprintf(ve, sizeof(ve), "ve_%s", ctid2nft(h, ctid));

	return run_nft_cmd(argv, NULL);
}

int vzctl2_clear_all_ve_netstat(void)
{
	char *argv[] = {NFT_CMD, "reset", "counters", "netdev", NULL};

	return run_nft_cmd(argv, NULL);
}

static json_object *json_get_key(json_object *obj, const char *key)
{
	struct json_object_iterator it = json_object_iter_begin(obj);
	struct json_object_iterator ie = json_object_iter_end(obj);

	for (; !json_object_iter_equal(&it, &ie); json_object_iter_next(&it)) {
		const char *name = json_object_iter_peek_name(&it);
		if (strcmp(name, key) == 0)
			return json_object_iter_peek_value(&it);
	}

	return NULL;
}

static const char *json_get_key_string(json_object *obj, const char *key)
{
	json_object *val = json_get_key(obj, key);
	if (val == NULL || json_object_get_type(val) != json_type_string)
		return NULL;

	return json_object_get_string(val);
}

int vzctl2_get_env_tc_netstat(struct vzctl_env_handle *h,
		struct vzctl_tc_netstat *stat, int v6)
{
	int ret = VZCTL_E_SYSTEM;
	char *out = NULL;
	char ve[STR_SIZE];
	char *argv[] = {NFT_CMD, "-j", "list", "counters", "table", "netdev", ve, NULL};
	ctid_t ctid;
	json_tokener *tok = NULL;
	json_object *obj = NULL;
	json_object *tbl;
	enum json_tokener_error jerr;
	size_t i;

	if (h == NULL || stat == NULL)
		return VZCTL_E_INVAL_PARAMETER_SYNTAX;

	bzero(stat, sizeof(struct vzctl_tc_netstat));

	if (exist_nft_table(h))
		return VZCTL_E_OK;

	snprintf(ve, sizeof(ve), "ve_%s", ctid2nft(h, ctid));

	if ((ret = run_nft_cmd(argv, &out)) != 0)
		goto err;

	tok = json_tokener_new();
	obj = json_tokener_parse_ex(tok, out, strlen(out));
	if ((jerr = json_tokener_get_error(tok)) != json_tokener_success) {
		ret = vzctl_err(VZCTL_E_INVAL, 0,
			"Unable to parse json: %s",
			json_tokener_error_desc(jerr));
		goto err;
	}

	if ((tbl = json_get_key(obj, "nftables")) == NULL) {
		ret = vzctl_err(VZCTL_E_INVAL, 0, "Unable to get json table");
		goto err;
	}

	if (json_object_get_type(tbl) != json_type_array) {
		ret = vzctl_err(VZCTL_E_INVAL, 0, "Uncompatible json format");
		goto err;
	}

	for (i = 0; i < json_object_array_length(tbl); i++) {
		json_object *el = json_object_array_get_idx(tbl, i);
		json_object *item = json_get_key(el, "counter");

		if (item) {
			const char *name = json_get_key_string(item, "name");
			json_object *pks = json_get_key(item, "packets");
			json_object *bts = json_get_key(item, "bytes");

			if (name && pks && bts) {
				char dir, ver;
				unsigned int cls;

				if (sscanf(name, "counter_%c%c_%u",
				    &dir, &ver, &cls) != 3 ||
				    (dir != 'i' && dir != 'o') ||
				    (ver != '4' && ver != '6') ||
				    (ver == '4' && v6) || (ver == '6' && !v6) ||
				    cls >= TC_MAX_CLASSES)
					continue;

				if (dir == 'i') {
					stat->incoming_pkt[cls] =
						json_object_get_int(pks);
					stat->incoming[cls] =
						json_object_get_uint64(bts);
				} else {
					stat->outgoing_pkt[cls] =
						json_object_get_int(pks);
					stat->outgoing[cls] =
						json_object_get_uint64(bts);
				}
			}
		}
	}

	ret = VZCTL_E_OK;

err:
	json_object_put(obj);
	json_tokener_free(tok);
	free(out);

	return ret;
}

/*
 * vzctl2_get_all_tc_netstat()
 * Get stat information about all domain.
 * The caller is responsible for freeing @stat when no longer needed.
 * Returns 0 in case of success, or error code in case of failure.
 * @param stat	return pointer to array of stat
 * @param size	return size of stat array in elements
 */
int vzctl2_get_all_tc_netstat(struct vzctl_all_tc_netstat **stat, int *size)
{
	int ret = VZCTL_E_SYSTEM;
	char *out = NULL;
	char *argv[] = {NFT_CMD, "-j", "list", "counters", "netdev", NULL};
	ctid_t last_ctid = "";
	struct vzctl_all_tc_netstat *s = NULL;
	json_tokener *tok = NULL;
	json_object *obj = NULL;
	json_object *tbl;
	enum json_tokener_error jerr;
	size_t cnt = 0;
	size_t max = 32;
	size_t i;

	if (stat == NULL && size == NULL)
		return VZCTL_E_INVAL_PARAMETER_SYNTAX;

	if ((s = calloc(max, sizeof(*s))) == NULL)
		return VZCTL_E_NOMEM;

	if ((ret = run_nft_cmd(argv, &out)) != 0)
		goto err;

	tok = json_tokener_new();
	obj = json_tokener_parse_ex(tok, out, strlen(out));
	if ((jerr = json_tokener_get_error(tok)) != json_tokener_success) {
		ret = vzctl_err(VZCTL_E_INVAL, 0,
			"Unable to parse json: %s",
			json_tokener_error_desc(jerr));
		goto err;
	}

	if ((tbl = json_get_key(obj, "nftables")) == NULL) {
		ret = vzctl_err(VZCTL_E_INVAL, 0, "Unable to get json table");
		goto err;
	}

	if (json_object_get_type(tbl) != json_type_array) {
		ret = vzctl_err(VZCTL_E_INVAL, 0, "Uncompatible json format");
		goto err;
	}

	for (i = 0; i < json_object_array_length(tbl); i++) {
		json_object *el = json_object_array_get_idx(tbl, i);
		json_object *item = json_get_key(el, "counter");

		if (item) {
			const char *table = json_get_key_string(item, "table");
			const char *name = json_get_key_string(item, "name");
			json_object *pks = json_get_key(item, "packets");
			json_object *bts = json_get_key(item, "bytes");

			if (table && name && pks && bts) {
				ctid_t ctid;
				char dir, ver;
				unsigned int cls;
				unsigned int *pkt;
				unsigned long long *bytes;
				int ctid_num;

				if (strncmp(table, "ve_", 3))
					continue;

				if (vzctl2_get_normalized_uuid(table + 3, ctid, sizeof(ctid))) {
					if (parse_int(table + 3, &ctid_num) || ctid_num < 0)
							continue;
					snprintf(ctid, sizeof(ctid), "%d", ctid_num);
				}

				if (sscanf(name, "counter_%c%c_%u",
				    &dir, &ver, &cls) != 3 ||
				    (dir != 'i' && dir != 'o') ||
				    (ver != '4' && ver != '6') ||
				    cls >= TC_MAX_CLASSES)
					continue;

				if (strcmp(ctid, last_ctid)) {
					if (strlen(last_ctid))
						cnt++;

					if (cnt == max - 1) {
						max *= 2;
						if ((s = realloc(s, max * sizeof(*s))) == NULL) {
							ret = VZCTL_E_NOMEM;
							goto err;
						}
					}

					bzero(&s[cnt], sizeof(*s));
					strncpy(s[cnt].ctid, ctid, sizeof(ctid));
					strncpy(last_ctid, ctid, sizeof(last_ctid));
				}

				if (ver == '4') {
					pkt = (dir == 'i') ? &s[cnt].v4.incoming_pkt[cls] :
						&s[cnt].v4.outgoing_pkt[cls];
					bytes = (dir == 'i') ? &s[cnt].v4.incoming[cls] :
						&s[cnt].v4.outgoing[cls];
				} else {
					pkt = (dir == 'i') ? &s[cnt].v6.incoming_pkt[cls] :
						&s[cnt].v6.outgoing_pkt[cls];
					bytes = (dir == 'i') ? &s[cnt].v6.incoming[cls] :
						&s[cnt].v6.outgoing[cls];
				}

				*pkt = json_object_get_int(pks);
				*bytes = json_object_get_uint64(bts);
			}
		}
	}

	*size = strlen(last_ctid) ? cnt + 1 : 0;
	*stat = s;
	s = NULL;

	ret = VZCTL_E_OK;

err:
	json_object_put(obj);
	json_tokener_free(tok);
	free(out);
	free(s);

	return ret;
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
	int venet = strcmp(dev, "venet0") == 0;

	if (venet) {
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

	stat->incoming = venet ? s.incoming : s.outgoing;
	stat->incoming_pkt = venet ? s.incoming_pkt : s.outgoing_pkt;
	stat->outgoing = venet ? s.outgoing : s.incoming;
	stat->outgoing_pkt = venet? s.outgoing_pkt :s.incoming_pkt;

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
	char *arg[] = {"/usr/sbin/ip", "-n", ctid, "a", "l",
		ifname ? "dev" : NULL, (char *) ifname, NULL};

	fp = vzctl_popen(arg, NULL, 0);
	if (fp == NULL)
		return VZCTL_E_SYSTEM;

	while (fgets(buf, sizeof(buf), fp)) {
		int n;

		if (sscanf(buf, "%d:", &n) == 1 && strstr(buf, ",UP")) {
			info->if_up = 1;
			continue;
		} else if (sscanf(buf, "%*[\t ]ine%*[t6] %s", ip) != 1)
			continue;

		if (strncmp(ip, "127.", 4) == 0 ||
				strncmp(ip, "::1/", 4) == 0 ||
				strncmp(ip, "::2/", 4) == 0 ||
				strncmp(ip, "fe80:", 5) == 0)
			continue;

		char *p = strrchr(ip, '/');
		if (p != NULL)
			*p = '\0';

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
