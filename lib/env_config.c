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

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>

#include "env.h"
#include "cpu.h"
#include "veth.h"
#include "dev.h"
#include "net.h"
#include "io.h"
#include "meminfo.h"
#include "iptables.h"
#include "list.h"
#include "vzctl_param.h"
#include "config.h"
#include "util.h"
#include "logger.h"
#include "vzerror.h"
#include "vztypes.h"
#include "vz.h"
#include "env_configure.h"
#include "disk.h"
#include "bindmount.h"
#include "env_ops.h"

static const struct vzctl_config_param *vzctl_get_conf_param(
	struct vzctl_data_param *data);

static struct vzctl_config_param config_param_map[] = {
/*	ip param	*/
{"IP_ADDRESS",	VZCTL_PARAM_IP_ADDRESS},
/*      fs param	*/
{"VE_ROOT",	VZCTL_PARAM_VE_ROOT},
{"VE_PRIVATE",	VZCTL_PARAM_VE_PRIVATE},
{"TEMPLATE",	VZCTL_PARAM_TEMPLATE},
{"TEMPLATES",	VZCTL_PARAM_TEMPLATES},
/*	tmpl		*/
{"OSTEMPLATE",	VZCTL_PARAM_OSTEMPLATE},
/*	veth parm	*/
{"NETIF",	VZCTL_PARAM_NETIF},
/* DISK */
{"DISK",	VZCTL_PARAM_DISK},
/*	UBC		*/
{"LOCKEDPAGES",	VZCTL_PARAM_LOCKEDPAGES},
{"PRIVVMPAGES",	VZCTL_PARAM_PRIVVMPAGES},
{"SHMPAGES",	VZCTL_PARAM_SHMPAGES},
{"NUMPROC",	VZCTL_PARAM_NUMPROC},
{"PHYSPAGES",	VZCTL_PARAM_PHYSPAGES},
{"VMGUARPAGES",	VZCTL_PARAM_VMGUARPAGES},
{"NUMTCPSOCK",	VZCTL_PARAM_NUMTCPSOCK},
{"NUMFLOCK",	VZCTL_PARAM_NUMFLOCK},
{"NUMPTY",	VZCTL_PARAM_NUMPTY},
{"NUMSIGINFO",	VZCTL_PARAM_NUMSIGINFO},
{"TCPSNDBUF",	VZCTL_PARAM_TCPSNDBUF},
	{"TCPSENDBUF",  VZCTL_PARAM_TCPSNDBUF, "TCPSNDBUF"},
{"TCPRCVBUF",   VZCTL_PARAM_TCPRCVBUF},
{"OTHERSOCKBUF",VZCTL_PARAM_OTHERSOCKBUF},
{"DGRAMRCVBUF",	VZCTL_PARAM_DGRAMRCVBUF},
{"NUMOTHERSOCK",VZCTL_PARAM_NUMOTHERSOCK},
{"NUMFILE",	VZCTL_PARAM_NUMFILE},
{"NUMIPTENT",	VZCTL_PARAM_NUMIPTENT},
	{"IPTENTRIES",	VZCTL_PARAM_NUMIPTENT, "NUMIPTENT"},
{"AVNUMPROC",	VZCTL_PARAM_AVNUMPROC},
{"SWAPPAGES",	VZCTL_PARAM_SWAPPAGES},
{"KMEMSIZE",	VZCTL_PARAM_KMEMSIZE},
{"VM_OVERCOMMIT",	VZCTL_PARAM_VM_OVERCOMMIT},
/*	Old 2.6 UBC	*/
{"TOTVMPAGES",	VZCTL_PARAM_TOTVMPAGES},
{"IPCSHMPAGES",	VZCTL_PARAM_IPCSHMPAGES},
{"ANONSHPAGES",	VZCTL_PARAM_ANONSHPAGES},
{"RSSPAGES",	VZCTL_PARAM_RSSPAGES},
{"OOMGUAR",	VZCTL_PARAM_OOMGUAR},
{"NUMSOCK",	VZCTL_PARAM_NUMSOCK},
{"UNIXSOCKBUF",	VZCTL_PARAM_UNIXSOCKBUF},
{"SOCKRCVBUF",	VZCTL_PARAM_SOCKRCVBUF},
{"NUMUNIXSOCK",	VZCTL_PARAM_NUMUNIXSOCK},

/*	Disk quota	*/
{"DISK_QUOTA",	VZCTL_PARAM_DISK_QUOTA},
{"DISKSPACE",	VZCTL_PARAM_DISKSPACE},
{"DISKINODES",	VZCTL_PARAM_DISKINODES},
{"QUOTAUGIDLIMIT", VZCTL_PARAM_QUOTAUGIDLIMIT},
{"JOURNALED_QUOTA", VZCTL_PARAM_JOURNALED_QUOTA},
{"QUOTATIME",	VZCTL_PARAM_QUOTATIME},

/*	CPU		*/
{"CPULIMIT",	VZCTL_PARAM_CPULIMIT},
{"CPULIMIT_MHZ",VZCTL_PARAM_CPULIMIT_MHZ},
{"CPUWEIGHT",	VZCTL_PARAM_CPUWEIGHT},
{"CPUUNITS",	VZCTL_PARAM_CPUUNITS},
{"CPUS",	VZCTL_PARAM_CPUS},
{"CPUMASK",	VZCTL_PARAM_CPUMASK},
{"NODEMASK",	VZCTL_PARAM_NODEMASK},

{"DISTRIBUTION",VZCTL_PARAM_DISTRIBUTION},
/*	Features	*/
{"FEATURES",	VZCTL_PARAM_FEATURES},
{"TECHNOLOGIES",VZCTL_PARAM_TECHNOLOGIES},

{"NAME",	VZCTL_PARAM_NAME},

/*      Devices */
{"DEVICES",	VZCTL_PARAM_DEVICES},
{"DEVNODES",	VZCTL_PARAM_DEVNODES},
{"NETDEV",	VZCTL_PARAM_NETDEV},
{"PCI",		VZCTL_PARAM_PCI},

{"IPTABLES",	VZCTL_PARAM_IPTABLES},
{"NETFILTER",	VZCTL_PARAM_NETFILTER},
{"IOPRIO",	VZCTL_PARAM_IOPRIO},
{"IOLIMIT",	VZCTL_PARAM_IOLIMIT},
{"IOPSLIMIT",	VZCTL_PARAM_IOPSLIMIT},
/* Global parameters */
{"LOCKDIR",	VZCTL_PARAM_LOCKDIR},

/* meminfo */
{"MEMINFO",	VZCTL_PARAM_MEMINFO},

{"ONBOOT",	VZCTL_PARAM_ONBOOT},
{"AUTOSTOP",VZCTL_PARAM_AUTOSTOP},
	{"AUTOSTOPSTOP",VZCTL_PARAM_AUTOSTOP, "AUTOSTOP"},
{"DESCRIPTION",	VZCTL_PARAM_DESCRIPTION},
{"HOSTNAME",	VZCTL_PARAM_HOSTNAME},
{"SEARCHDOMAIN",VZCTL_PARAM_SEARCHDOMAIN},
{"NAMESERVER",	VZCTL_PARAM_NAMESERVER},
{"VE_TYPE",	VZCTL_PARAM_VE_TYPE},
{"UUID",	VZCTL_PARAM_VE_UUID},
{"APPLY_IPONLY",VZCTL_PARAM_APPLY_IPONLY},
{"OSRELEASE",	VZCTL_PARAM_OSRELEASE},

{"USE_NET_RPS",	VZCTL_PARAM_USE_NET_RPS},

/* High Availability Cluster */
{"HA_ENABLE",	VZCTL_PARAM_HA_ENABLE},
{"HA_PRIO",	VZCTL_PARAM_HA_PRIO},

{"BINDMOUNT",	VZCTL_PARAM_BINDMOUNT},
{"VE_ENVIRONMENT", VZCTL_PARAM_VE_ENVIRONMENT},
{"NOATIME",	VZCTL_PARAM_NOATIME},

{"ORIGIN_SAMPLE", VZCTL_PARAM_ORIGIN_SAMPLE},
{"DISABLED",	VZCTL_PARAM_DISABLED},
{"AUTOCOMPACT",	VZCTL_PARAM_AUTOCOMPACT},
{"BOOTORDER",	VZCTL_PARAM_BOOTORDER},
{"ROOT_DISK",	VZCTL_PARAM_ROOT_DISK},
/*      SLM             */
{"SLMMEMORYLIMIT",VZCTL_PARAM_SLMMEMORYLIMIT},
{"SLMMODE",	VZCTL_PARAM_SLMMODE},

/* CPU */
{"BURST_CPU_AVG_USAGE",VZCTL_PARAM_BURST_CPU_AVG_USAGE},
{"BURST_CPULIMIT",VZCTL_PARAM_BURST_CPULIMIT},

/* traffic shaping */
{"TRAFFIC_SHAPING",VZCTL_PARAM_TRAFFIC_SHAPING},
{"TOTALRATE",	VZCTL_PARAM_TOTALRATE},
{"RATE",	VZCTL_PARAM_RATE},
{"RATEBOUND",	VZCTL_PARAM_RATEBOUND},

{"MEMGUARANTEE",VZCTL_PARAM_MEM_GUARANTEE},
{"MEMGUARANTEE_BYTES", VZCTL_PARAM_MEM_GUARANTEE_BYTES},
{"PAGECACHE_ISOLATION",VZCTL_PARAM_PAGECACHE_ISOLATION},
{"NUMMEMORYSUBGROUPS", VZCTL_PARAM_NUMMEMORYSUBGROUPS},
{"NUMNETIF", VZCTL_PARAM_NUMNETIF},


/* TODO */
// EXT_IP_ADDRESS
// CONFIG_CUSTOMIZED
// USE_VENET_MASK
// BURST_CPU_AVG_USAGE
// BURST_CPULIMIT
{NULL,		-1}
};

static int parse_str(char **dst, const char *src, int replace)
{
	if (*dst != NULL && !replace)
		return 0;
	return xstrdup(dst, src);
}

static int parse_memguar(struct vzctl_res_param *res, const char *str,
		int in_bytes)
{
	struct vzctl_mem_guarantee x = {
		.type = in_bytes ? VZCTL_MEM_GUARANTEE_BYTES :
				VZCTL_MEM_GUARANTEE_PCT};

	if (strcmp(str, "auto") == 0) {
		x.type = VZCTL_MEM_GUARANTEE_AUTO;
	} else if (parse_ul(str, &x.value)) {
		return VZCTL_E_INVAL;
	}

	if (res->memguar == NULL) {
		res->memguar = xmalloc(sizeof(*res->memguar));
		if (res->memguar == NULL)
			return VZCTL_E_NOMEM;
	}

	memcpy(res->memguar, &x, sizeof(struct vzctl_mem_guarantee));

	return 0;
}

static char *memguar2str(struct vzctl_mem_guarantee *memguar)
{
	char x[12] = "auto";

	if (memguar->type != VZCTL_MEM_GUARANTEE_AUTO)
		snprintf(x, sizeof(x), "%lu", memguar->value);

	return strdup(x);
}

static int add_env_param(struct vzctl_env_handle *h, struct vzctl_env_param *env,
		struct vzctl_data_param *data, int flags)
{
	const char *str = data->data;
	unsigned long num, ul;
	int id, n, ret = 0, param_id = -1;
	int replace = flags & VZCTL_CONF_PARAM;
	const struct vzctl_config_param *c = NULL;

	if (data->name != NULL) {
		c = vzctl_get_conf_param(data);
		if (c != NULL)
			param_id = c->id;

		debug(DBG_CFG, "%s: %s=%s", __func__, data->name, data->data);
	} else {
		param_id = data->id;
		debug(DBG_CFG, "%s: %d=%s", __func__, param_id, data->data);
	}

	switch (param_id) {
	case VZCTL_PARAM_VE_ROOT:
		ret = parse_str(&env->fs->ve_root_orig, str, replace);
		if (ret == 0) {
			free(env->fs->ve_root);
			env->fs->ve_root = subst_VEID(EID(h), str);
		}
		break;
	case VZCTL_PARAM_VE_PRIVATE:
		ret = parse_str(&env->fs->ve_private_orig, str, replace);
		if (ret == 0) {
			if ((flags & VZCTL_CONF_UNREGISTERED) &&
				h && EMPTY_CTID(EID(h)) && h->conf->fname)
			{
				char *t = strdupa(h->conf->fname);
				ret = xstrdup(&env->fs->ve_private, dirname(t));
			} else {
				free(env->fs->ve_private);
				env->fs->ve_private = subst_VEID(EID(h), str);
			}
		}
		break;
	case VZCTL_PARAM_TEMPLATE:
		ret = parse_str(&env->fs->tmpl, str, replace);
		break;
	case VZCTL_PARAM_TEMPLATES:
		ret = parse_str(&env->tmpl->templates, str, replace);
		break;
	case VZCTL_PARAM_OSTEMPLATE:
		ret = parse_str(&env->tmpl->ostmpl, str, replace);
		break;
	case VZCTL_PARAM_DISK:
		ret = parse_disk(env->disk, str);
		break;
	}

	if (flags & VZCTL_CONF_BASE_SET)
		return 0;

	switch (param_id) {
	case VZCTL_PARAM_IP_ADDRESS:
		ret = parse_ip_str(&env->net->ip, str, replace);
		break;
	case VZCTL_PARAM_IPDEL:
		if (strcmp(str, "all") == 0)
			env->net->delall = 1;
		else
			ret = parse_ip_str(&env->net->ip_del, str, replace);
		break;
	case VZCTL_PARAM_NETIF:
		ret = parse_netif(h, &env->veth->dev_list, str);
		break;
	case VZCTL_PARAM_NETIF_ADD:
		ret = parse_netif_cmd(h, &env->veth->dev_list, str);
		break;
	case VZCTL_PARAM_NETIF_DEL:
		ret = parse_netif_cmd(h, &env->veth->dev_del_list, str);
		break;
	case VZCTL_PARAM_NETIF_IFNAME:
	case VZCTL_PARAM_NETIF_MAC:
	case VZCTL_PARAM_NETIF_HOST_IFNAME:
	case VZCTL_PARAM_NETIF_HOST_MAC:
	case VZCTL_PARAM_NETIF_GW:
	case VZCTL_PARAM_NETIF_GW6:
	case VZCTL_PARAM_NETIF_DHCP:
	case VZCTL_PARAM_NETIF_DHCP6:
	case VZCTL_PARAM_NETIF_MAC_FILTER:
	case VZCTL_PARAM_NETIF_NETWORK:
	case VZCTL_PARAM_NETIF_IPADD:
	case VZCTL_PARAM_NETIF_IPDEL:
	case VZCTL_PARAM_NETIF_CONFIGURE_MODE:
	case VZCTL_PARAM_NETIF_NETTYPE:
	case VZCTL_PARAM_NETIF_VPORT_TYPE:
		ret = parse_netif_ifname(env->veth, str, param_id, replace);
		break;
	case VZCTL_PARAM_LOCKEDPAGES:
	case VZCTL_PARAM_PRIVVMPAGES:
	case VZCTL_PARAM_SHMPAGES:
	case VZCTL_PARAM_PHYSPAGES:
	case VZCTL_PARAM_VMGUARPAGES:
	case VZCTL_PARAM_SWAPPAGES:
		ret = parse_ub(env->res->ub, str, param_id, get_pagesize(), 0);
		break;
	case VZCTL_PARAM_SWAP:
		ret = parse_ub(env->res->ub, str, VZCTL_PARAM_SWAPPAGES,
				get_pagesize(), get_pagesize());
		break;
	case VZCTL_PARAM_MEMORY:
		ret = parse_ub(env->res->ub, str, VZCTL_PARAM_PHYSPAGES,
				get_pagesize(), get_pagesize());
		break;
	case VZCTL_PARAM_NUMPROC:
	case VZCTL_PARAM_NUMFLOCK:
	case VZCTL_PARAM_NUMPTY:
	case VZCTL_PARAM_NUMSIGINFO:
	case VZCTL_PARAM_NUMFILE:
	case VZCTL_PARAM_NUMIPTENT:
	case VZCTL_PARAM_AVNUMPROC:
	case VZCTL_PARAM_NUMMEMORYSUBGROUPS:
	case VZCTL_PARAM_NUMNETIF:
		ret = parse_ub(env->res->ub, str, param_id, 0, 0);
		break;
	case VZCTL_PARAM_KMEMSIZE:
		ret = parse_ub(env->res->ub, str, param_id, 1, 1);
		break;
	case VZCTL_PARAM_NUMTCPSOCK:
	case VZCTL_PARAM_NUMOTHERSOCK:
	case VZCTL_PARAM_TCPSNDBUF:
	case VZCTL_PARAM_TCPRCVBUF:
	case VZCTL_PARAM_OTHERSOCKBUF:
	case VZCTL_PARAM_DGRAMRCVBUF:
	case VZCTL_PARAM_OOMGUARPAGES:
	case VZCTL_PARAM_DCACHESIZE:
		if (!(flags & VZCTL_CONF_PARAM))
			logger(0, 0, "Warning: %s parameter is deprecated",
					get_ub_param_name(param_id));
		break;
	case VZCTL_PARAM_VM_OVERCOMMIT:
	{
		float p;

		if (sscanf(str, "%f", &p) != 1)
			goto err_inval;
		if (env->res->ub->vm_overcommit == NULL) {
			env->res->ub->vm_overcommit = malloc(sizeof(float));
			if (env->res->ub->vm_overcommit == NULL)
				return VZCTL_E_NOMEM;
		}

		*env->res->ub->vm_overcommit = p;
		break;
	}
	case VZCTL_PARAM_DISK_QUOTA:
		if ((n = yesno2id(str)) == -1)
			goto err_inval;
		env->dq->enable = n;
		break;
	case VZCTL_PARAM_DISKSPACE:
	{
		struct vzctl_2UL_res res;

		if (env->dq->diskspace != NULL && !replace)
			break;
		ret = parse_twoul_sfx(str, &res, 1024, 1);
		if (ret)
			break;
		ret = add_dq_param(&env->dq->diskspace, &res);
		break;
	}
	case VZCTL_PARAM_DISKINODES:
	{
		struct vzctl_2UL_res res;

		if (env->dq->diskinodes != NULL && !replace)
			break;

		ret = parse_twoul_sfx(str, &res, 1, 1);
		if (ret)
			break;
		ret = add_dq_param(&env->dq->diskinodes, &res);
		break;
	}
	case VZCTL_PARAM_QUOTAUGIDLIMIT:
		if (env->dq->ugidlimit != NULL && !replace)
			break;

		if (parse_ul(str, &ul))
			goto err_inval;
		if (env->dq->ugidlimit == NULL) {
			env->dq->ugidlimit = xmalloc(sizeof(unsigned long));
			if (env->dq->ugidlimit == NULL)
				return VZCTL_E_NOMEM;
		}
		*env->dq->ugidlimit = ul;
		break;
	case VZCTL_PARAM_JOURNALED_QUOTA:
		if (env->dq->journaled_quota != 0 && !replace)
			break;

		if ((n = yesno2id(str)) == -1)
			goto err_inval;
		env->dq->journaled_quota = n;
		break;
	case VZCTL_PARAM_QUOTATIME:
		break;
	case VZCTL_PARAM_DISTRIBUTION:
		ret = parse_str(&env->tmpl->dist, str, replace);
		break;
	case VZCTL_PARAM_FEATURES:
		ret = parse_features(env->features, str);
		break;
	case VZCTL_PARAM_TECHNOLOGIES:
		ret = parse_technologies(&env->features->tech, str);
		break;
	case VZCTL_PARAM_CAP:
		/* deprecated */
		break;
	case VZCTL_PARAM_CPUUNITS:
		if (env->cpu->units != NULL && !replace)
			break;
		if (parse_ul(str, &num))
			goto err_inval;
		if (num < MINCPUUNITS || num > MAXCPUUNITS)
			goto err_inval;
		if (env->cpu->units == NULL) {
			env->cpu->units = malloc(sizeof(unsigned long));
			if (env->cpu->units == NULL)
				return VZCTL_E_NOMEM;
		}
		*env->cpu->units = num;
		break;
	case VZCTL_PARAM_CPUWEIGHT:
		if (env->cpu->weight != NULL && !replace)
			break;
		if (parse_ul(str, &num))
			goto err_inval;
		if (env->cpu->weight == NULL) {
			env->cpu->weight = xmalloc(sizeof(unsigned long));
			if (env->cpu->weight == NULL)
				return VZCTL_E_NOMEM;
		}
		*env->cpu->weight = num;
		break;
	case VZCTL_PARAM_CPULIMIT:
		if (env->cpu->limit_res != NULL && !replace)
			break;
		if (parse_cpulimit(env->cpu, str, 0))
			goto err_inval;
		break;
	case VZCTL_PARAM_CPULIMIT_MHZ:
		if (env->cpu->limit_res != NULL && !replace)
			break;
		if (parse_cpulimit(env->cpu, str, 1))
			goto err_inval;
		break;
	case VZCTL_PARAM_CPUS:
		if (env->cpu->vcpus != NULL && !replace)
			break;
		if (parse_ul(str, &num))
			goto err_inval;
		if (env->cpu->vcpus == NULL) {
			env->cpu->vcpus = xmalloc(sizeof(unsigned long));
			if (env->cpu->vcpus == NULL)
				return VZCTL_E_NOMEM;
		}
		*env->cpu->vcpus = num;
		break;
	case VZCTL_PARAM_CPUMASK:
		if (env->cpu->cpumask != NULL && !replace)
			break;
		if (parse_cpumask(str, &env->cpu->cpumask))
			goto err_inval;
		break;
	case VZCTL_PARAM_NODEMASK:
		if (env->cpu->nodemask != NULL && !replace)
			break;
		if (parse_nodemask(str, &env->cpu->nodemask))
			goto err_inval;
		break;
	case VZCTL_PARAM_NAME:
		ret = parse_str(&env->name->name, str, replace);
		break;
	case VZCTL_PARAM_LOCKDIR:
		ret = parse_str(&env->opts->lockdir, str, replace);
		break;
	case VZCTL_PARAM_CONFIG:
		ret = parse_str(&env->opts->config, str, replace);
		break;
	case VZCTL_PARAM_DEVICES:
		ret = parse_devices(env->dev, str);
		break;
	case VZCTL_PARAM_DEVNODES:
		ret = parse_devnodes(env->dev, str, replace);
		break;
	case VZCTL_PARAM_IPTABLES:
		ret = parse_iptables(&env->features->ipt_mask, str);
		break;
	case VZCTL_PARAM_NETFILTER:
		ret = parse_netfilter(&env->features->nf_mask, str);
		break;
	case VZCTL_PARAM_NETDEV:
		ret = parse_netdev(&env->netdev->dev, str, replace);
		break;
	case VZCTL_PARAM_NETDEV_DEL:
		ret = parse_netdev(&env->netdev->dev_del, str, replace);
		break;
	case VZCTL_PARAM_PCI:
		ret = parse_pcidev(&env->dev->pci, str, 1, replace);
		break;
	case VZCTL_PARAM_PCI_DEL:
		ret = parse_pcidev(&env->dev->pci_del, str, 0, replace);
		break;
	case VZCTL_PARAM_IOPRIO:
		ret = parse_ioprio(env->io, str);
		break;
	case VZCTL_PARAM_IOLIMIT:
		ret = parse_iolimit(env->io, str, 1);
		break;
	case VZCTL_PARAM_IOLIMIT_MB:
		ret = parse_iolimit(env->io, str, 1024 * 1024);
		break;
	case VZCTL_PARAM_IOPSLIMIT:
		ret = parse_iopslimit(env->io, str);
		break;
	case VZCTL_PARAM_MEMINFO:
		ret = parse_meminfo(env->meminfo, str);
		break;
	case VZCTL_PARAM_ONBOOT:
		if (!strcmp(str, "auto"))
			n = VZCTL_AUTOSTART_AUTO;
		else if (!strcmp(str, "yes"))
			n = VZCTL_AUTOSTART_ON;
		else if (!strcmp(str, "no"))
			n = VZCTL_AUTOSTART_OFF;
		else
			goto err_inval;
		env->opts->onboot = n;
		break;
	case VZCTL_PARAM_AUTOSTOP:
		if (strcmp(str, "suspend") == 0)
			env->opts->autostop = VZCTL_AUTOSTOP_SUSPEND;
		else if (strcmp(str, "stop") == 0)
			env->opts->autostop = VZCTL_AUTOSTOP_SHUTDOWN;
		else
			goto err_inval;
		break;
	case VZCTL_PARAM_BOOTORDER:
		if (parse_ul(str, &ul))
			goto err_inval;
		if (env->opts->bootorder == NULL) {
			env->opts->bootorder = xmalloc(sizeof(unsigned long));
			if (env->opts->bootorder == NULL)
				return VZCTL_E_NOMEM;
		}
		*env->opts->bootorder = ul;
		break;
	case VZCTL_PARAM_DESCRIPTION:
		ret = parse_str(&env->misc->description_eq, str, replace);
		break;
	case VZCTL_PARAM_HOSTNAME:
		ret = parse_str(&env->misc->hostname, str, replace);
		break;
	case VZCTL_PARAM_SEARCHDOMAIN:
		ret = parse_str_param(&env->misc->searchdomain, str);
		break;
	case VZCTL_PARAM_NAMESERVER:
		ret = parse_str_param(&env->misc->nameserver, str);
		break;
	case VZCTL_PARAM_VE_ENVIRONMENT:
		ret = parse_str_param(&env->misc->ve_env, str);
		break;
	case VZCTL_PARAM_VE_TYPE:
		if (str2env_type(env->misc, str))
			goto err_inval;
		break;
	case VZCTL_PARAM_VE_UUID: {
		char uuid[40];

		if (vzctl2_get_normalized_uuid(str, uuid, sizeof(uuid)))
			goto err_inval;

		ret = parse_str(&env->misc->uuid, uuid, replace);
		break;
	}
	case VZCTL_PARAM_APPLY_IPONLY:
		if ((n = yesno2id(str)) == -1)
			goto err_inval;
		env->opts->apply_iponly = n;
		break;
	case VZCTL_PARAM_HA_ENABLE:
		if ((n = yesno2id(str)) == -1)
			goto err_inval;
		env->opts->ha_enable = n;
		break;
	case VZCTL_PARAM_HA_PRIO:
		if (env->opts->ha_prio != NULL && !replace)
			break;
		if (parse_ul(str, &num))
			goto err_inval;
		if (num > MAXHAPRIO)
			goto err_inval;
		if (env->opts->ha_prio == NULL) {
			env->opts->ha_prio = malloc(sizeof(*env->opts->ha_prio));
			if (env->opts->ha_prio == NULL)
				return VZCTL_E_NOMEM;
		}
		*env->opts->ha_prio = num;
		break;
	case VZCTL_PARAM_OSRELEASE:
		if (env->tmpl->osrelease != NULL && !replace)
			break;
		ret = xstrdup(&env->tmpl->osrelease, str);
		break;
	case VZCTL_PARAM_USE_NET_RPS:
		if ((n = yesno2id(str)) == -1)
			goto err_inval;
		env->net->rps = n;
		break;
	case VZCTL_PARAM_BINDMOUNT:
		ret = parse_bindmount(env->bindmount, str, 1);
		break;
	case VZCTL_PARAM_BINDMOUNT_DEL:
		ret = parse_bindmount(env->bindmount, str, 0);
		break;
	case VZCTL_PARAM_NOATIME:
		if ((n = yesno2id(str)) == -1)
			goto err_inval;
		env->fs->noatime = n;
		break;
	case VZCTL_PARAM_ORIGIN_SAMPLE:
		if (env->opts->config && !replace)
			break;
		ret = xstrdup(&env->opts->config, str);
		break;
	case VZCTL_PARAM_DISABLED:
		if ((n = yesno2id(str)) == -1)
			goto err_inval;
		env->misc->start_disabled = n;
		break;
	case VZCTL_PARAM_AUTOCOMPACT:
		if ((n = yesno2id(str)) == -1)
			goto err_inval;
		env->misc->autocompact = n;
		break;
	case VZCTL_PARAM_ROOT_DISK:
		if ((n = yesno2id(str)) == -1)
			goto err_inval;
		env->disk->root = n;
		break;
	case VZCTL_PARAM_SLMMODE:
		if ((id = slm_mode2id(str)) == -1)
			goto err_inval;
		env->res->slm->mode = id;
		break;
	case VZCTL_PARAM_SLMMEMORYLIMIT:
	{
		struct vzctl_2UL_res res;

		ret = parse_twoul_sfx(str, &res, get_pagesize(), 1);
		if (ret)
			return ret;
		free(env->res->slm->memorylimit);
		env->res->slm->memorylimit =
				malloc(sizeof(struct vzctl_slm_memorylimit));
		if (env->res->slm->memorylimit == NULL)
			return VZCTL_E_NOMEM;
		env->res->slm->memorylimit->avg = res.b;
		env->res->slm->memorylimit->quality = res.l;
		env->res->slm->memorylimit->inst = res.l;
		break;
	}
	case VZCTL_PARAM_BURST_CPU_AVG_USAGE:
		ret = parse_ul(str, &ul);
		if (ret)
			return ret;
		if (env->cpu->burst_cpu_avg_usage == NULL) {
			env->cpu->burst_cpu_avg_usage = xmalloc(sizeof(unsigned long));
			if (env->cpu->burst_cpu_avg_usage == NULL)
				return VZCTL_E_NOMEM;
		}
		*env->cpu->burst_cpu_avg_usage = ul;
		break;
	case VZCTL_PARAM_BURST_CPULIMIT:
		ret = parse_ul(str, &ul);
		if (ret)
			return ret;
		if (env->cpu->burst_cpulimit == NULL) {
			env->cpu->burst_cpulimit = xmalloc(sizeof(unsigned long));
			if (env->cpu->burst_cpulimit == NULL)
				return VZCTL_E_NOMEM;
		}
		*env->cpu->burst_cpulimit = ul;
		break;
	case VZCTL_PARAM_TRAFFIC_SHAPING:
		if ((id = yesno2id(str)) == -1)
			goto err_inval;
		env->vz->tc->traffic_shaping = id;
		break;
	case VZCTL_PARAM_TOTALRATE:
		ret = parse_rates(&env->vz->tc->totalrate_list, str, 3, replace);
		break;
	case VZCTL_PARAM_RATE:
		ret = parse_rates(&env->vz->tc->rate_list, str, 3, replace);
		break;
	case VZCTL_PARAM_RATEBOUND:
		if ((id = yesno2id(str)) == -1)
			goto err_inval;
		env->vz->tc->ratebound = id;
		break;
	case VZCTL_PARAM_MEM_GUARANTEE:
	case VZCTL_PARAM_MEM_GUARANTEE_BYTES:
		if (env->res->memguar != NULL && !replace)
			break;
		ret = parse_memguar(env->res, str,
				param_id == VZCTL_PARAM_MEM_GUARANTEE_BYTES);
		break;
	case VZCTL_PARAM_PAGECACHE_ISOLATION:
		if ((id = yesno2id(str)) == -1)
			goto err_inval;
		env->res->ub->pagecache_isolation = id;
		break;
	default:
		debug(DBG_CFG, "Unknown parameter id=%d", param_id);
		break;
	}

	if (ret == VZCTL_E_INVAL)
		goto err_inval;

	return ret;

err_inval:
	if (c == NULL)
		c = vzctl_get_conf_param(data);
	if (c)
		logger((flags & VZCTL_CONF_QUIET) ? INT_MAX : -1, 0,
				"Invalid parameter %s: '%s'", c->name, str);

	return VZCTL_E_INVAL;
}

int vzctl2_add_env_param_by_name(struct vzctl_env_param *env, const char *name, const char *str)
{
	struct vzctl_data_param data = {
		.name = (char*) name,
		.data = (char*) str,
	};

	return add_env_param(NULL, env, &data, VZCTL_CONF_QUIET);
}

int vzctl2_add_env_param_by_id(struct vzctl_env_param *env, unsigned id, const char *str)
{
	struct vzctl_data_param data = {
		.id = id,
		.data = (char*) str,
	};

	return add_env_param(NULL, env, &data, VZCTL_CONF_QUIET);
}

const struct vzctl_config_param *vzctl_get_conf_param(
		struct vzctl_data_param *data)
{
	const struct vzctl_config_param **p;
	const struct vzctl_config_param *map[] = {\
			config_param_map,
			NULL};

	for (p = map; *p != NULL; p++) {
		const struct vzctl_config_param *param;
		param = get_conf_param(*p, data);
		if (param != NULL)
			return param;
	}
	return NULL;
}

int vzctl2_del_param_by_id(struct vzctl_env_handle *h, int id)
{
	const struct vzctl_config_param *param;
	struct vzctl_data_param data = {
		.id = id,
	};

	param = vzctl_get_conf_param(&data);
	if (param == NULL)
		return VZCTL_E_INVAL;

	return vzctl_conf_del_param(h->conf, param->name);
}

int vzctl2_del_param_by_name(struct vzctl_env_handle *h, const char *name)
{
	const struct vzctl_config_param *param;
	struct vzctl_data_param data = {
		.name = name,
	};

	param = vzctl_get_conf_param(&data);
	if (param == NULL)
		return VZCTL_E_INVAL;

	return vzctl_conf_del_param(h->conf, param->name);
}

int vzctl_update_env_param(struct vzctl_env_handle *h, int flags)
{
	struct vzctl_config *conf = h->conf;
	struct vzctl_data_param data;
	int rc, i, ret = 0;

	debug(DBG_CFG, "update_env_param");
	data.id = 0;
	for (i = 0; i < conf->map.last; i++) {
		if (conf->map.data[i].val != NULL) {
			data.data = conf->map.data[i].val;
			data.name = conf->map.data[i].name;
			rc = add_env_param(h, h->env_param, &data, flags);
			if (rc != 0 && ret == 0)
				ret = rc; // return first error
		}
	}

	if (h->env_param->fs->layout == 0)
		h->env_param->fs->layout = vzctl2_env_layout_version(
				h->env_param->fs->ve_private);

	rc = set_disk_param(h->env_param, flags);
	if (rc != 0 && ret == 0)
		ret = rc; // return first error

	if (flags & VZCTL_CONF_RUNTIME_PARAM)
		get_env_ops()->env_get_runtime_param(h, flags);

	if (ret == VZCTL_E_INVAL && (flags & VZCTL_CONF_SKIP_PARAM_ERRORS))
		return 0;

	return ret;
}

static char *ips2str(struct vzctl_net_param *old, struct vzctl_net_param *new)
{
	int r, len = 0;
	char ipstr[128];
	struct vzctl_ip_param *it;
	char *buf, *sp, *ep;
	list_head_t *phead;
	int delall = new->delall;
	LIST_HEAD(merged);

	phead = &merged;

	if (!delall) {
		list_for_each(it, &old->ip, list) {
			if (strcmp(it->ip, "0.0.0.0") == 0)
				continue;
			if (find_ip(&new->ip, it) != NULL ||
					find_ip(&new->ip_del, it) != NULL)
				continue;
			add_ip_param(phead, it);
		}
	}
	list_for_each(it, &new->ip, list) {
		if (strcmp(it->ip, "0.0.0.0") == 0)
			continue;
		if (find_ip(&new->ip_del, it) != NULL)
			continue;
		if (find_ip(phead, it) != NULL)
			continue;
		add_ip_param(phead, it);
	}
	if (list_empty(phead))
		return strdup("");

	list_for_each(it, phead, list)
		len += strlen(it->ip) + 16 + 1;

	buf = malloc(len + 1);
	if (buf == NULL) {
		free_ip(phead);
		return NULL;
	}
	*buf = 0;
	sp = buf;
	ep = buf + len;

	list_for_each(it, phead, list) {
		if (get_ip_str(it, ipstr, sizeof(ipstr)))
			continue;
		r = snprintf(sp, ep - sp, "%s ", ipstr);
		if (r < 0 || sp + r >= ep)
			break;
		sp += r;
	}
	free_ip(phead);

	return buf;
}

static char *env_param2str(struct vzctl_env_handle *h,
		struct vzctl_env_param *env, int id)
{
	char buf[STR_SIZE];
	const char *str;

	switch (id) {
	case VZCTL_PARAM_VE_ROOT:
		if (env->fs->ve_root_orig != NULL)
			return strdup(env->fs->ve_root_orig);
		break;
	case VZCTL_PARAM_VE_PRIVATE:
		if (env->fs->ve_private_orig != NULL)
			return strdup(env->fs->ve_private_orig);
		break;
	case VZCTL_PARAM_TEMPLATE:
		if (env->fs->tmpl != NULL)
			return strdup(env->fs->tmpl);
		break;
	case VZCTL_PARAM_TEMPLATES:
		if (env->tmpl->templates != NULL)
			return strdup(env->tmpl->templates);
		break;
	case VZCTL_PARAM_OSTEMPLATE:
		if (env->tmpl->ostmpl != NULL)
			return strdup(env->tmpl->ostmpl);
		break;
	case VZCTL_PARAM_TECHNOLOGIES :
		if (env->features->tech) {
			tech2str(env->features->tech, buf, sizeof(buf));
			return strdup(buf);
		}
		break;
	/*	UBC	*/
	case VZCTL_PARAM_LOCKEDPAGES:
	case VZCTL_PARAM_PRIVVMPAGES:
	case VZCTL_PARAM_SHMPAGES:
	case VZCTL_PARAM_PHYSPAGES:
	case VZCTL_PARAM_VMGUARPAGES:
	case VZCTL_PARAM_NUMPROC:
	case VZCTL_PARAM_NUMTCPSOCK:
	case VZCTL_PARAM_NUMFLOCK:
	case VZCTL_PARAM_NUMPTY:
	case VZCTL_PARAM_NUMSIGINFO:
	case VZCTL_PARAM_NUMOTHERSOCK:
	case VZCTL_PARAM_NUMFILE:
	case VZCTL_PARAM_NUMIPTENT:
	case VZCTL_PARAM_AVNUMPROC:
	case VZCTL_PARAM_TCPSNDBUF:
	case VZCTL_PARAM_TCPRCVBUF:
	case VZCTL_PARAM_OTHERSOCKBUF:
	case VZCTL_PARAM_DGRAMRCVBUF:
	case VZCTL_PARAM_SWAPPAGES:
	case VZCTL_PARAM_KMEMSIZE:
	case VZCTL_PARAM_NUMNETIF:
	{
		const struct vzctl_2UL_res *res;

		if ((res = vzctl_get_ub_res(env->res->ub, id)) != NULL) {
			snprintf(buf, sizeof(buf), "%lu:%lu", res->b, res->l);
			return strdup(buf);
		}
		break;
	}
	case VZCTL_PARAM_NUMMEMORYSUBGROUPS:
		if (env->res->ub->num_memory_subgroups) {
			snprintf(buf, sizeof(buf), "%lu",
				env->res->ub->num_memory_subgroups->l);
			return strdup(buf);
		}
		break;
	case VZCTL_PARAM_VM_OVERCOMMIT:
		if (env->res->ub->vm_overcommit != NULL) {
			snprintf(buf, sizeof(buf), "%g",
				*env->res->ub->vm_overcommit);
			return strdup(buf);
		}
		break;
	case VZCTL_PARAM_IP_ADDRESS:
		if (env->net->delall || !list_empty(&env->net->ip) ||
				!list_empty(&env->net->ip_del)) {
			if (env->net->delall)
				h->env_param->net->delall = 1;
			return ips2str(h->env_param->net, env->net);
		}
		break;
	case VZCTL_PARAM_DISKSPACE:
	{
		if (env->dq != NULL && env->dq->diskspace != NULL) {
			snprintf(buf, sizeof(buf), "%lu:%lu",
				env->dq->diskspace->b,
				env->dq->diskspace->l);
			return strdup(buf);
		}
		break;
	}
	case VZCTL_PARAM_DISKINODES:
	{
		if (env->dq != NULL && env->dq->diskinodes != NULL) {
			snprintf(buf, sizeof(buf), "%lu:%lu",
				env->dq->diskinodes->b,
				env->dq->diskinodes->l);
			return strdup(buf);
		}
		break;
	}
	case VZCTL_PARAM_QUOTAUGIDLIMIT:
		if (env->dq != NULL && env->dq->ugidlimit != NULL) {
			snprintf(buf, sizeof(buf), "%lu",
				*env->dq->ugidlimit);
			return strdup(buf);
		}
		break;
	case VZCTL_PARAM_JOURNALED_QUOTA:
		if (env->dq->journaled_quota) {
			str = id2yesno(env->dq->journaled_quota);
			if (str != NULL)
				return strdup(str);
		}
		break;
	case VZCTL_PARAM_QUOTATIME:
		if (env->dq != NULL && env->dq->exptime != NULL) {
			snprintf(buf, sizeof(buf), "%lu",
				*env->dq->exptime);
			return strdup(buf);
		}
		break;
	case VZCTL_PARAM_DISTRIBUTION:
		if (env->tmpl->dist != NULL)
			return strdup(env->tmpl->dist);
		break;
	case VZCTL_PARAM_FEATURES:
		if (env->features->known) {
			features_mask2str(env->features, buf, sizeof(buf));
			return strdup(buf);
		}
		break;
	case VZCTL_PARAM_CPUUNITS:
		if (env->cpu->units != NULL) {
			snprintf(buf, sizeof(buf), "%lu",
				*env->cpu->units);
			return strdup(buf);
		}
		break;
	case VZCTL_PARAM_CPUWEIGHT:
		break;
	case VZCTL_PARAM_CPULIMIT:
		if (env->cpu->limit_res != NULL &&
		    env->cpu->limit_res->type == VZCTL_CPULIMIT_PCT) {
			snprintf(buf, sizeof(buf), "%lu",
					env->cpu->limit_res->limit);
			vzctl_conf_del_param(h->conf, "CPULIMIT_MHZ");
			return strdup(buf);
		}
		break;
	case VZCTL_PARAM_CPULIMIT_MHZ:
		if (env->cpu->limit_res != NULL &&
		    env->cpu->limit_res->type == VZCTL_CPULIMIT_MHZ) {
			snprintf(buf, sizeof(buf), "%lu",
					env->cpu->limit_res->limit);

			vzctl_conf_del_param(h->conf, "CPULIMIT");
			return strdup(buf);
		}
		break;
	case VZCTL_PARAM_CPUS:
		if (env->cpu->vcpus != NULL) {
			if (*env->cpu->vcpus == 0) {
				vzctl_conf_del_param(h->conf, "CPUS");
				break;
			}
	
			snprintf(buf, sizeof(buf), "%lu",
					*env->cpu->vcpus);
			return strdup(buf);

		}
		break;
	case VZCTL_PARAM_CPUMASK:
		if (env->cpu->cpumask != NULL)
			return cpumask2str(env->cpu->cpumask);
		break;
	case VZCTL_PARAM_NODEMASK:
		if (env->cpu->nodemask != NULL)
			return nodemask2str(env->cpu->nodemask);
		break;
	case VZCTL_PARAM_NETIF:
		return veth2str(h->env_param, env->veth, 0);
	case VZCTL_PARAM_NAME:
		if (env->name->name != NULL)
			return strdup(env->name->name);
		break;
	case VZCTL_PARAM_DEVICES:
		return devices2str(env->dev);
	case VZCTL_PARAM_DEVNODES:
		return devnodes2str(env->dev, 0);
	case VZCTL_PARAM_IPTABLES:
		if (env->features->ipt_mask) {
			iptables_mask2str(env->features->ipt_mask, buf, sizeof(buf));
			return strdup(buf);
		}
		break;
	case VZCTL_PARAM_NETFILTER:
		if (env->features->nf_mask) {
			netfilter_mask2str(env->features->nf_mask, buf, sizeof(buf));
			return strdup(buf);
		}
		break;
	case VZCTL_PARAM_NETDEV:
		return netdev2str(h->env_param->netdev, env->netdev);
	case VZCTL_PARAM_PCI:
		return pci2str(h->env_param->dev, env->dev);
	case VZCTL_PARAM_IOPRIO:
		if (env->io->prio >= 0) {
			snprintf(buf, sizeof(buf), "%d",
					env->io->prio);
			return strdup(buf);
		}
		break;
	case VZCTL_PARAM_IOLIMIT:
		if (env->io->limit != UINT_MAX) {
			snprintf(buf, sizeof(buf), "%u",
				env->io->limit);
			return strdup(buf);
		}
		break;
	case VZCTL_PARAM_IOPSLIMIT:
		if (env->io->iopslimit != UINT_MAX) {
			snprintf(buf, sizeof(buf), "%u",
				env->io->iopslimit);
			return strdup(buf);
		}
		break;
	case VZCTL_PARAM_MEMINFO:
		if (env->meminfo->mode != 0)
			return meminfo2str(env->meminfo);
		break;
	case VZCTL_PARAM_ONBOOT:
		if (env->opts->onboot != VZCTL_AUTOSTART_NONE) {
			switch (env->opts->onboot) {
			case VZCTL_AUTOSTART_OFF:
				return strdup("no");
			case VZCTL_AUTOSTART_ON:
				return strdup("yes");
			case VZCTL_AUTOSTART_AUTO:
				return strdup("auto");
			}
		}
		break;
	case VZCTL_PARAM_AUTOSTOP:
		if (env->opts->autostop) {
			snprintf(buf, sizeof(buf),"%s",
				env->opts->autostop == VZCTL_AUTOSTOP_SUSPEND ?
							"suspend" : "stop");
			return strdup(buf);
		}
		break;
	case VZCTL_PARAM_BOOTORDER:
		if ((env->opts->bootorder)) {
			snprintf(buf, sizeof(buf), "%lu",
					*env->opts->bootorder);
			return strdup(buf);
		}
		break;
	case VZCTL_PARAM_DESCRIPTION:
		if (env->misc->description_eq != NULL)
			return strdup(env->misc->description_eq);
		break;
	case VZCTL_PARAM_HOSTNAME:
		if (env->misc->hostname != NULL)
			return strdup(env->misc->hostname);
		break;
	case VZCTL_PARAM_SEARCHDOMAIN:
		if (!list_empty(&env->misc->searchdomain))
			return list2str(NULL, &env->misc->searchdomain);
		break;
	case VZCTL_PARAM_NAMESERVER:
		if (!list_empty(&env->misc->nameserver))
			return list2str(NULL, &env->misc->nameserver);
		break;
	case VZCTL_PARAM_VE_TYPE:
		if (env->misc->ve_type) {
			str = env_type2str(env->misc);
			if (str != NULL)
				return strdup(str);
		}
		break;
	case VZCTL_PARAM_VE_UUID:
		if (env->misc->uuid != NULL)
			return strdup(env->misc->uuid);
		break;
	case VZCTL_PARAM_APPLY_IPONLY:
		if (env->opts->apply_iponly) {
			str = id2yesno(env->opts->apply_iponly);
			if (str != NULL)
				return strdup(str);
		}
		break;
	case VZCTL_PARAM_HA_ENABLE:
		if (env->opts->ha_enable) {
			str = id2yesno(env->opts->ha_enable);
			if (str != NULL)
				return strdup(str);
		}
		break;
	case VZCTL_PARAM_HA_PRIO:
		if (env->opts->ha_prio != NULL) {
			snprintf(buf, sizeof(buf), "%lu", *env->opts->ha_prio);
			return strdup(buf);
		}
		break;
	case VZCTL_PARAM_OSRELEASE:
		if (env->tmpl->osrelease != NULL)
			return strdup(env->tmpl->osrelease);
		break;
	case VZCTL_PARAM_USE_NET_RPS:
		if (env->net->rps) {
			str = id2yesno(env->net->rps);
			if (str != NULL)
				return strdup(str);
		}
		break;
	case VZCTL_PARAM_BINDMOUNT:
		return bindmount2str(h->env_param->bindmount, env->bindmount);
	case VZCTL_PARAM_NOATIME:
		if (env->fs->noatime) {
			str = id2yesno(env->fs->noatime);
			if (str != NULL)
				return strdup(str);
		}
		break;
	case VZCTL_PARAM_ORIGIN_SAMPLE:
		if (env->opts->config != NULL)
			return strdup(env->opts->config);
		break;
	case VZCTL_PARAM_DISABLED:
		if (env->misc->start_disabled) {
			str = id2yesno(env->misc->start_disabled);
			if (str != NULL)
				return strdup(str);
		}
		break;
	case VZCTL_PARAM_AUTOCOMPACT:
		if (env->misc->autocompact) {
			str = id2yesno(env->misc->autocompact);
			if (str != NULL)
				return strdup(str);
		}
		break;
	case VZCTL_PARAM_ROOT_DISK:
		if (env->disk->root) {
			str = id2yesno(env->disk->root);
			if (str != NULL)
				return strdup(str);
		}
		break;
	case VZCTL_PARAM_SLMMODE:
		if (env->res->slm->mode)
			return strdup(slm_id2mode(env->res->slm->mode));
		break;
	case VZCTL_PARAM_SLMMEMORYLIMIT:
		if (env->res->slm->memorylimit != NULL) {
			snprintf(buf, sizeof(buf), "%lu:%lu",
				env->res->slm->memorylimit->avg,
				env->res->slm->memorylimit->inst);
			return strdup(buf);
		}
		break;
	case VZCTL_PARAM_BURST_CPULIMIT:
		if (env->cpu->burst_cpulimit != NULL) {
			snprintf(buf, sizeof(buf), "%lu",
					*env->cpu->burst_cpulimit);
			return strdup(buf);
		}
		break;
	case VZCTL_PARAM_BURST_CPU_AVG_USAGE:
		if (env->cpu->burst_cpu_avg_usage != NULL) {
			snprintf(buf, sizeof(buf), "%lu",
					*env->cpu->burst_cpu_avg_usage);
			return strdup(buf);
		}
		break;
	case VZCTL_PARAM_RATE:
		if (!list_empty(&env->vz->tc->rate_list))
			return rate2str(&env->vz->tc->rate_list);
		break;
	case VZCTL_PARAM_RATEBOUND:
		if (env->vz->tc->ratebound)
			return strdup(id2yesno(env->vz->tc->ratebound ));
		break;
	case VZCTL_PARAM_MEM_GUARANTEE:
		if (env->res->memguar != NULL &&
				env->res->memguar->type != VZCTL_MEM_GUARANTEE_BYTES) {
			vzctl_conf_del_param(h->conf, "MEMGUARANTEE_BYTES");
			return memguar2str(env->res->memguar);
		}
		break;
	case VZCTL_PARAM_MEM_GUARANTEE_BYTES:
		if (env->res->memguar != NULL &&
				env->res->memguar->type == VZCTL_MEM_GUARANTEE_BYTES) {
			vzctl_conf_del_param(h->conf, "MEMGUARANTEE");
			return memguar2str(env->res->memguar);
		}
		break;
	case VZCTL_PARAM_PAGECACHE_ISOLATION:
		if (env->res->ub->pagecache_isolation)
			return strdup(id2yesno(env->res->ub->pagecache_isolation));
		break;
	default:
		break;
	}
	return NULL;
}

int merge_env_param(struct vzctl_env_handle *h, struct vzctl_env_param *env,
		param_filter_f filter, int flags)
{
	struct vzctl_config_param *param;
	char *str;
	int ret = 0;

	if (h->conf == NULL || h->env_param == env)
		return 0;
	debug(DBG_CFG, "merge_env_param");
	for (param = config_param_map; param->id != -1; param++) {
		if (param->name == NULL)
			continue;
		if (param->alias != NULL)
			continue;
		if (filter && filter(param->name))
			continue;
		str = env_param2str(h, env, param->id);

		if (str != NULL) {
			struct vzctl_data_param data;

			data.name = NULL;
			data.id = param->id;
			data.data = str;

			add_env_param(h, h->env_param, &data, VZCTL_CONF_PARAM);

			/* compatibility bugfix #PSBM-33885 */
			if (data.id == VZCTL_PARAM_DEVNODES &&
					!(flags & VZCTL_APPLY_CONF))
			{
				free(str);
				str = devnodes2str(h->env_param->dev, 1);
			}

			ret = add_conf_data(h->conf, param->name, str, CONF_DATA_UPDATED);
			free(str);
			if (ret)
				break;
		}
	}
	return ret;
}

/* Dump binary data from 'struct vzctl_env_param' in text representation
   to the 'struct vzctl_config'
 */
int vzctl2_merge_env_param(struct vzctl_env_handle *h, struct vzctl_env_param *env)
{
	return merge_env_param(h, env, NULL, 0);
}

static void free_tmpl_param(struct vzctl_tmpl_param *tmpl)
{
	free(tmpl->ostmpl);
	free(tmpl->templates);
	free(tmpl->dist);
	free(tmpl->osrelease);
	free(tmpl);
}

static void free_opts(struct vzctl_opts *opts)
{
	free(opts->dumpdir);
	free(opts->config);
	free(opts->bootorder);
	free(opts->lockdir);
	free(opts->ha_prio);
	free(opts->cidata_fname);
	free(opts);
}

static void free_name_param(struct vzctl_name_param *name)
{
	free(name->name);
	free(name);
}

void vzctl2_free_env_param(struct vzctl_env_param *env)
{
	if (env == NULL)
		return;
	if (env->opts)
		free_opts(env->opts);
	if (env->tmpl)
		free_tmpl_param(env->tmpl);
	if (env->features)
		free(env->features);
	if (env->fs != NULL)
		free_fs_param(env->fs);
	if (env->dq != NULL)
		free_dq_param(env->dq);
	if (env->cpu != NULL)
		free_cpu_param(env->cpu);
	if (env->res != NULL)
		free_res_param(env->res);
	if (env->veth != NULL)
		free_veth_param(env->veth);
	if (env->net != NULL)
		free_net_param(env->net);
	if (env->cap != NULL)
		free(env->cap);
	if (env->name != NULL)
		free_name_param(env->name);
	if (env->dev != NULL)
		free_dev_param(env->dev);
	if (env->netdev != NULL)
		free_netdev_param(env->netdev);
	if (env->io != NULL)
		free_io_param(env->io);
	if (env->meminfo != NULL)
		free_meminfo_param(env->meminfo);
	if (env->misc != NULL)
		free_misc_param(env->misc);
	if (env->disk != NULL)
		free_env_disk(env->disk);
	if (env->bindmount != NULL)
		free_bindmount_param(env->bindmount);

	/* Fixme: vz specific */
	if (env->vz != NULL)
		free_vz_env_param(env->vz);

	free(env);
}

struct vzctl_env_param *vzctl2_alloc_env_param()
{
	struct vzctl_env_param *env = NULL;

	if ((env = calloc(1, sizeof(struct vzctl_env_param))) == NULL)
		goto err;

	if ((env->opts = calloc(1, sizeof(struct vzctl_opts))) == NULL)
		goto err;
	env->opts->onboot = VZCTL_AUTOSTART_NONE;
	if ((env->tmpl = calloc(1, sizeof(struct vzctl_tmpl_param))) == NULL)
		goto err;
	if ((env->features = calloc(1,
				sizeof(struct vzctl_features_param))) == NULL)
		goto err;
	if ((env->fs = alloc_fs_param()) == NULL)
		goto err;
	if ((env->dq = calloc(1, sizeof(struct vzctl_dq_param))) == NULL)
		goto err;
	if ((env->cpu = alloc_cpu_param()) == NULL)
		goto err;
	if ((env->res = alloc_res_param()) == NULL)
		goto err;
	if ((env->veth = alloc_veth_param()) == NULL)
		goto err;
	if ((env->net = alloc_net_param()) == NULL)
		goto err;
	if ((env->cap = calloc(1, sizeof(struct vzctl_cap_param))) == NULL)
		goto err;
	if ((env->name = calloc(1, sizeof(struct vzctl_name_param))) == NULL)
		goto err;
	if ((env->dev = alloc_dev_param()) == NULL)
		goto err;
	if ((env->netdev = alloc_netdev_param()) == NULL)
		goto err;
	if ((env->io = alloc_io_param()) == NULL)
		goto err;
	if ((env->meminfo = alloc_meminfo_param()) == NULL)
		goto err;
	if ((env->misc = alloc_misc_param()) == NULL)
		goto err;
	if ((env->disk = alloc_env_disk()) == NULL)
		goto err;
	if ((env->bindmount = alloc_bindmount_param()) == NULL)
		goto err;

	/* Fixme: vz specific */
	if ((env->vz = alloc_vz_env_param()) == NULL)
		goto err;

	return env;
err:
	if (env != NULL)
		vzctl2_free_env_param(env);
	vzctl_err(VZCTL_E_NOMEM, ENOMEM, "vzctl2_alloc_env_param");

	return NULL;
}
