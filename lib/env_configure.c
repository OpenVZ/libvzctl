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

#define _GNU_SOURCE 
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <linux/vzcalluser.h>

#include "vzctl.h"
#include "vzerror.h"
#include "logger.h"
#include "exec.h"
#include "vztypes.h"
#include "dist.h"
#include "util.h"
#include "env.h"
#include "env_configure.h"
#include "net.h"
#include "dev.h"
#include "image.h"
#include "cpt.h"
#include "env_ops.h"

static char *envp_s[] =
{
	"HOME=/",
	"TERM=linux",
	"PATH=/bin:/sbin:/usr/bin:/usr/sbin",
	NULL
};


struct vzctl_misc_param *alloc_misc_param()
{
	struct vzctl_misc_param *param;

	param = calloc(1, sizeof(struct vzctl_misc_param));
	if (param == NULL)
		return NULL;

	list_head_init(&param->userpw);
	list_head_init(&param->nameserver);
	list_head_init(&param->searchdomain);
	list_head_init(&param->ve_env);

	return param;
}

void free_misc_param(struct vzctl_misc_param *param)
{
	free_str(&param->userpw);
	free_str(&param->nameserver);
	free_str(&param->searchdomain);
	free_str(&param->ve_env);
	free(param->hostname);
	free(param->description);
	free(param->description_eq);
	free(param->uuid);
	free(param->ve_type_custom);
	free(param);
}

static const char *get_first_ip(struct vzctl_env_handle *h, struct vzctl_env_param *env)
{
	struct vzctl_ip_param *ip;

	if (!list_empty(&h->env_param->net->ip)) {
		ip = list_first_entry(&h->env_param->net->ip, typeof(struct vzctl_ip_param), list);
		return ip->ip;
	}
	if (!list_empty(&env->net->ip)) {
		ip = list_first_entry(&env->net->ip, typeof(struct vzctl_ip_param), list);
		return ip->ip;
	}

	return NULL;
}

int env_hostnm_configure(struct vzctl_env_handle *h, struct vzctl_env_param *env, int flags)
{
	char *envp[4];
	const char *script;
	int ret;
	char hostnm[STR_SIZE];
	char ipaddr[STR_SIZE];
	char state[256];
	char *hostname = env->misc->hostname;
	const char *ip;
	int i = 0;

	if (flags & VZCTL_SKIP_CONFIGURE)
		return 0;
	if (hostname == NULL)
		return 0;
	if (!is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_NOT_RUN, 0,
			"Unable to configure: Container is not running");
	if ((ret = read_dist_actions(h)))
		return ret;

	script = h->dist_actions->set_hostname;
	if (script == NULL) {
		logger(0, 0, "Warning: set_hostname action script is not"
			" specified");
		return 0;
	}
	snprintf(state, sizeof(state), "VE_STATE=%s", get_state(h));
	envp[i++] = state;
	snprintf(hostnm, sizeof(hostnm), "HOSTNM=%s", hostname);
	envp[i++] = hostnm;
	if ((ip = get_first_ip(h, env)) != NULL) {
		snprintf(ipaddr, sizeof(ipaddr), "IP_ADDR=%s", ip);
		envp[i++] = ipaddr;
	}
	envp[i] = NULL;
	logger(0, 0, "Set hostname: %s", hostname);
	ret = vzctl2_wrap_env_exec_vzscript(h, NULL, envp, script,
			VZCTL_SCRIPT_EXEC_TIMEOUT, EXEC_LOG_OUTPUT);

	return ret;
}

struct resolv_conf_data {
	int set;
	char *nameserver;
	char *searchdomain;
};

/* Read nameserver and search/domain lines from HW's /etc/resolv.conf
 *
 * We have to process resolv.conf the same way as system does,
 * so this function is partly based on GLIBC implementation
 * (resolv/res_init.c:__res_vinit()) which in turn
 * is taken from BIND 8.
 */
static int read_resolv_conf(struct resolv_conf_data *r)
{
	const char *file = "/etc/resolv.conf";
	FILE *fp;
	char buf[STR_SIZE];
	char nsrv[STR_SIZE] = "";
	char *srch = NULL;

	if (r->set)
		return 0;

	r->set = 1;

#define MATCH(line, name) \
	(!strncmp(line, name, sizeof(name) - 1) && \
	 (line[sizeof(name) - 1] == ' ' || \
	  line[sizeof(name) - 1] == '\t'))

	fp = fopen(file, "r");
	if (!fp) {
		logger(-1, errno, "Can't open %s", file);
		return -1;
	}
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char *cp, *ep;

		/* skip comments */
		if (*buf == ';' || *buf == '#')
			continue;
		/* read default domain name */
		if (MATCH(buf, "domain") || MATCH(buf, "search")) {
			cp = buf + 6;
			while (*cp == ' ' || *cp == '\t')
				cp++;
			if ((*cp == '\0') || (*cp == '\n'))
				continue;
			if ((ep = strchr(cp, '\n')) != NULL)
				*ep = '\0';
			/* As per resolv.conf(5), if there's more than
			 * one line, only the last line is used
			 */
			if (srch)
				free(srch);
			srch = strdup(cp);
			continue;
		}
		if (MATCH(buf, "nameserver")) {
			cp = buf + 10;
			while (*cp == ' ' || *cp == '\t')
				cp++;
			if ((*cp == '\0') || (*cp == '\n'))
				continue;
			if ((ep = strchr(cp, '\n')) != NULL)
				*ep = '\0';
			/* nameserver entries are accumulated */
			if (nsrv[0])
				*--cp=' ';
			strncat(nsrv, cp, sizeof(nsrv) - strlen(nsrv) - 1);
			continue;
		}
	}
#undef MATCH

	fclose(fp);

	if (asprintf(&r->nameserver, "NAMESERVER=%s", nsrv) == -1)
		logger(-1, errno, "asprintf()");
	if (asprintf(&r->searchdomain, "SEARCHDOMAIN=%s", srch) == -1)
		logger(-1, errno, "asprintf()");
	free(srch);

	return 0;
}

int env_dns_configure(struct vzctl_env_handle *h, struct vzctl_env_param *env,
		int flags)
{
	list_head_t *phead;
	char *envp[MAX_ARGS];
	char state[64];
	char *str;
	const char *script;
	int ret, i = 0;
	struct resolv_conf_data r = {};

	if (flags & VZCTL_SKIP_CONFIGURE)
		return 0;

	if (list_empty(&env->misc->searchdomain) &&
	    list_empty(&env->misc->nameserver))
		return 0;

	if (!is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_NOT_RUN, 0,
			"Unable to configure: Container is not running");

	if ((ret = read_dist_actions(h)))
		return ret;

	script = h->dist_actions->set_dns;
	if (script == NULL) {
		logger(0, 0, "Warning: set_dns action script is not specified");
		return 0;
	}

	snprintf(state, sizeof(state), "VE_STATE=%s", get_state(h));
	envp[i++] = strdup(state);

	phead = &env->misc->searchdomain;
	if (!list_empty(phead)) {
		str = list_first_entry(phead, struct vzctl_str_param, list)->str;
		if (strcmp(str, "inherit") == 0) {
			read_resolv_conf(&r);
			str = r.searchdomain;
			r.searchdomain = NULL;
		}
		else
			str = list2str("SEARCHDOMAIN=", phead);

		if (str != NULL)
			envp[i++] = str;
	}
	phead = &env->misc->nameserver;
	if (!list_empty(phead)) {
		str = list_first_entry(phead, struct vzctl_str_param, list)->str;
		if (strcmp(str, "inherit") == 0) {
			read_resolv_conf(&r);
			str = r.nameserver;
			r.nameserver = NULL;
		}
		else
			str = list2str("NAMESERVER=", phead);

		if (str != NULL)
			envp[i++] = str;
	}
	envp[i] = NULL;
	ret = vzctl2_wrap_env_exec_vzscript(h, NULL, envp, script,
			VZCTL_SCRIPT_EXEC_TIMEOUT, EXEC_LOG_OUTPUT);

	logger(0, 0, "File resolv.conf was modified");
	free_ar_str(envp);
	free(r.nameserver);
	free(r.searchdomain);

	return ret;
}

int env_pw_configure(struct vzctl_env_handle *h, const char *user,
		const char *pw, int flags)
{
	char *env[3];
	const char *script;
	int ret;
	char userpw[1024];
	int i = 0;

	if (!is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_NOT_RUN, 0,
			"Unable to configure: Container is not running");
	if ((ret = read_dist_actions(h)))
		return ret;

	script = h->dist_actions->set_userpass;
	if (script == NULL) {
		logger(0, 0, "Warning: set_userpass action script is not"
			" specified");
		return 0;
	}
	snprintf(userpw, sizeof(userpw), "USERPW=%s:%s", user, pw);
	env[i++] = userpw;
	if (flags & VZCTL_SET_USERPASSWD_CRYPTED)
		env[i++] = "IS_CRYPTED=1";
	env[i] = NULL;

	ret = vzctl2_wrap_env_exec_vzscript(h, NULL, env, script,
			VZCTL_SCRIPT_EXEC_TIMEOUT, EXEC_LOG_OUTPUT);

	if (ret)
		return vzctl_err(VZCTL_E_CHANGEPASS, 0,
			"Password change failed");
	return ret;
}

static int quotaon(void)
{
	int pid, ret;
	char *arg[] = {"quotaon", "-a", NULL};

	logger(0, 0, "Turn userquota on");
	pid = fork();
	if (pid == 0) {
		execvep(arg[0], arg, envp_s);
		logger(-1, errno, "Failed to exec %s", arg[0]);
		exit(42);
	} else if (pid == -1)
		return vzctl_err(-1, errno, "fork");
	ret = env_wait(pid, 0, NULL);
	if (ret)
		return vzctl_err(ret, 0, "%s exited with error %d",
				arg[0], ret);
	return 0;
}

int setup_env_quota(int mode)
{
	int ret;
	struct stat st;

	if (stat("/", &st))
		return vzctl_err(-1, errno, "Failed to stat /");

	if (stat_file(QUOTA_U) == 0 || stat_file(QUOTA_G) == 0) {
		char *quotacheck[] = {"quotacheck", "-anugmM", "-F",
			(char *)get_jquota_format(mode), NULL};

		logger(0, 0, "Running quotacheck ...");
		ret = vzctl2_exec_script(quotacheck, NULL, 0);
		if (ret)
			return ret;
	}

	return quotaon();
}

static int env_quota_configure(struct vzctl_env_handle *h,
		unsigned long ugidlimit, int flags)
{
	int ret;
	char buf[STR_SIZE];
	char *envp[6];
	int i = 0;

	if (flags & VZCTL_SKIP_CONFIGURE)
		return 0;

	if ((ret = read_dist_actions(h)))
		return ret;

	if (h->dist_actions->set_ugid_quota == NULL) {
		logger(0, 0, "Warning: set_ugid_quota action script is not"
				" specified");
		return 0;
	}

	if (h->env_param->fs->layout <= VZCTL_LAYOUT_4 && ugidlimit != 0)  {
		snprintf(buf, sizeof(buf), "DEVFS=%s", vz_fs_get_name(
						h->env_param->fs->ve_root));
		envp[i++] = strdup(buf);
	}
	if (ugidlimit != 0) {
		snprintf(buf, sizeof(buf), "UGIDLIMIT=%lu", ugidlimit);
		envp[i++] = strdup(buf);
	}
	envp[i++] = strdup(ENV_PATH);
	envp[i] = NULL;

	logger(0, 0, "Setting quota ugidlimit: %lu", ugidlimit);
	ret = vzctl2_wrap_env_exec_vzscript(h, NULL, envp,
			h->dist_actions->set_ugid_quota,
			VZCTL_SCRIPT_EXEC_TIMEOUT, EXEC_LOG_OUTPUT);

	free_ar_str(envp);

	return ret;
}

int apply_quota_param(struct vzctl_env_handle *h, struct vzctl_env_param *env, int flags)
{
	if ((flags & VZCTL_RESTORE) ||
			h->env_param->dq->enable == VZCTL_PARAM_OFF ||
			env->dq->ugidlimit == NULL)
		return 0;

	return env_quota_configure(h, *env->dq->ugidlimit, flags);
}

int env_console_configure(struct vzctl_env_handle *h, int flags)
{
	int ret;

	if (flags & VZCTL_SKIP_CONFIGURE)
		return 0;

	if ((ret = read_dist_actions(h)))
		return ret;

	if (h->dist_actions->set_console == NULL)
		return 0;

	if (vzctl2_wrap_env_exec_vzscript(h, NULL, NULL,
				h->dist_actions->set_console,
				VZCTL_SCRIPT_EXEC_TIMEOUT, EXEC_LOG_OUTPUT))
		return vzctl_err(VZCTL_E_ACTIONSCRIPT, 0,
				"Failed to configure Container console");
	return 0;
}

/*
 * Setup (add/delete) IP address(es) inside CT
 */
int env_ip_configure(struct vzctl_env_handle *h, int cmd,
		list_head_t *ip, int delall, int flags)
{
	char *env[6];
	const char *script = NULL;
	char *ip_str = NULL;
	int ret, i = 0;
	char state_str[32];

	if (flags & (VZCTL_SKIP_CONFIGURE | VZCTL_RESTORE))
		return 0;

	if (list_empty(ip) && !delall)
		return 0;
	if ((ret = read_dist_actions(h)))
		return ret;
	switch (cmd) {
	case VZCTL_IP_ADD_CMD:
		if ((script = h->dist_actions->add_ip) == NULL)
			return vzctl_err(0, 0, "Warning: add_ip action script"
				" is not specified");
		break;
	case VZCTL_IP_DEL_CMD:
		if ((script = h->dist_actions->del_ip) == NULL)
			return vzctl_err(0, 0, "Warning: del_ip action script"
				" is not specified");
		break;
	}
	snprintf(state_str, sizeof(state_str), "VE_STATE=%s", get_state(h));
	env[i++] = state_str;
	if (delall)
		env[i++] = "IPDELALL=yes";

	if (vzctl2_env_get_param_bool(h, "IPV6") == VZCTL_PARAM_ON)
		env[i++] = "IPV6=yes";

	env[i++] = ENV_PATH;
	ip_str = ip2str("IP_ADDR=", ip, 1);
	env[i++] = ip_str;
	env[i] = NULL;

	ret = vzctl2_wrap_env_exec_vzscript(h, NULL, env, script,
			VZCTL_SCRIPT_EXEC_TIMEOUT, EXEC_LOG_OUTPUT);

	free(ip_str);

	return ret;
}

static int configure_pci(struct vzctl_env_handle *h, int op, const char *dev)
{
	char *argv[2];
	char *envp[5];
	int ret;
	char buf[STR_SIZE];
	int i = 0;

	snprintf(buf, sizeof(buf), "VEID=%s", EID(h));
	envp[i++] = strdup(buf);
	snprintf(buf, sizeof(buf), "VE_ROOT=%s", h->env_param->fs->ve_root);
	envp[i++] = strdup(buf);
	snprintf(buf, sizeof(buf), "ADD=%d", op);
	envp[i++] = strdup(buf);
	snprintf(buf, sizeof(buf), "PCI=%s", dev) ;
	envp[i++] = strdup(buf);
	envp[i] = NULL;

	argv[0] = get_script_path(VZCTL_PCI_CONFIGURE, buf, sizeof(buf));
	argv[1] = NULL;

	ret = vzctl2_wrap_exec_script(argv, envp, 0);
	if (ret)
		ret = VZCTL_E_SET_PCI;
	free_ar_str(envp);

	return ret;
}

int env_pci_configure(struct vzctl_env_handle *h, struct vzctl_env_param *env, int flags)
{
	struct vzctl_str_param *it;
	list_head_t *head;
	int ret;

	if (!is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_NOT_RUN, 0,
				"Unable to apply PCI devices: Container is not running");
	logger(0, 0, "Setting PCI devices");
	head = &env->dev->pci;
	list_for_each(it, head, list) {
		configure_pci(h, 0, it->str);
	}
	head = &env->dev->pci_del;
	list_for_each(it, head, list) {
		ret = configure_pci(h, 1, it->str);
		if (ret)
			return ret;
	}

	return 0;
}

int vzctl_env_configure(struct vzctl_env_handle *h, struct vzctl_env_param *env, int flags)
{
	int ret;

	if (h->env_param->opts->apply_iponly != VZCTL_PARAM_ON &&
			env->opts->apply_iponly != VZCTL_PARAM_ON) {

		if ((ret = env_hostnm_configure(h, env, flags)))
			return ret;
		if ((ret = env_dns_configure(h, env, flags)))
			return ret;
	}

	if (!list_empty(&env->dev->pci) ||
			!list_empty(&env->dev->pci_del))
	{
		ret = env_pci_configure(h, env, flags);
		if (ret)
			return ret;
	}


	return 0;
}
