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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/vzcalluser.h>
#include <linux/vzctl_netstat.h>

#include "config.h"
#include "vzenv.h"
#include "vzerror.h"
#include "logger.h"
#include "hook.h"
#include "util.h"
#include "vz.h"
#include "env.h"
#include "exec.h"

struct vzctl_rate *alloc_rate()
{
	return calloc(1, sizeof(struct vzctl_rate));
}

void free_rate(struct vzctl_rate *rate)
{
	if (rate->dev != NULL)
		free(rate->dev);
	free(rate);
}

static void free_rate_list(list_head_t *head)
{
	struct vzctl_rate *it, *tmp;

	list_for_each_safe(it, tmp, head, list) {
		list_del(&it->list);
		free_rate(it);
	}
}

void free_tc_param(struct vzctl_tc_param *param)
{
	free_rate_list(&param->totalrate_list);
	free_rate_list(&param->rate_list);
	free(param);
}

struct vzctl_tc_param *alloc_tc_param(void)
{
	struct vzctl_tc_param *param;

	param = calloc(1, sizeof(struct vzctl_tc_param));
	if (param == NULL)
		return NULL;
	list_head_init(&param->totalrate_list);
	list_head_init(&param->rate_list);
	return param;
}

int parse_rate(list_head_t *head, const char *str, int num)
{
	char *tail, *tail2;
	char *s;
	int numparam = 0;
	struct vzctl_rate *rate;
	int len, ret;

	if ((s = strchr(str, ':')) == NULL)
		return VZCTL_E_INVAL;
	len = s - str;
	if (len <= 0)
		return VZCTL_E_INVAL;
	rate = alloc_rate();
	if (rate == NULL)
		return VZCTL_E_NOMEM;
	ret = VZCTL_E_INVAL;
	rate->dev = malloc(len + 1);
	strncpy(rate->dev, str, len);
	rate->dev[len] = 0;
	numparam++;
	rate->net_class = strtoul(s + 1, &tail, 10);
	if (errno == ERANGE)
		goto err;
	numparam++;
	if (*tail == ':') {
		tail++;
		errno = 0;
		rate->rate = strtoul(tail, &tail2, 10);
		if ((*tail2 != '\0') || (errno == ERANGE))
			goto err;
		numparam++;
	} else if (*tail != '\0') {
		goto err;
	}
	if (numparam != num)
		goto err;
	list_add_tail(&rate->list, head);
	return 0;
err:
	free_rate(rate);
	return ret;
}

int parse_rates(list_head_t *head, const char *str, int num, int replace)
{
	int ret = 0;
	char *tmp;
	char *token;
	char *savedptr;

	if (replace)
		free_rate_list(head);

	tmp = strdup(str);
	if ((token = strtok_r(tmp, LIST_DELIMITERS, &savedptr)) != NULL) {
		do {
			ret = parse_rate(head, token, num);
			if (ret != 0) {
				debug(DBG_CFG, "failed to parse the rate entry '%s'", tmp);
				break;
			}
		} while ((token = strtok_r(NULL, LIST_DELIMITERS, &savedptr)) != NULL);
	}
	free(tmp);
	return ret;
}

char *rate2str(list_head_t *head)
{
	char buf[STR_MAX];
	struct vzctl_rate *it;
	char *sp, *ep;

	if (list_empty(head))
		return NULL;
	sp = buf;
	ep = buf + sizeof(buf);
	list_for_each(it, head, list) {
		sp += snprintf(sp, ep - sp, "%s:%d:%d ",
			it->dev, it->net_class, it->rate);
		if (sp >= ep)
			break;
	}
	sp[-1] = 0;

	return strdup(buf);
}

int tc_get_base(struct vzctl_env_handle *h, int *tc_base)
{
	int ret;

	ret = ioctl(get_vzctlfd(), VZCTL_TC_GET_BASE, h->veid);
	if (ret == -1) {
		return vzctl_err(VZCTL_E_SET_RATE, errno, "tc_get_base failed");
	} else if (ret == 0) {
		struct vzctl_tc_set_base tc = {.veid = h->veid};

		ret = ioctl(get_vzctlfd(), VZCTL_TC_SET_BASE, &tc);
		if (ret == -1)
			return vzctl_err(VZCTL_E_SET_RATE, errno,
					"tc_set_base failed");
	}

	logger(5, 0, "TC base %d veid=%d", ret, h->veid);
	*tc_base = ret;

	return 0;
}

int vzctl2_set_tc_param(struct vzctl_env_handle *h, struct vzctl_env_param *env,
		int flags)
{
	char buf[STR_MAX];
	char *argv[3];
	char *envp[MAX_ARGS];
	char *p;
	int tc_base = -1;
	int ret, i = 0;
	const char *bandwidth = NULL;
	const char *totalrate = NULL;
	const char *ratempu = NULL;
	int ratebound;
	struct vzctl_tc_param *tc = env->vz->tc;
	list_head_t *rate = !list_empty(&tc->rate_list) ? &tc->rate_list :
		&h->env_param->vz->tc->rate_list;

	vzctl2_env_get_param(h, "BANDWIDTH", &bandwidth);
	if (bandwidth == NULL)
		return vzctl_err(VZCTL_E_SET_RATE, 0, "BANDWIDTH is not set");
	vzctl2_env_get_param(h, "TOTALRATE", &totalrate);
	if (totalrate == NULL)
		return vzctl_err(VZCTL_E_SET_RATE, 0, "TOTALRATE is not set");
	vzctl2_env_get_param(h, "RATEMPU", &ratempu);

	ret = tc_get_base(h, &tc_base);
	if (ret)
		return ret;

	snprintf(buf, sizeof(buf), "VE_STATE=%s", get_state(h));
	envp[i++] = strdup(buf);
	snprintf(buf, sizeof(buf), "BANDWIDTH=%s", bandwidth);
	envp[i++] = strdup(buf);
	snprintf(buf, sizeof(buf), "TOTALRATE=%s", totalrate);
	envp[i++] = strdup(buf);
	if (ratempu != NULL) {
		snprintf(buf, sizeof(buf), "RATEMPU=%s", ratempu);
		envp[i++] = strdup(buf);
	}

	if (tc_base != -1)
		snprintf(buf, sizeof(buf), "TC_HANDLE_BASE=%d", tc_base);
	envp[i++] = strdup(buf);
	envp[i++] = strdup("TRAFFIC_SHAPING=yes");
	snprintf(buf, sizeof(buf), "VEID=%d", h->veid);
	envp[i++] = strdup(buf);
	if ((p = rate2str(rate)) != NULL) {
		logger(1, 0, "Setup shaping: %s", p);
		snprintf(buf, sizeof(buf), "RATE=%s", p);
		envp[i++] = strdup(buf);
		free(p);
	}
	ratebound = tc->ratebound ? tc->ratebound :
			h->env_param->vz->tc->ratebound;
	if (ratebound == VZCTL_PARAM_ON) {
		snprintf(buf, sizeof(buf), "RATEBOUND=yes");
		envp[i++] = strdup(buf);
	}
	envp[i] = NULL;
	argv[0] = get_script_path(VZCTL_SETRATE, buf, sizeof(buf));
	argv[1] = "add";
	argv[2] = NULL;
	ret = vzctl2_wrap_exec_script(argv, envp, 0);
	free_ar_str(envp);

	return ret;
}

int vzctl_apply_tc_param(struct vzctl_env_handle *h,
		struct vzctl_env_param *env, int flags)
{
	struct vzctl_tc_param *tc = env->vz->tc;

	if (h->env_param->vz->tc->traffic_shaping != VZCTL_PARAM_ON)
		return 0;
	if (!tc->ratebound && list_empty(&tc->rate_list))
		return 0;

	if (!is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_NOT_RUN, 0,
			"Unable to setup traffic shaping, Container is not running");

	return vzctl2_set_tc_param(h, env, flags);
}
