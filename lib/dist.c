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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "util.h"
#include "dist.h"
#include "config.h"
#include "logger.h"
#include "vzerror.h"
#include "vztypes.h"
#include "create.h"
#include "vztmpl.h"

static int add_dist_action(struct vzctl_dist_actions *dist_actions,
	const char *name, const char *action, const char *dir)
{
	char file[PATH_MAX];

	if (!action[0])
		return 0;

	snprintf(file, sizeof(file), "%s/%s/%s", dir, DIST_SCRIPTS, action);
	if (!stat_file(file)) {
		logger(-1, 0, "Action script %s does not found", file);
		return 0;
	}

#define ADD_DIST_SCRIPT(n, f) \
	if (dist_actions->f == NULL && !strcmp(name, n)) \
		return xstrdup(&dist_actions->f, file); \

	ADD_DIST_SCRIPT("ADD_IP", add_ip)
	ADD_DIST_SCRIPT("DEL_IP", del_ip)
	ADD_DIST_SCRIPT("SET_HOSTNAME", set_hostname)
	ADD_DIST_SCRIPT("SET_DNS", set_dns)
	ADD_DIST_SCRIPT("SET_USERPASS", set_userpass)
	ADD_DIST_SCRIPT("SET_UGID_QUOTA", set_ugid_quota)
	ADD_DIST_SCRIPT("POST_CREATE", post_create)
	ADD_DIST_SCRIPT("NETIF_ADD", netif_add)
	ADD_DIST_SCRIPT("NETIF_DEL", netif_del)
	ADD_DIST_SCRIPT("SET_CONSOLE", set_console)

	return 0;
#undef ADD_DIST_SCRIPT
}

const char *get_dist_action_script(struct vzctl_dist_actions *dist,
		const char *name)
{
#define GET_DIST_SCRIPT(n, f) \
	if (!strcmp(name, n)) \
		return dist->f;

	GET_DIST_SCRIPT("ADD_IP", add_ip)
	GET_DIST_SCRIPT("DEL_IP", del_ip)
	GET_DIST_SCRIPT("SET_HOSTNAME", set_hostname)
	GET_DIST_SCRIPT("SET_DNS", set_dns)
	GET_DIST_SCRIPT("SET_USERPASS", set_userpass)
	GET_DIST_SCRIPT("SET_UGID_QUOTA", set_ugid_quota)
	GET_DIST_SCRIPT("POST_CREATE", post_create)
	GET_DIST_SCRIPT("NETIF_ADD", netif_add)
	GET_DIST_SCRIPT("NETIF_DEL", netif_del)
	GET_DIST_SCRIPT("SET_CONSOLE", set_console)

	return NULL;
#undef GET_DIST_SCRIPT
}

void free_dist_action(struct vzctl_dist_actions *dist_actions)
{
	if (dist_actions == NULL)
		return;
	free(dist_actions->add_ip);
	free(dist_actions->del_ip);
	free(dist_actions->set_hostname);
	free(dist_actions->set_dns);
	free(dist_actions->set_userpass);
	free(dist_actions->set_ugid_quota);
	free(dist_actions->post_create);
	free(dist_actions->netif_add);
	free(dist_actions->netif_del);
	free(dist_actions->set_console);
	free(dist_actions);
}

static int get_dist_conf_name(const char *dist_name, const char *dir,
	char *file, int len)
{
	char buf[256];
	char *ep;

	if (dist_name != NULL) {
		snprintf(buf, sizeof(buf), "%s", dist_name);
		ep = buf + strlen(buf);
		do {
			snprintf(file, len, "%s/%s.conf", dir, buf);
			if (stat_file(file))
				return 0;
			while (ep > buf && *ep !=  '-') --ep;
			*ep = 0;
		} while (ep > buf);
		snprintf(file, len, "%s/%s", dir, DIST_CONF_DEF);
		logger(-1, 0, "Warning: configuration file"
			" for distribution %s not found default used",
			dist_name);
	} else {
		snprintf(file, len, "%s/%s", dir, DIST_CONF_DEF);
		logger(-1, 0, "Warning: distribution not specified"
			" default used %s", file);
	}
	if (!stat_file(file))
		return vzctl_err(VZCTL_E_NO_DISTR_CONF, 0,
				"Distribution configuration not found %s", file);
	return 0;
}

/** Get distribution name form tmpl_param structure.
 *
 * @param tmpl		distribution data.
 * @return		malloc'ed name.
 */
char *get_dist_name(struct vzctl_tmpl_param *tmpl)
{
	if (tmpl->dist != NULL)
		return strdup(tmpl->dist);
	if (tmpl->ostmpl != NULL) {
		char dist[STR_SIZE];

		if (vztmpl_get_distribution(tmpl->ostmpl, dist, sizeof(dist)) == 0)
			return strdup(dist);
		return strdup(tmpl->ostmpl);
	}
	return NULL;
}

/* Read distribution specific action configuration file.
 */
int read_dist_actions(struct vzctl_env_handle *h)
{
	char buf[256];
	char ltoken[256];
	char file[PATH_MAX];
	char *rtoken;
	FILE *fp;
	int ret = 0;
	char *dist;

	if (h->dist_actions != NULL)
		return 0;
	dist = get_dist_name(h->env_param->tmpl);
	ret = get_dist_conf_name(dist, DIST_DIR, file, sizeof(file));
	xfree(dist);
	if (ret)
		return ret;
	if ((fp = fopen(file, "r")) == NULL) {
		return vzctl_err(VZCTL_E_READ_DISTACTION, errno,
			"unable to open %s", file);
	}
	h->dist_actions = calloc(1, sizeof(struct vzctl_dist_actions));
	if (h->dist_actions == NULL) {
		fclose(fp);
		return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "read_dist_actions");
	}
	while (!feof(fp)) {
		buf[0] = 0;
		if (fgets(buf, sizeof(buf), fp) == NULL)
			break;
		if ((rtoken = parse_line(buf, ltoken, sizeof(ltoken))) == NULL)
			continue;
		if ((ret = add_dist_action(h->dist_actions, ltoken, rtoken, DIST_DIR))) {
			free_dist_action(h->dist_actions);
			h->dist_actions = NULL;
			break;
		}
	}
	fclose(fp);
	return ret;
}


