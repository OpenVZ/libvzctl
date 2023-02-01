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
#include <string.h>
#include <stdio.h>

#include <linux/vzcalluser.h>

#include "libvzctl.h"
#include "iptables.h"
#include "logger.h"
#include "vzerror.h"
#include "env.h"

struct iptables_s {
        char *name;
        unsigned long id;
        unsigned long long ipt_mask;
};

static struct iptables_s _g_iptables[] = {
	{"ip_tables", VE_IP_IPTABLES_MOD, VE_IP_IPTABLES},
	{"iptable_filter", VE_IP_FILTER_MOD, VE_IP_FILTER},
	{"iptable_mangle", VE_IP_MANGLE_MOD, VE_IP_MANGLE},
	{"ipt_limit", VE_IP_MATCH_LIMIT_MOD, VE_IP_IPTABLES},
	{"ipt_multiport", VE_IP_MATCH_MULTIPORT_MOD, VE_IP_IPTABLES},
	{"ipt_tos", VE_IP_MATCH_TOS_MOD, VE_IP_IPTABLES},
	{"ipt_TOS", VE_IP_TARGET_TOS_MOD, VE_IP_IPTABLES},
	{"ipt_REJECT", VE_IP_TARGET_REJECT_MOD, VE_IP_IPTABLES},
	{"ipt_TCPMSS", VE_IP_TARGET_TCPMSS_MOD, VE_IP_IPTABLES},
	{"ipt_tcpmss", VE_IP_MATCH_TCPMSS_MOD, VE_IP_IPTABLES},
	{"ipt_ttl", VE_IP_MATCH_TTL_MOD, VE_IP_IPTABLES},
	{"ipt_LOG", VE_IP_TARGET_LOG_MOD, VE_IP_IPTABLES},
	{"ipt_length", VE_IP_MATCH_LENGTH_MOD, VE_IP_IPTABLES},
	{"ip_conntrack", VE_IP_CONNTRACK_MOD, VE_IP_CONNTRACK},
	{"ip_conntrack_ftp", VE_IP_CONNTRACK_FTP_MOD, VE_IP_CONNTRACK_FTP},
	{"ip_conntrack_irc", VE_IP_CONNTRACK_IRC_MOD, VE_IP_CONNTRACK_IRC},
	{"ipt_conntrack", VE_IP_MATCH_CONNTRACK_MOD, VE_IP_CONNTRACK},
	{"ipt_state", VE_IP_MATCH_STATE_MOD, VE_IP_CONNTRACK},
	{"ipt_helper", VE_IP_MATCH_HELPER_MOD, VE_IP_CONNTRACK},
	{"iptable_nat", VE_IP_NAT_MOD, VE_IP_NAT},
	{"ip_nat_ftp", VE_IP_NAT_FTP_MOD, VE_IP_NAT_FTP},
	{"ip_nat_irc", VE_IP_NAT_IRC_MOD, VE_IP_NAT_IRC},

#ifdef VE_IP_TARGET_REDIRECT
	{"ipt_REDIRECT",VE_IP_TARGET_REDIRECT_MOD, VE_IP_NAT},
#endif
#ifdef VE_IP_MATCH_MAC
	{"xt_mac",	VE_IP_MATCH_MAC_MOD, VE_IP_IPTABLES},
#endif
	{"ipt_owner",	VE_IP_MATCH_OWNER_MOD, VE_IP_IPTABLES},
	{NULL}
};

static struct iptables_s *find_ipt_by_name(struct iptables_s *ipt, const char *name)
{
	struct iptables_s *p;

	for (p = ipt; p->name != NULL; p++)
		if (!strcmp(name, p->name))
			return p;
	return NULL;
}

static struct iptables_s *find_ipt_by_id(struct iptables_s *ipt, unsigned long id)
{
	struct iptables_s *p;

	for (p = ipt; p->name != NULL; p++)
		if (p->id == id)
			return p;
	return NULL;
}

void iptables_mask2str(unsigned long mask, char *buf, int size)
{
	int r;
	char *sp, *ep;
	struct iptables_s *p;

	*buf = '\0';
	sp = buf;
	ep = buf + size;
	for (p = _g_iptables; p->name != NULL; p++) {
		if (!(mask & p->id))
			continue;
		r = snprintf(sp, ep - sp, "%s ", p->name);
		if (r < 0 || sp + r >= ep)
			break;
		sp += r;
	}
}

static unsigned long long get_iptables_mask(unsigned long id)
{
	struct iptables_s *p;
	unsigned long long mask = 0;

	for (p = _g_iptables; p->name != NULL; p++)
		if (p->id & id)
			mask |= p->ipt_mask;

	return mask;
}

unsigned long long get_ipt_mask(struct vzctl_features_param *param)
{
	if (param->ipt_mask)
		return get_iptables_mask(param->ipt_mask);

	return VE_IP_DEFAULT;
}

static int parse_ipt(struct iptables_s *ipt, unsigned long *mask, const char *val)
{
	char *buf;
	char *token;
	struct iptables_s *p;
	int ret = 0;
	char *savedptr;

	buf = strdup(val);
	if ((token = strtok_r(buf, LIST_DELIMITERS, &savedptr)) != NULL) {
		do {
			p = find_ipt_by_name(ipt, token);
			if (p != NULL)
				*mask |= (unsigned long) p->id;
			else
				ret = vzctl_err(VZCTL_E_INVAL, 0, "Warning:"
						" Unknown iptable module %s; skipped",
						token);
		} while ((token = strtok_r(NULL, LIST_DELIMITERS, &savedptr)));
	}
	free(buf);

	return ret;
}

int parse_iptables(unsigned long *mask, const char *val)
{
	return parse_ipt(_g_iptables, mask, val);
}
