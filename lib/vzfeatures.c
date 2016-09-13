/*
 *  Copyright (c) 1999-2015 Parallels IP Holdings GmbH
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
 * Our contact details: Parallels IP Holdings GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 *
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sys/utsname.h>
#include <linux/vzcalluser.h>

#include "vzctl.h"
#include "vzfeatures.h"
#include "vztypes.h"
#include "vzerror.h"
#include "logger.h"
#include "libvzctl.h"
#include "util.h"

struct feature_s {
	char *name;
	unsigned long long mask;
};

static struct feature_s features[] = {
	{ "sysfs",	VZ_FEATURE_SYSFS },
	{ "nfs",	VZ_FEATURE_NFS },
	{ "sit",        VZ_FEATURE_SIT},
	{ "ipip",       VZ_FEATURE_IPIP},
	{ "ppp",        VZ_FEATURE_PPP},
	{ "ipgre",      VZ_FEATURE_IPGRE},
	{ "bridge",     VZ_FEATURE_BRIDGE},
	{ "nfsd",       VZ_FEATURE_NFSD},
	{ NULL}
};

int vzctl2_fstype2layout(unsigned long fstype)
{
	switch (fstype) {
	case VZ_T_SIMFS:
		return VZCTL_LAYOUT_4;
	case VZ_T_EXT4:
		return VZCTL_LAYOUT_5;
	default:
		return 0;
	}
	return 0;
}

const char *vzctl2_layout2fstype(int layout)
{
	if (layout == VZCTL_LAYOUT_5)
		return "ext4";
	return "simfs";
}

static struct feature_s *find_feature(const char *name)
{
	struct feature_s *f;

	for (f = features; f->name != NULL; f++) {
		if (strcmp(name, f->name) == 0)
			return f;
	}

	return NULL;
}

void features_mask2str(struct vzctl_features_param *f, char *buf, int len)
{
	struct feature_s *p;
	int r;
	char *sp, *ep;

	buf[0] = '\0';
	sp = buf;
	ep = buf + len;
	for (p = features; p->name != NULL; p++) {
		if (!(f->known & p->mask))
			continue;

		r = snprintf(sp, ep - sp, "%s:%s ", p->name,
				f->mask & p->mask ? "on" : "off");
		if (r < 0 || sp + r >= ep)
			break;
		sp += r;

	}
}

static int parse_feature(struct vzctl_features_param *features, const char *str)
{
	int id, len;
	const char *p;
	struct feature_s *f;
	char name[STR_SIZE];

	p = strrchr(str, ':');
	if (p == NULL)
		goto err;

	len = p - str;
	if (len >= sizeof(name))
		len = sizeof(name) - 1;
	strncpy(name, str, len);
	name[len] = 0;
	f = find_feature(name);
	if (f == NULL)
		goto err;

	id = onoff2id(p + 1);
	if (id == -1)
		goto err;
	if (id == VZCTL_PARAM_ON)
		features->mask |= f->mask;
	features->known |= f->mask;

	return 0;
err:

	return vzctl_err(VZCTL_E_INVAL, 0, "An incorrect feature syntax: %s", str);
}

int parse_features(struct vzctl_features_param *features, const char *str)
{
	int ret = 0;
	char *buf = NULL, *token;
	char *savedptr;

	ret = xstrdup(&buf, str);
	if (ret)
		return ret;
	if ((token = strtok_r(buf, LIST_DELIMITERS, &savedptr)) != NULL) {
		do {
			ret = parse_feature(features, token);
			if (ret)
				break;

		} while ((token = strtok_r(NULL, LIST_DELIMITERS, &savedptr)) != NULL);
	}
	free(buf);

	return ret;
}

#define VZ_T_ARCH	(VZ_T_I386 | VZ_T_X86_64 | VZ_T_IA64)

static struct tech_mtx {
	unsigned long id;
	char *kver;
} tech_mtx[] = {
	{VZ_T_NPTL,		"2.6"},
	{VZ_T_SYSFS,		"2.6.8"},
	{VZ_T_NFS,		"2.6.18"},
	{VZ_T_VZFS_HASHDIR,	"2.6.9"},
	{VZ_T_VZFS_COWDIR,	"2.6.9"},
	{VZ_T_VZFS_MFILES,	"2.6.9"},
	{VZ_T_SIMFS,		"2.4"},
	{VZ_T_EXT4,		"2.6.32"},
};

static struct id2name {
	unsigned long id;
	char *name;
} id2name[] = {
	{VZ_T_I386,		"x86"},
	{VZ_T_X86_64,		"x86_64"},
	{VZ_T_IA64,		"ia64"},
	{VZ_T_NPTL,		"nptl"},
	{VZ_T_SYSFS,		"sysfs"},
	{VZ_T_NFS,		"nfs"},
	{VZ_T_VZFS_HASHDIR,	"hashdir"},
	{VZ_T_VZFS_COWDIR,	"cowdir"},
	{VZ_T_VZFS_MFILES,	"mfiles"},
	{VZ_T_EXT4,		"ext4"},
	{VZ_T_VZFS0,		"simfs"},
	{VZ_T_SIMFS,		"simfs"},
};

const char *vzctl2_tech2name(unsigned long long id)
{
	int i;

	for (i = 0; i < sizeof(id2name) / sizeof(id2name[0]); i++)
		if (id2name[i].id == id)
			return id2name[i].name;
	return 0;
}

unsigned long long vzctl2_name2tech(const char *name)
{
	int i;

	for (i = 0; i < sizeof(id2name) / sizeof(id2name[0]); i++)
		if (!strcmp(name, id2name[i].name))
			return id2name[i].id;
	return 0;
}

static int ver_cmp(const char *str1, const char *str2)
{
	const char *p1, *p2;
	int ret;

	p1 = str1;
	p2 = str2;
	while (1) {
		/* skip till the next valuable block */
		while (*p1 && (!isalnum(*p1) || *p1 == '0'))
			p1++;
		while (*p2 && (!isalnum(*p2) || *p2 == '0'))
			p2++;
		if (!*p1 || !*p2)
			break;

		str1 = p1;
		str2 = p2;
		if (isdigit(*p1)) {
			/* compare numeric */
			if (!isdigit(*p2))
				return -1;
			while (*p1 && isdigit(*p1))
				p1++;
			while (*p2 && isdigit(*p2))
				p2++;
			if ((p1 - str1) > (p2 - str2))
				return 1;
			else if ((p1 - str1) < (p2 - str2))
				return -1;
			else {
				ret = strncmp(str1, str2, p1 - str1);
				if (ret)
					return ret;
			}
		} else {
			/* compare strings */
			if (!isalpha(*p2))
				return -1;
			while (*p1 && isalpha(*p1) && *p2 && isalpha(*p2)) {
				if (*p1 > *p2)
					return 1;
				else if (*p2 > *p1)
					return -1;
				p1++;
				p2++;
			}
			if ((!*p1 || !isalpha(*p1)) && *p2 && isalpha(*p2))
				return -1;
			else if (*p1 && isalpha(*p1) && (!*p2 || !isalpha(*p2)))
				return 1;
		}
	}
	/* the only way to escape from cycle is one string's end */
	if (!*p2 && *p1)
		return 1;
	else if (!*p1 && *p2)
		return -1;
	return 0;
}

static unsigned long get_supported_tech(void)
{
	int i;
	struct utsname uts;
	unsigned long long mask;
	const char *kver, *arch;

	if (uname(&uts))
		return 0;
	arch = uts.machine;
	/* Get architecture */
	if (arch[0] == 'i' && arch[2] == '8' && arch[3] == '6' && arch[4] == 0)
		arch = "x86";
	mask = vzctl2_name2tech(arch);
	kver = uts.release;
	/* Get kernel supported technologies */
	for (i = 0; i < sizeof(tech_mtx) / sizeof(tech_mtx[0]); i++)
		if (ver_cmp(kver, tech_mtx[i].kver) >= 0)
			mask |= tech_mtx[i].id;
	return mask;
}


/** Check supported technologies.
 * Compare technologies in mask with running kernel technologies,
 * return unsupported technologies mask.
 *
 * @param mask		requested technologies.
 * @return		unsupported technologies
 */
unsigned long vzctl2_check_tech(unsigned long mask)
{
	unsigned long provides;

	provides = get_supported_tech();
	if (provides & VZ_T_X86_64)
		provides |= VZ_T_I386;
	return (mask & provides) ^ mask;
}

const char *tech2str(unsigned long long mask, char *buf, int len)
{
	int i, r;
	char *sp, *ep;

	buf[0] = '\0';
	sp = buf;
	ep = buf + len;
	for (i = 0; i < sizeof(id2name) / sizeof(id2name[0]); i++) {
		if (!(mask & id2name[i].id))
			continue;

		r = snprintf(sp, ep - sp, "%s ", id2name[i].name);
		if (r < 0 || sp + r >= ep)
			break;
		sp += r;
	}
	return buf;
}

static int parse_tech(const char *name, unsigned long long *tech)
{
	unsigned long long mask;

	if (!(mask = vzctl2_name2tech(name)))
		return -1;
	*tech |= mask;

	return 0;
}

int parse_technologies(unsigned long long *tech, const char *str)
{
	int ret = 0;
	char *buf, *token;
	char *savedptr;

	buf = strdup(str);
	if ((token = strtok_r(buf, LIST_DELIMITERS, &savedptr)) != NULL) {
		do {
			ret = parse_tech(token, tech);
		} while ((token = strtok_r(NULL, LIST_DELIMITERS, &savedptr)) != NULL);
	}
	free(buf);

	return ret;
}

static int check_features_mask(unsigned long mask)
{
	struct feature_s *f;
	unsigned long known = 0;

	for (f = features; f->name != NULL; f++)
		known |= f->mask;

	return (known | mask) != known;
}

int vzctl2_env_set_features(struct vzctl_env_param *env, struct vzctl_feature_param *param)
{
	struct vzctl_features_param *f = env->features;

	if (check_features_mask(param->on))
		return vzctl_err(VZCTL_E_INVAL, 0, "An invalid feature on=%#llx is specified",
				param->on);
	if (check_features_mask(param->off))
		return vzctl_err(VZCTL_E_INVAL, 0, "An invalid feature off=%#llx is specified",
				param->off);

	f->mask = param->on;
	f->known = param->on | param->off;

	return 0;
}

int vzctl2_env_get_features(struct vzctl_env_param *env, struct vzctl_feature_param *param)
{
	struct vzctl_features_param *f = env->features;

	param->on = f->mask;
	param->off = ~f->mask & f->known;

	return 0;
}

unsigned long long tech2features(unsigned long long tech)
{
	if (tech & VZ_T_NFS)
		return VE_FEATURE_NFS;

	return 0;
}
