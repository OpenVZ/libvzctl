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

#include <stdio.h>
#include <sys/mount.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "vzerror.h"
#include "util.h"
#include "logger.h"
#include "bindmount.h"

static struct mount_opt {
	char *name;
	int flag;
} mount_opt[] = {
	{"nosuid", MS_NOSUID},
	{"noexec", MS_NOEXEC},
	{"nodev", MS_NODEV},
	{"ro", MS_RDONLY},
};

static int get_mount_opt(char* str)
{
	int i;

	for (i = 0; i < sizeof(mount_opt) / sizeof(mount_opt[0]); i++)
		if (!strcmp(str, mount_opt[i].name))
			return mount_opt[i].flag;
	return -1;
}

static void free_bindmount(struct vzctl_bindmount *mnt)
{
	free(mnt->src);
	free(mnt->dst);
}

void free_bindmount_param(struct vzctl_bindmount_param *mnt)
{
	struct vzctl_bindmount *tmp, *it;

	if (mnt == NULL)
		return;

	list_for_each_safe(it, tmp, &mnt->mounts, list) {
		list_del(&it->list);
		free_bindmount(it);
		free(it);
	}
	free(mnt);
}

struct vzctl_bindmount_param *alloc_bindmount_param(void)
{
	struct vzctl_bindmount_param *p;

	p = calloc(1, sizeof(struct vzctl_bindmount_param));
	if (p == NULL)
		return NULL;
	list_head_init(&p->mounts);

	return p;
}

static int add_bindmount(struct vzctl_bindmount_param *mnt,
		struct vzctl_bindmount *data)
{
	int ret;
	struct vzctl_bindmount *p;

	p = calloc(1, sizeof(struct vzctl_bindmount));
	if (mnt == NULL)
		return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "add_bindmount");

	ret = xstrdup(&p->src, data->src);
	if (ret)
		return ret;
	ret = xstrdup(&p->dst, data->dst);
	if (ret)
		return ret;

	p->op = data->op;
	p->mntopt = data->mntopt;
	list_add_tail(&p->list, &mnt->mounts);

	return 0;
}

static struct vzctl_bindmount *find_bindmount(struct vzctl_bindmount_param *mnt,
		const char *name)
{
	struct vzctl_bindmount *it;

	list_for_each(it, &mnt->mounts, list)
		if (!strcmp(it->dst, name))
			return it;
	return NULL;
}

static int merge_bindmount(struct vzctl_bindmount_param *old,
		struct vzctl_bindmount_param *new,
		struct vzctl_bindmount_param *merged)
{
	struct vzctl_bindmount *it;

	if (new == NULL || list_empty(&new->mounts))
		return 0;
	if (old != NULL) {
		list_for_each(it, &old->mounts, list) {
			if (find_bindmount(new, it->dst) == NULL)
				add_bindmount(merged, it);
		}
	}
	if (new != NULL) {
		list_for_each(it, &new->mounts, list) {
			if (it->op == ADD)
				add_bindmount(merged, it);
		}
	}
	return 0;
}

static int get_mount_optnames(int mntopt, char *buf, int len)
{
	int i;
	char *sp, *ep;

	sp = buf;
	ep = sp + len;
	*sp = 0;
	for (i = 0; i < sizeof(mount_opt) / sizeof(mount_opt[0]); i++) {
		if (mntopt & mount_opt[i].flag) {
			sp += snprintf(sp, ep - sp, ",%s", mount_opt[i].name);
			if (sp >= ep)
				break;
		}
	}
	return 0;
}

static int parse_bindmount_str(struct vzctl_bindmount_param *mnt, char *str, int add)
{
	char buf[32];
	char path[STR_SIZE];
	char *sp, *p, *ep;
	struct vzctl_bindmount mnt_s;
	int ret, len, mntopt;

	if (!add && !strcmp(str, "all")) {
		mnt->delall = 1;
		return 0;
	}
	ret = 0;
	sp = str;
	ep = sp + strlen(str);
	memset(&mnt_s, 0, sizeof(mnt_s));
	if ((p = strchr(sp, ':')) != NULL) {
		len = p - sp;
		if (sp[0] != '/')
			goto err;
		if (len == 0 || len > sizeof(path) - 1)
			goto err;
		strncpy(path, sp, len);
		path[len] = 0;
		mnt_s.src = strdup(path);
		sp = p + 1;
	}
	if ((p = strchr(sp, ',')) == NULL)
		p = ep;
	len = p - sp;
	if (sp[0] != '/')
		goto err;
	if (len == 0 || len > sizeof(path) - 1)
		goto err;
	strncpy(path, sp, len);
	path[len] = 0;
	mnt_s.dst = strdup(path);
	if (mnt_s.dst[0] == '/' && mnt_s.dst[1] == 0)
		goto err;
	sp = p + 1;
	if (add) {
		mnt_s.op = ADD;
	} else {
		mnt_s.op = DEL;
		p = sp;
	}
	while (p < ep) {
		if ((p = strchr(sp, ',')) == NULL)
			p = ep;
		len = p - sp;
		if (len >= sizeof(buf))
			goto err;
		strncpy(buf, sp, len);
		buf[len] = 0;
		mntopt = get_mount_opt(buf);
		if (mntopt < 0)
			goto err;
		mnt_s.mntopt |= mntopt;
		sp = ++p;
	}
	if (find_bindmount(mnt, mnt_s.dst) == NULL)
		add_bindmount(mnt, &mnt_s);
out:
	free_bindmount(&mnt_s);
	return ret;
err:
	ret = VZCTL_E_INVAL;
	goto out;
}

int parse_bindmount(struct vzctl_bindmount_param *mnt, const char *str, int add)
{
	int ret = 0;
	char *token, *tmp = NULL;
	char *savedptr = NULL;

	ret = xstrdup(&tmp, str);
	if (ret)
		return ret;

	if ((token = strtok_r(tmp, "\t ", &savedptr)) != NULL) {
		do {
			if ((ret = parse_bindmount_str(mnt, token, add)))
				break;
		} while ((token = strtok_r(NULL, "\t ", &savedptr)));
	}
	free(tmp);

	return ret;
}

char *bindmount2str(struct vzctl_bindmount_param *old_mnt, struct vzctl_bindmount_param *mnt)
{
	char *buf;
	char flags[64];
	char *sp, *ep;
	struct vzctl_bindmount *mnt_t;
	struct vzctl_bindmount_param *merged;
	int len;

	if (mnt == NULL || (!mnt->delall && list_empty(&mnt->mounts)))
		return NULL;
	merged = alloc_bindmount_param();
	if (merged == NULL)
		return NULL;
	merge_bindmount(mnt->delall ? NULL : old_mnt, mnt, merged);

	len = 0;
	list_for_each(mnt_t, &merged->mounts, list) {
		len += (mnt_t->src ? strlen(mnt_t->src) : 0) +
			(mnt_t->dst ? strlen(mnt_t->dst) : 0) +
			sizeof(flags) + 3;
	}
	buf = malloc(len + 1);
	sp = buf;
	ep = buf + len;
	*sp = 0;
	list_for_each(mnt_t, &merged->mounts, list) {
		if (mnt_t->src == NULL) {
			sp += snprintf(sp, ep - sp, "%s", mnt_t->dst);
			if (sp >= ep)
				break;
		} else {
			sp += snprintf(sp, ep - sp, "%s:%s",
				mnt_t->src, mnt_t->dst);
			if (sp >= ep)
				break;
		}
		get_mount_optnames(mnt_t->mntopt, flags, sizeof(flags));
		sp += snprintf(sp, ep - sp, "%s ", flags);
		if (sp >= ep)
			break;
	}
	free_bindmount_param(merged);
	return buf;
}

static int bind_mount(struct vzctl_env_handle *h, struct vzctl_bindmount *mnt)
{
	char s[STR_SIZE];
	char d[PATH_MAX];
	struct stat st;
	int flags = mnt->mntopt;
	char *root = h->env_param->fs->ve_root;

	snprintf(d, sizeof(d), "%s/%s", root, mnt->dst);
	if (lstat(d, &st)) {
		if (errno != ENOENT)
			return vzctl_err(VZCTL_E_MOUNT, 0,
				"Unable to stat bindmount target %s", d);

		if (mkdir(d, 1))
			return vzctl_err(VZCTL_E_CREATE_DIR, errno,
				"Unable to create bindmount target %s", d);
		if (lstat(d, &st))
			return vzctl_err(VZCTL_E_MOUNT, 0,
				"Unable to stat bindmount target %s", d);

	}

	if (!S_ISDIR(st.st_mode))
		return vzctl_err(VZCTL_E_MOUNT, 0,
				"Unable to setup bindmount: the target"
				" is not a folder '%s'", d);

	if (mnt->src == NULL) {
		snprintf(s, sizeof(s), "%s/%s/%s",
				root, BINDMOUNT_DIR, mnt->dst);
		if (access(s, F_OK)) {
			if (stat(d, &st))
				st.st_mode = 0777;
			make_dir(s, 1);
			chmod(s, st.st_mode);
		}
	} else {
		snprintf(s, sizeof(s), "%s", mnt->src);
	}

	logger(0, 0, "Set up the bind mount: %s", s);

	if (mount(s, d, "", MS_BIND, NULL) < 0)
		return vzctl_err(VZCTL_E_MOUNT, errno,
			"Cannot bind-mount: %s %s", s, d);

	/* apply flags */
	if (flags && mount(s, d, "", flags | MS_REMOUNT | MS_BIND, NULL))
		return vzctl_err(VZCTL_E_MOUNT, errno,
				"Cannot bind-mount: %s %s", s, d);

	return 0;
}

int vzctl2_bind_mount(struct vzctl_env_handle *h,
		struct vzctl_bindmount_param *mnt, int flags)
{
	int ret;
	struct vzctl_bindmount *it;

	if (mnt == NULL || list_empty(&mnt->mounts))
		return 0;

	list_for_each(it, &mnt->mounts, list) {
		ret = bind_mount(h, it);
		if (ret)
			return ret;
	}

	return 0;
}
