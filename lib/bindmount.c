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
#include <sys/mount.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <mntent.h>
#include <fcntl.h>
#include <linux/fs.h>

#include "vzerror.h"
#include "util.h"
#include "logger.h"
#include "bindmount.h"
#include "exec.h"

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE	1
#endif

#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH	0x00000004
#endif

struct exec_bind_param {
	int fd;
	const char *src;
	const char *dst;
	int flags;
	int op;
};

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

int add_bindmount(struct vzctl_bindmount_param *mnt,
		struct vzctl_bindmount *data)
{
	int ret;
	struct vzctl_bindmount *p;

	p = calloc(1, sizeof(struct vzctl_bindmount));
	if (p == NULL)
		return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "add_bindmount");

	ret = xstrdup(&p->src, data->src);
	if (ret)
		goto err;
	ret = xstrdup(&p->dst, data->dst);
	if (ret) 
		goto err;

	p->op = data->op;
	p->mntopt = data->mntopt;
	list_add_tail(&p->list, &mnt->mounts);

	return 0;

err:
	free_bindmount(p);
	free(p);

	return ret;
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
	char *savedptr;

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

static int get_mount_flags(const char *dir, int *flags)
{
	FILE *fp;
	struct mntent *ent, mntbuf;
	char tmp[PATH_MAX];
	struct stat st;

	if (stat(dir, &st))
		return vzctl_err(-1, errno, "Cannot stat %s", dir);

	fp = fopen("/proc/mounts", "r");
	if (fp == NULL)
		return vzctl_err(-1, errno, "Cannot open /proc/mounts");

	while ((ent = getmntent_r(fp, &mntbuf, tmp, sizeof(tmp)))) {
		struct stat s;

		if (ent->mnt_opts == NULL)
			continue;
		if (stat(ent->mnt_dir, &s))
			continue;

		if (st.st_dev == s.st_dev) {
			if (hasmntopt(ent, "nodev"))
				*flags |= MS_NODEV;
			if (hasmntopt(ent, "nosuid"))
				*flags |= MS_NOSUID;
			if (hasmntopt(ent, "noexec"))
				*flags |= MS_NOEXEC;
			break;
		}
	}
	fclose(fp);

	return 0;
}

static int open_tree(int dirfd, const char *pathname, unsigned int flags) {
	return syscall(428, dirfd, pathname, flags);
}

static int move_mount(int from_dirfd, const char *from_pathname, int to_dirfd,
		const char *to_pathname, unsigned int flags) {
	return syscall(429, from_dirfd, from_pathname, to_dirfd, to_pathname, flags);
}

static int set_mount_flags(const char *mnt, int flags)
{
	if (flags && mount("", mnt, "", flags | MS_REMOUNT | MS_BIND, NULL))
                return vzctl_err(1, errno, "Cannot apply bind-mount flags: %s", mnt);
	return 0;
}

static int live_bind_mount(struct exec_bind_param *param)
{
	if (param->op == DEL) {
		if (umount2(param->dst, MNT_DETACH))
			return vzctl_err(VZCTL_E_UMOUNT, errno, "Can't umount %s", param->dst);
		return 0;
	}

	if (move_mount(param->fd, "", AT_FDCWD, param->dst, MOVE_MOUNT_F_EMPTY_PATH))
		return vzctl_err(1, errno, "Can't move_mount %s -> %s",\
				param->src, param->dst);

	if (set_mount_flags(param->dst, param->flags)) {
		umount(param->dst);
		return 1;
	}

	return 0;
}

static int do_live_bind_mount(struct vzctl_env_handle *h, const char *src,
		const char *dst, int op, int flags)
{
	int ret = VZCTL_E_MOUNT;
	char path[64];
	struct exec_bind_param param = {
		.fd = -1,
		.src = src,
		.dst = dst,
		.flags = flags,
		.op = op,
	};

	if (op == DEL)
		return vzctl_env_exec_fn(h, (execFn) live_bind_mount, &param, 0);

	param.fd = open_tree(AT_FDCWD, src, OPEN_TREE_CLONE);
	if (param.fd == -1)
		return vzctl_err(VZCTL_E_MOUNT, errno, "open_tree(%s)", src);

	snprintf(path, sizeof(path), "/proc/self/fd/%d", param.fd);
	if (mount(NULL, path, NULL, MS_PRIVATE, NULL)) {
		vzctl_err(VZCTL_E_MOUNT, errno,
				"Cannot remount bind mount %s as private", dst);
		goto err;
	}

	if (vzctl_env_exec_fn(h, (execFn) live_bind_mount, &param, 0))
		goto err;
	ret = 0;

err:
	close(param.fd);

	return ret;
}

static int do_bind_mount(const char *src, const char *dst, int flags)
{
	if (mount(src, dst, "", MS_BIND, NULL) < 0)
		return vzctl_err(VZCTL_E_MOUNT, errno,
			"Cannot bind-mount: %s %s", src, dst);

	if (mount(NULL, dst, NULL, MS_PRIVATE | MS_REC, NULL) < 0)
		return vzctl_err(VZCTL_E_MOUNT, errno,
			"Cannot remount bind mount %s as private", dst);

	if (set_mount_flags(dst, flags)) {
		umount(dst);
		return VZCTL_E_MOUNT;
	}

	return 0;
}

static int bind_mount(struct vzctl_env_handle *h, struct vzctl_bindmount *mnt, int live)
{
	char s[STR_SIZE];
	char d[PATH_MAX];
	struct stat st;
	int flags = mnt->mntopt;
	char *root = h->env_param->fs->ve_root;

	snprintf(d, sizeof(d), "%s/%s", root, mnt->dst);
	if (mnt->op == DEL)
		goto set;

	if (lstat(d, &st)) {
		if (errno != ENOENT)
			return vzctl_err(VZCTL_E_MOUNT, 0,
				"Unable to stat bindmount target %s", d);

		if (make_dir(d, 1))
			return vzctl_err(VZCTL_E_CREATE_DIR, errno,
				"Unable to create bindmount target %s", d);
	} else if (!S_ISDIR(st.st_mode))
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
		if (flags && get_mount_flags(mnt->src, &flags))
			return VZCTL_E_MOUNT;
	}

set:
	if (mnt->op == ADD)
		logger(0, 0, "Set up the bind mount: %s at %s", s, d);
	else
		logger(0, 0, "Unmount %s", d);
	if (live)
		return do_live_bind_mount(h, s, mnt->dst, mnt->op, flags);

	return do_bind_mount(s, d, flags);
}

int vzctl2_bind_mount(struct vzctl_env_handle *h,
		struct vzctl_bindmount_param *mnt, int live)
{
	int ret;
	struct vzctl_bindmount *it;

	if (mnt == NULL || list_empty(&mnt->mounts))
		return 0;

	list_for_each(it, &mnt->mounts, list) {
		ret = bind_mount(h, it, live);
		if (ret)
			return ret;
	}

	return 0;
}
