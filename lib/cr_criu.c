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
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/param.h>
#include <sys/sysmacros.h>

#include "libvzctl.h"
#include "disk.h"
#include "list.h"
#include "cgroup.h"
#include "env.h"
#include "util.h"
#include "exec.h"
#ifdef USE_VCMMD
#include "vcmm.h"
#endif
#include "vzerror.h"
#include "logger.h"
#include "disk.h"

static int create_ploop_dev_map(struct vzctl_env_handle *h, pid_t pid)
{
	int ret;
	char path[PATH_MAX];
	struct vzctl_disk *d;

	list_for_each(d, &h->env_param->disk->disks, list) {
		const char *partname;

		if (d->enabled == VZCTL_PARAM_OFF)
			continue;

		if (d->dev == 0) {
			ret = update_disk_info(h, d);
			if (ret)
				return ret;
		}
		
		snprintf(path, sizeof(path), "/proc/%d/root/dev/%s",
				(int)pid, d->uuid);
		unlink(path);

		partname = get_fs_partname(d);
		logger(5, 0, "create device map %s -> %s", d->uuid, partname);
		if (symlink(partname, path))
			return vzctl_err(VZCTL_E_SYSTEM, errno,
					"Failed to create symlink %s -> %s",
					path, partname);
	}

	return 0;
}

static int make_ext_mount_args(struct vzctl_env_handle *h, int cpt, char *out,
		int size)
{
	char *ep, *pbuf = out;
	struct vzctl_bindmount *it;
	struct vzctl_bindmount_param *mnt = h->env_param->bindmount;

	ep = pbuf + size;
	pbuf += snprintf(pbuf, size, "VE_EXT_MOUNT_MAP=");
	list_for_each(it, &mnt->mounts, list) {
		if (it->src == NULL)
			continue;

		if (cpt)
			pbuf += snprintf(pbuf, ep - pbuf, "%s:%s\n",
					it->dst, it->src);
		else
			pbuf += snprintf(pbuf, ep - pbuf, "%s:%s\n",
					it->src, it->src);
		if (pbuf > ep)
			return vzctl_err(VZCTL_E_INVAL, 0,
					"make_ext_map: buffer overflow");
	}

	return 0;
}

static int make_ploop_dev_args(struct vzctl_env_handle *h, char *out, int size)
{
	char *ep, *pbuf = out;
	struct vzctl_disk *d;

	ep = pbuf + size;
	pbuf += snprintf(pbuf, size, "VE_PLOOP_DEVS=");
	list_for_each(d, &h->env_param->disk->disks, list) {
		dev_t part_dev = get_fs_partdev(d);

		if (d->enabled == VZCTL_PARAM_OFF)
			continue;

		pbuf += snprintf(pbuf, ep - pbuf, "%s@%s:%d:%d:%s\n",
				d->uuid,
				get_fs_partname(d),
				gnu_dev_major(part_dev),
				gnu_dev_minor(part_dev),
				is_root_disk(d) ? "root" : "");
		if (pbuf > ep)
			return vzctl_err(VZCTL_E_INVAL, 0, "make_ploop_dev_args: buffer overflow");
	}

	return 0;
}

static int dump(struct vzctl_env_handle *h, int cmd,
		struct vzctl_cpt_param *param)
{
	char path[PATH_MAX];
	char buf[PATH_MAX + 15];
	char script[PATH_MAX];
	char *arg[2];
	char *env[13] = {};
	int ret, i = 0;
	pid_t pid;

	ret = cg_env_get_init_pid(EID(h), &pid);
	if (ret)
		return ret;

	ret = create_ploop_dev_map(h, pid);
	if (ret)
		return ret;

	get_dumpfile(h, param, path, sizeof(path));
	logger(2, 0, "Store dump at %s", path);

	snprintf(buf, sizeof(buf), "VE_DUMP_DIR=%s", path);
	env[i++] = strdup(buf);
	snprintf(buf, sizeof(buf), "VE_ROOT=%s", h->env_param->fs->ve_root);
	env[i++] = strdup(buf);
	snprintf(buf, sizeof(buf), "VE_PID=%d", pid);
	env[i++] = strdup(buf);
	snprintf(buf, sizeof(buf), "CRIU_LOGLEVEL=%d",
		vzctl2_get_log_verbose() + 1);
	env[i++] = strdup(buf);

	cg_get_path(EID(h), CG_FREEZER, "", path, sizeof(path));
	snprintf(buf, sizeof(buf), "VE_FREEZE_CG=%s", path);
	env[i++] = strdup(buf);

	if (cmd == VZCTL_CMD_DUMP_LEAVE_FROZEN) {
		if (h->ctx->status_p[1] == -1 || h->ctx->wait_p[0] == -1)
			return vzctl_err(VZCTL_E_INVAL, 0,
					"dump: pipe ctx not initialized status[%d] wait[%d]", h->ctx->status_p[1], h->ctx->wait_p[0]);

		snprintf(buf, sizeof(buf), "STATUSFD=%d", h->ctx->status_p[1]);
		env[i++] = strdup(buf);
		snprintf(buf, sizeof(buf), "WAITFD=%d", h->ctx->wait_p[0]);
		env[i++] = strdup(buf);
	}

	if (cmd == VZCTL_CMD_DUMP_LEAVE_FROZEN || cmd == VZCTL_CMD_DUMP) {
		snprintf(buf, sizeof(buf), "CRIU_EXTRA_ARGS=--leave-running");
		env[i++] = strdup(buf);
	}

	ret = make_ploop_dev_args(h, buf, sizeof(buf));
	if (ret)
		goto err;

	env[i++] = strdup(buf);

	snprintf(buf, sizeof(buf), "VEID=%s", h->ctid);
	env[i++] = strdup(buf);

	cg_get_cgroup_env_param(NULL, buf, sizeof(buf));
	env[i++] = strdup(buf);

	ret = make_ext_mount_args(h, 1, buf, sizeof(buf));
	if (ret)
		goto err;
	env[i++] = strdup(buf);

	env[i] = NULL;

	arg[0] = get_script_path("vz-cpt", script, sizeof(script));
	arg[1] = NULL;

	ret = vzctl2_wrap_exec_script(arg, env, 0);
	if (ret)
		ret = VZCTL_E_CHKPNT;

err:
	free_ar_str(env);

	return ret;
}

static int chkpnt(struct vzctl_env_handle *h, int cmd,
		struct vzctl_cpt_param *param)
{
	int ret;

	ret = dump(h, cmd, param);
	if (ret)
		return ret;
#ifdef USE_VCMMD
	vcmm_unregister(h);
#endif
	clear_init_pid(h->ctid);

	return 0;
}

static int restore_ini(struct vzctl_env_handle *h,
		struct vzctl_cpt_param *param, char **dump, char **work,
		char **log)
{
	int ret = 0;
	const char *p;
	struct vzctl_config *f;
	char s[PATH_MAX];

	get_dumpfile(h, param, s, sizeof(s));
	ret = xstrdup(dump, s);
	if (ret)
		return ret;
	ret = xstrdup(work, s);
	if (ret)
		return ret;
	ret = xstrdup(log, "restore.log");
	if (ret)
		return ret;

	snprintf(s, sizeof(s), "%s/restore-extra-args", *dump);
	if (access(s, F_OK))
		return 0;

	f = vzctl2_conf_open(s, VZCTL_CONF_SKIP_GLOBAL, &ret);
	if (ret)
		return ret;

	if (vzctl2_conf_get_param(f, "VE_WORK_DIR", &p) == 0) {
		ret = xstrdup(work, p);
		if (ret)
			goto err;
	}

	if (vzctl2_conf_get_param(f, "VE_RESTORE_LOG_PATH", &p) == 0) {
		ret = xstrdup(log, p);
		if (ret)
			goto err;
	}
err:
	vzctl2_conf_close(f);

	return ret;
}

static void restore_fin(const char *dumpdir, const char *workdir,
		const char *logfile, int rc)
{
	char s[PATH_MAX];
	char d[PATH_MAX];
	char *f[] = {"spfs-manager", "dump.log", "restore.log", NULL};
	char **p;

	if (rc)	{
		char *arg[] = {"/bin/grep", " Error ", s, NULL};

		snprintf(s, sizeof(s), "%s/%s", workdir, logfile);
		if (access(s, F_OK) == 0)
			vzctl2_exec_script(arg, NULL, 0);
		vzctl_err(-1, 0, "The restore log was saved in %s", s);
		return;
	}

	snprintf(d, sizeof(d), "%s.restore", dumpdir);
	if (make_dir(d, 1))
		return;

	for (p = f; *p != NULL; p++) {
		snprintf(s, sizeof(s), "%s/%s", dumpdir, *p);
		snprintf(d, sizeof(d), "%s.restore/%s", dumpdir, *p);
		rename(s, d);
	}

	logger(0, 0, "The log of successful restore was saved in %s", d);
}

static int restore(struct vzctl_env_handle *h, struct vzctl_cpt_param *param,
	struct start_param *data)
{
	char *dumpdir = NULL;
	char *workdir = NULL;
	char *logfile = NULL;
	char path[PATH_MAX];
	char script[PATH_MAX];
	char buf[PATH_MAX + 14];
	char *arg[2];
	char *env[20] = {};
	struct vzctl_veth_dev *veth;
	int ret, i = 0;
	char *pbuf, *ep, *s;

	ret = restore_ini(h, param, &dumpdir, &workdir, &logfile);
	if (ret)
		return ret;

	logger(3, 0, "Open the dump file %s", dumpdir);
	snprintf(buf, sizeof(buf), "VE_DUMP_DIR=%s", dumpdir);
	env[i++] = strdup(buf);
	snprintf(buf, sizeof(buf), "VE_WORK_DIR=%s", workdir);
	env[i++] = strdup(buf);
	snprintf(buf, sizeof(buf), "VE_RESTORE_LOG_PATH=%s", logfile);
	env[i++] = strdup(buf);
	/*
	   -v1, -v only messages and errors;
	   -v2, -vv also warnings (default level);
	   -v3, -vvv also information messages and timestamps;
	   -v4, -vvvv lots of debug.*
	*/
	snprintf(buf, sizeof(buf), "CRIU_LOGLEVEL=%d",
		vzctl2_get_log_verbose() + 1);
	env[i++] = strdup(buf);

	s = getenv("CRIU_ACTION_POST_RESUME_READ_FD");
	if (s != NULL) {
		snprintf(buf, sizeof(buf), "CRIU_ACTION_POST_RESUME_READ_FD=%s", s);
		env[i++] = strdup(buf);
	}

	s = getenv("CRIU_ACTION_POST_RESUME_WRITE_FD");
	if (s != NULL) {
		snprintf(buf, sizeof(buf), "CRIU_ACTION_POST_RESUME_WRITE_FD=%s", s);
		env[i++] = strdup(buf);
	}

	snprintf(buf, sizeof(buf), "VE_INIT_PIDFILE=%s",
			get_init_pidfile(h->ctid, path));
	env[i++] = strdup(buf);
	snprintf(buf, sizeof(buf), "VE_CRIU_PIDFILE=%s",
			get_criu_pidfile(h->ctid, path));
	env[i++] = strdup(buf);
	snprintf(buf, sizeof(buf), "VE_ROOT=%s", h->env_param->fs->ve_root);
	env[i++] = strdup(buf);
	snprintf(buf, sizeof(buf), "VZCTL_PID=%d", getpid());
	env[i++] = strdup(buf);
	if (data != NULL) {
		snprintf(buf, sizeof(buf), "STATUSFD=%d", h->ctx->status_p[1]);
		env[i++] = strdup(buf);
		snprintf(buf, sizeof(buf), "WAITFD=%d", h->ctx->wait_p[0]);
		env[i++] = strdup(buf);
	}
	get_netns_path(h, path, sizeof(path));
	snprintf(buf, sizeof(buf), "VE_NETNS_FILE=%s", path);
	env[i++] = strdup(buf);

	snprintf(buf, sizeof(buf), "VEID=%s", h->ctid);
	env[i++] = strdup(buf);

	pbuf = buf;
	ep = buf + sizeof(buf);
	pbuf += snprintf(buf, sizeof(buf), "VE_VETH_DEVS=");
	list_for_each(veth, &h->env_param->veth->dev_list, list) {
		pbuf += snprintf(pbuf, ep - pbuf,
				"%s=%s\n", veth->dev_name_ve, veth->dev_name);
		if (pbuf > ep) {
			env[i] = NULL;
			free_ar_str(env);
			return vzctl_err(VZCTL_E_INVAL, 0, "restore: buffer overflow");
		}
	}
	env[i++] = strdup(buf);

	ret = make_ploop_dev_args(h, buf, sizeof(buf));
	if (ret)
		goto err;
	logger(10, 0, "* %s", buf);
	env[i++] = strdup(buf);

	ret = make_ext_mount_args(h, 0, buf, sizeof(buf));
	if (ret)
		goto err;
	env[i++] = strdup(buf);

	cg_get_cgroup_env_param(EID(h), buf, sizeof(buf));
	env[i++] = strdup(buf);

	env[i] = NULL;

	arg[0] = get_script_path("vz-rst", script, sizeof(script));
	arg[1] = NULL;

	if (vzctl2_wrap_exec_script(arg, env, 0)) {
		unlink(get_criu_pidfile(h->ctid, path));
		ret = VZCTL_E_RESTORE;
	}

	restore_fin(dumpdir, workdir, logfile, ret);
err:
	free_ar_str(env);
	free(dumpdir);
	free(workdir);
	free(logfile);

	return ret;
}

int criu_cmd(struct vzctl_env_handle *h, int cmd,
		struct vzctl_cpt_param *param, struct start_param *data)
{
	switch (cmd) {
	/* cpt */
	case VZCTL_CMD_CHKPNT:
		if (param->flags & VZCTL_CPT_CREATE_DEVMAP) {
			int ret;
			pid_t pid;

			ret = cg_env_get_init_pid(EID(h), &pid);
			if (ret)
				return ret;

			return create_ploop_dev_map(h, pid);
		}
		return chkpnt(h, cmd, param);
	case VZCTL_CMD_DUMP:
		logger(0, 0, "\tdump");
		return dump(h, cmd, param);
	case VZCTL_CMD_DUMP_LEAVE_FROZEN:
		logger(0, 0, "\tdump leave frozen");
		return dump(h, cmd, param);
	/* rst */
	case VZCTL_CMD_RESTORE:
		return restore(h, param, data);
	default:
		return vzctl_err(VZCTL_E_INVAL, 0,
			"Unsupported criu command %d", cmd);
	}
}
