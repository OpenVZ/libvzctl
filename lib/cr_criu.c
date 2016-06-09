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


#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/param.h>

#include "libvzctl.h"
#include "disk.h"
#include "list.h"
#include "cpt.h"
#include "cgroup.h"
#include "env.h"
#include "util.h"
#include "exec.h"
#include "vcmm.h"
#include "vzerror.h"
#include "logger.h"

static int create_ploop_dev_map(struct vzctl_env_handle *h, pid_t pid)
{
	int ret;
	char devname[STR_SIZE];
	char path[PATH_MAX];
	struct vzctl_disk *d;

	list_for_each(d, &h->env_param->disk->disks, list) {
		if (d->enabled == VZCTL_PARAM_OFF)
			continue;

		ret = vzctl2_get_ploop_dev(d->path, devname, sizeof(devname));
		if (ret)
			return ret;

		snprintf(path, sizeof(path), "/proc/%d/root/dev/%s",
				(int)pid, d->uuid);
		unlink(path);
		logger(5, 0, "create device map %s -> %s", d->uuid, devname);
		if (symlink(devname, path))
			return vzctl_err(VZCTL_E_SYSTEM, errno,
					"Failed to creaet symlink %s -> %s",
					path, devname);
	}

	return 0;
}

static int make_ploop_dev_args(struct vzctl_env_handle *h, char *out, int size)
{
	int ret;
	char *ep, *pbuf = out;
	char devname[STR_SIZE];
	struct vzctl_disk *d;
	struct stat st;
	dev_t dev;

	ep = pbuf + size;
	pbuf += snprintf(pbuf, size, "VE_PLOOP_DEVS=");
	list_for_each(d, &h->env_param->disk->disks, list) {
		if (d->enabled == VZCTL_PARAM_OFF)
			continue;

		dev = d->dev;
		if (dev == 0) {
			ret = vzctl2_get_ploop_dev(d->path, devname, sizeof(devname));
			if (ret)
				return ret;

			if (stat(devname, &st))
				return vzctl_err(VZCTL_E_SYSTEM, errno, "Can't stat %s",
						devname);
			dev = st.st_rdev;
		}

		pbuf += snprintf(pbuf, ep - pbuf, "%s@ploop%d:%d:%d:%s\n",
				d->uuid,
				gnu_dev_minor(dev) >> 4,
				gnu_dev_major(dev),
				gnu_dev_minor(dev),
				is_root_disk(d) ? "root" : "");
		if (pbuf > ep)
			return vzctl_err(VZCTL_E_INVAL, 0, "make_ploop_dev_args: buffer overflow");
	}

	return 0;
}

static int do_dump(struct vzctl_env_handle *h, int cmd,
		struct vzctl_cpt_param *param, struct start_param *data)
{
	char path[PATH_MAX];
	char buf[PATH_MAX];
	char script[PATH_MAX];
	char *arg[2];
	char *env[12] = {};
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

	if (cmd == VZCTL_CMD_DUMP) {
		if (data != NULL) {
			snprintf(buf, sizeof(buf), "STATUSFD=%d", data->status_p[1]);
			env[i++] = strdup(buf);
			snprintf(buf, sizeof(buf), "WAITFD=%d", h->ctx->wait_p[0]);
			env[i++] = strdup(buf);
		}

		snprintf(buf, sizeof(buf), "CRIU_EXTRA_ARGS=--leave-running");
		env[i++] = strdup(buf);
	}

	ret = make_ploop_dev_args(h, buf, sizeof(buf));
	if (ret)
		goto err;

	env[i++] = strdup(buf);

	snprintf(buf, sizeof(buf), "VEID=%s", h->ctid);
	env[i++] = strdup(buf);

	cg_get_cgroup_env_param(buf, sizeof(buf));
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

static int dump(struct vzctl_env_handle *h, int cmd,
		struct vzctl_cpt_param *param, struct start_param *data)
{
	return do_dump(h, cmd, param, data);
}

static int chkpnt(struct vzctl_env_handle *h, int cmd,
		struct vzctl_cpt_param *param)
{
	int ret;
	char buf[PATH_MAX];

	ret = do_dump(h, cmd, param, NULL);
	if (ret)
		return ret;

	vcmm_unregister(h);
	get_init_pid_path(EID(h), buf);
	unlink(buf);

	return 0;
}

static int restore(struct vzctl_env_handle *h, struct vzctl_cpt_param *param,
	struct start_param *data)
{
	char path[STR_SIZE];
	char script[PATH_MAX];
	char buf[PATH_MAX];
	char *arg[2];
	char *env[14] = {};
	struct vzctl_veth_dev *veth;
	int ret, i = 0;
	char *pbuf, *ep;

	get_dumpfile(h, param, path, sizeof(path));
	logger(3, 0, "Open the dump file %s", path);
	snprintf(buf, sizeof(buf), "VE_DUMP_DIR=%s", path);
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

	get_init_pid_path(h->ctid, path);
	snprintf(buf, sizeof(buf), "VE_PIDFILE=%s", path);
	env[i++] = strdup(buf);

	snprintf(buf, sizeof(buf), "VE_ROOT=%s", h->env_param->fs->ve_root);
	env[i++] = strdup(buf);
	snprintf(buf, sizeof(buf), "VZCTL_PID=%d", getpid());
	env[i++] = strdup(buf);
	if (data != NULL) {
		snprintf(buf, sizeof(buf), "STATUSFD=%d", data->status_p[1]);
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

	cg_get_cgroup_env_param(buf, sizeof(buf));
	env[i++] = strdup(buf);

	env[i] = NULL;

	arg[0] = get_script_path("vz-rst", script, sizeof(script));
	arg[1] = NULL;

	ret = vzctl2_wrap_exec_script(arg, env, 0);
	if (ret)
		ret = VZCTL_E_RESTORE;

err:
	free_ar_str(env);

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
		return dump(h, cmd, param, data);
	/* rst */
	case VZCTL_CMD_RESTORE:
		return restore(h, param, data);
	default:
		return vzctl_err(VZCTL_E_INVAL, 0,
			"Unsupported criu command %d", cmd);
	}
}
