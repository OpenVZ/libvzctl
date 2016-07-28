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
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/cpt_ioctl.h>
#include <linux/vzcalluser.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <unistd.h>
#include <dirent.h>

#include "vzctl.h"
#include "cpt.h"
#include "env.h"
#include "fs.h"
#include "exec.h"
#include "config.h"
#include "vzerror.h"
#include "logger.h"
#include "util.h"
#include "vz.h"
#include "lock.h"
#include "net.h"
#include "env_configure.h"
#include "env_ops.h"
#include "cpt.h"

/* with mix of md5sum: try generate unique name */
#define CPT_HARDLINK_DIR ".cpt_hardlink_dir_a920e4ddc233afddc9fb53d26c392319"

void clean_hardlink_dir(const char *mntdir)
{
	char buf[MAXPATHLEN];
	struct dirent *ep;
	DIR *dp;

	if (mntdir == NULL)
		return;

	snprintf(buf, sizeof(buf), "%s/%s", mntdir, CPT_HARDLINK_DIR);

	unlink(buf);    /* if file was created by someone */
	if (!(dp = opendir(buf)))
		return;
	while ((ep = readdir(dp))) {
		if (!strcmp(ep->d_name, ".") || !strcmp(ep->d_name, ".."))
			continue;

		snprintf(buf, sizeof(buf), "%s/%s/%s", mntdir, CPT_HARDLINK_DIR, ep->d_name);
		unlink(buf);
	}
	closedir(dp);

	snprintf(buf, sizeof(buf), "%s/%s", mntdir, CPT_HARDLINK_DIR);
	rmdir(buf);
}

static int setup_hardlink_dir(const char *mntdir, int cpt_fd)
{
	char buf[MAXPATHLEN];
	int fd, res = 0;

	snprintf(buf, sizeof(buf), "%s/%s", mntdir, CPT_HARDLINK_DIR);
	if (mkdir(buf, 0711) && errno != EEXIST)
		return vzctl_err(VZCTL_E_SYSTEM, errno,
				"Unable to create the hardlink directory %s",
				buf);

	fd = open(buf, O_RDONLY | O_NOFOLLOW | O_DIRECTORY);
	if (fd < 0)
		return vzctl_err(VZCTL_E_SYSTEM, errno,
				"Error: Unable open hardlink directory %s",
				buf);

	if (ioctl(cpt_fd, CPT_LINKDIR_ADD, fd) < 0) {
		if (errno != EINVAL)
			res = vzctl_err(VZCTL_E_SYSTEM, errno,
					"Cannot set linkdir in kernel");
		rmdir(buf);
	}

	close(fd);
	return res;
}

int vz_env_cpt_cmd(struct vzctl_env_handle *h, int action, int cmd,
		struct vzctl_cpt_param *param, int flags)
{
	int fd;
	int err, ret = 0;
	const char *file;
	unsigned veid = h->veid;

	if (!is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_NOT_RUN, 0, "Container is not running");
	if (action == VZCTL_CMD_CHKPNT) {
		file = PROC_CPT;
		err = VZCTL_E_CHKPNT;
	} else if (action == VZCTL_CMD_RESTORE) {
		file = PROC_RST;
		err = VZCTL_E_RESTORE;
	} else {
		return vzctl_err(VZCTL_E_INVAL, 0,
				"cpt_cmd: Unsupported command");
	}
	if ((fd = open(file, O_RDWR)) < 0) {
		if (errno == ENOENT)
			logger(-1, errno, "Error: No checkpointing"
				" support is available: unable to open %s", file);
		else
			logger(-1, errno, "Unable to open %s", file);
		return err;
	}
	if ((ret = ioctl(fd, CPT_JOIN_CONTEXT, param->ctx ? : veid)) < 0) {
		logger(-1, errno, "Cannot join the checkpoint context %d",
				param->ctx ? : veid);
		goto err;
	}
	switch (cmd) {
	case VZCTL_CMD_KILL:
		logger(0, 0, "Killing the Container...");
		if ((ret = ioctl(fd, CPT_KILL, 0)) < 0) {
			logger(-1, errno, "Cannot kill the Container");
			goto err;
		}
		if (action == VZCTL_CMD_RESTORE)
			/* remove .running file only for 'resume' command #PSBM-19081 */
			vzctl2_unregister_running_state(h->env_param->fs->ve_private);
		break;
	case VZCTL_CMD_RESUME:
		clean_hardlink_dir(h->env_param->fs->ve_root);
		logger(0, 0, "Resuming the Container...");
		if ((ret = ioctl(fd, CPT_RESUME, 0)) < 0) {
			logger(-1, errno, "Cannot resume the Container");
			goto err;
		}
		if (action == VZCTL_CMD_CHKPNT) {
			/* restore arp/routing cleared on dump stage */
			run_net_script(h, VZCTL_NET_ADD, &h->env_param->net->ip,
					flags);
		}
		vzctl2_register_running_state(h->env_param->fs->ve_private);
		break;
	}
	if (!param->ctx) {
		logger(2, 0, "\tput context");
		if ((ret = ioctl(fd, CPT_PUT_CONTEXT, 0)) < 0) {
			logger(-1, errno, "Cannot put context");
			goto err;
		}
	}
err:
	close(fd);
	return ret ? err : 0;
}

int vzctl2_cpt_cmd(struct vzctl_env_handle *h, int action, int cmd,
		struct vzctl_cpt_param *param, int flags)
{
	return get_env_ops()->env_cpt_cmd(h, action, cmd, param, flags);
}

static int real_chkpnt(struct vzctl_env_handle *h, int cpt_fd, int cmd,
	struct vzctl_cpt_param *param)
{
	int ret, len;
	char buf[PIPE_BUF];
	int err_p[2];
	unsigned veid = h->veid;

	if ((ret = vzctl_chroot(h->env_param->fs->ve_root)))
		return ret;
	if (pipe(err_p) < 0)
		return vzctl_err(VZCTL_E_PIPE, errno, "Unable to create pipe");
	fcntl(err_p[0], F_SETFL, O_NONBLOCK);
	fcntl(err_p[1], F_SETFL, O_NONBLOCK);
	if (ioctl(cpt_fd, CPT_SET_ERRORFD, err_p[1]) < 0)
		return vzctl_err(VZCTL_E_CHKPNT,  errno, "Can't set errorfd");

	close(err_p[1]);
	if (cmd == VZCTL_CMD_CHKPNT || cmd == VZCTL_CMD_FREEZE) {
		logger(0, 0, "\tsuspend...");
		if (ioctl(cpt_fd, CPT_SUSPEND, 0) < 0) {
			logger(-1, errno, "Cannot suspend the Container");
			goto err_out;
		}
		if (cmd == VZCTL_CMD_FREEZE && (param->flags & VZCTL_CPT_STOP_TRACKER)) {
			logger(0, 0, "\tstop tracker...");
			if (ioctl(cpt_fd, CPT_STOP_TRACKER, 0) < 0) {
				logger(-1, errno, "CPT_STOP_TRACKER");
				goto err_out;
			}
		}
	}

	if (cmd == VZCTL_CMD_CHKPNT || cmd == VZCTL_CMD_DUMP) {
		logger(0, 0, "\tdump...");
		clean_hardlink_dir("/");
		if (setup_hardlink_dir("/", cpt_fd))
			goto err_out;

		if (ioctl(cpt_fd, CPT_DUMP, 0) < 0) {
			logger(-1, errno, "Cannot dump the Container");
			if (cmd == VZCTL_CMD_CHKPNT) {
				clean_hardlink_dir("/");
				if (ioctl(cpt_fd, CPT_RESUME, 0) < 0)
					logger(-1, errno, "Cannot resume the Container");
			}
			goto err_out;
		}
	}
	if (cmd == VZCTL_CMD_CHKPNT) {
		logger(0, 0, "\tkill...");
		if (ioctl(cpt_fd, CPT_KILL, 0) < 0) {
			logger(-1, errno, "Cannot kill the Container");
			goto err_out;
		}
	}
	if (cmd == VZCTL_CMD_FREEZE && !param->ctx) {
		logger(0, 0, "\tget context...");
		if (ioctl(cpt_fd, CPT_GET_CONTEXT, veid) < 0) {
			logger(-1, errno, "Cannot get context");
			goto err_out;
		}
	}
	close(err_p[0]);

	return 0;
err_out:
	while ((len = read(err_p[0], buf, PIPE_BUF)) > 0) {
		buf[len - 1] = '\0';
		logger(-1, 0, "%s", buf);
	}
	close(err_p[0]);

	if (cmd == VZCTL_CMD_FREEZE && param->ctx) {
		/* destroy context */
		if (ioctl(cpt_fd, CPT_PUT_CONTEXT, veid) < 0)
			logger(-1, errno, "Cannot put the context");
	}
	return VZCTL_E_CHKPNT;
}

void get_dumpfile(struct vzctl_env_handle *h, struct vzctl_cpt_param *param,
		char *dumpfile, int size)
{
	if (param->dumpfile != NULL)
		snprintf(dumpfile, size, "%s", param->dumpfile);
	else
		vzctl2_get_dump_file(h,	dumpfile, size);
}

static int unfreeze_on_dump(int cpt_fd, const char *ve_root, int ctx, int ret)
{
	if (ret) {
		logger(0, 0, "Resuming the Container...");
		clean_hardlink_dir(ve_root);
		if (ioctl(cpt_fd, CPT_RESUME, 0) < 0) {
			logger(-1, errno, "Can not resume the Container");
			return -1;
		}
	} else {
		logger(0, 0, "Killing the Container...");
		if (ioctl(cpt_fd, CPT_KILL, 0) < 0) {
			logger(-1, errno, "Cannot kill the Container");
			return -1;
		}
	}
	if (!ctx) {
		if (ioctl(cpt_fd, CPT_PUT_CONTEXT, 0) < 0) {
			logger(-1, errno, "Can not put the context");
			return -1;
		}
	}
	return 0;
}

int vz_env_chkpnt(struct vzctl_env_handle *h, int cmd, struct vzctl_cpt_param *param, int flags)
{
	int dump_fd = -1;
	char dumpfile[PATH_LEN] = "";
	int cpt_fd, pid, ret;
	int lfd = -1;
	const char *root = h->env_param->fs->ve_root;
	unsigned veid = h->veid;
	LIST_HEAD(ip);

	ret = VZCTL_E_CHKPNT;
	logger(0, 0, "Setting up checkpoint...");
	if ((cpt_fd = open(PROC_CPT, O_RDWR)) < 0) {
		if (errno == ENOENT)
			return vzctl_err(VZCTL_E_CHKPNT, errno, "Error: No checkpointing"
				" support, unable to open " PROC_CPT);
		return vzctl_err(VZCTL_E_CHKPNT, errno, "Unable to open " PROC_CPT);
	}
	if (cmd == VZCTL_CMD_CHKPNT || cmd == VZCTL_CMD_DUMP) {
		/* Get IP list for further destroy */
		vzctl_get_env_ip(h, &ip);

		get_dumpfile(h, param, dumpfile, sizeof(dumpfile));
		logger(2, 0, "Store the dump at %s", dumpfile);
		make_dir(dumpfile, 0);
		unlink(dumpfile);
		dump_fd = open(dumpfile, O_CREAT|O_TRUNC|O_RDWR, 0600);
		if (dump_fd < 0) {
			logger(-1, errno, "Can not create dump file %s",
					dumpfile);
			goto err;
		}
		if ((param->flags & VZCTL_CPT_KEEP_PAGES) &&
				param->dumpfile != NULL)
		{
			char dumplink[MAXPATHLEN];
			/* create symlink from standard dump place */
			vzctl2_get_dump_file(h,	dumplink, sizeof(dumplink));
			unlink(dumplink);
			make_dir(dumplink, 0);
			if (symlink(param->dumpfile, dumplink)) {
				logger(-1, errno, "Failed to create symlink '%s' -> '%s'",
						dumplink, param->dumpfile);
				goto err;
			}
		}
	}
	if (cmd == VZCTL_CMD_CHKPNT || cmd == VZCTL_CMD_FREEZE) {
		/* Deny to enter on SUSPEND stage */
		lfd = get_enter_lock(h);
		if (lfd < 0)
			goto err;
	}
	if (param->ctx || cmd > VZCTL_CMD_FREEZE) {
		logger(0, 0, "\tjoin context..");
		if (ioctl(cpt_fd, CPT_JOIN_CONTEXT, param->ctx ? : veid) < 0) {
			logger(-1, errno, "Can not join the cpt context");
			goto err;
		}
	} else {
		if (ioctl(cpt_fd, CPT_SET_VEID, veid) < 0) {
			logger(-1, errno, "Can not set the veid");
			goto err;
		}

	}
	if (dump_fd != -1) {
		if (ioctl(cpt_fd, CPT_SET_DUMPFD, dump_fd) < 0) {
			logger(-1, errno, "Can not set dump file");
			goto err;
		}
	}
	if (param->cpu_flags) {
		logger(0, 0, "\tset cpu flags..");
		if (ioctl(cpt_fd, CPT_SET_CPU_FLAGS, param->cpu_flags) < 0) {
			logger(-1, errno, "Can not set the CPU flags: %x",
					param->cpu_flags);
			goto err;
		}
	}
	if ((param->flags & VZCTL_CPT_KEEP_PAGES) &&
			(cmd == VZCTL_CMD_CHKPNT || cmd == VZCTL_CMD_DUMP))
	{
		logger(0, 0, "\tset cpt pram..");
		if (ioctl(cpt_fd, CPT_SET_PRAM, 1) < 0) {
			logger(-1, errno, "Can not set the CPT_SET_PRAM");
			goto err;
		}
	}
	if ((pid = fork()) < 0) {
		ret = vzctl_err(VZCTL_E_FORK, errno, "Cannot fork");
		goto err;
	} else if (pid == 0) {
		if ((ret = vzctl_setluid(h)))
			_exit(ret);
		if ((pid = fork()) < 0) {
			_exit(VZCTL_E_FORK);
		} else if (pid == 0) {
			ret = real_chkpnt(h, cpt_fd, cmd, param);
			_exit(ret);
		}
		ret = env_wait(pid, 0, NULL);
		_exit(ret);
	}
	if (env_wait(pid, 0, NULL))
		goto err;


	if (!list_empty(&ip)) {
		/* Clear Container network configuration */
		run_net_script(h, VZCTL_NET_DEL, &ip, flags);
	}

	ret = 0;
err:
	if (cmd == VZCTL_CMD_DUMP &&
			(param->flags & VZCTL_CPT_UNFREEZE_ON_DUMP))
		unfreeze_on_dump(cpt_fd, root, param->ctx, ret);

	if (dump_fd != -1) {
		if (ret == 0)
			fsync(dump_fd);
		close(dump_fd);
	}
	if (dumpfile[0] != '\0' && ret)
		unlink(dumpfile);
	if (cpt_fd != -1)
		close(cpt_fd);
	release_enter_lock(lfd);

	free_ip(&ip);

	if (ret == 0) {
		if (cmd == VZCTL_CMD_CHKPNT)
			vzctl2_env_umount(h, 0);
		logger(0, 0, "Checkpointing completed succesfully");
	} else {
		ret = vzctl_err(VZCTL_E_CHKPNT, 0, "Failed to checkpoint the Container");
	}

	return ret;
}

static int restore_FN(struct vzctl_env_handle *h, struct start_param *param)
{
	int status, len;
	struct vzctl_cpt_param *cpt_param = (struct vzctl_cpt_param *) param->data;
	char buf[PIPE_BUF];
	int error_pipe[2] = {-1, -1};
	unsigned veid = h->veid;

	status = VZCTL_E_RESTORE;

	/* Close all fds */
	close_fds(VZCTL_CLOSE_NOCHECK, param->h->ctx->wait_p[0], param->h->ctx->err_p[1], param->status_p[1],
			get_vzctlfd(), cpt_param->rst_fd, vzctl2_get_log_fd(), -1);

	if (ioctl(cpt_param->rst_fd, CPT_SET_VEID, veid) < 0) {
		logger(-1, errno, "Can't set VEID %d", cpt_param->rst_fd);
		goto err;
	}
	if (pipe(error_pipe) < 0 ) {
		logger(-1, errno, "Can't create pipe");
		goto err;
	}
	fcntl(error_pipe[0], F_SETFL, O_NONBLOCK);
	fcntl(error_pipe[1], F_SETFL, O_NONBLOCK);
	if (ioctl(cpt_param->rst_fd, CPT_SET_ERRORFD, error_pipe[1]) < 0) {
		logger(-1, errno, "Can't set errorfd");
		goto err;
	}

	close(error_pipe[1]); error_pipe[1] = -1;
	if (ioctl(cpt_param->rst_fd, CPT_SET_LOCKFD2, param->h->ctx->wait_p[0]) < 0) {
		logger(-1, errno, "Can't set lockfd");
		goto err;
	}
	close(param->h->ctx->wait_p[0]); param->h->ctx->wait_p[0] = -1;
	if (ioctl(cpt_param->rst_fd, CPT_SET_STATUSFD, param->status_p[1]) < 0) {
		logger(-1, errno, "Can't set statusfd");
		goto err;
	}

	close(param->status_p[1]); param->status_p[1] = -1;

	ioctl(cpt_param->rst_fd, CPT_HARDLNK_ON);

	logger(0, 0, "\tundump...");
	if (ioctl(cpt_param->rst_fd, CPT_UNDUMP, 0) < 0) {
		logger(-1, errno, "Error: undump failed");
		goto err_undump;
	}

	if (!cpt_param->ctx) {
		logger(0, 0, "\tget context...");
		if (ioctl(cpt_param->rst_fd, CPT_GET_CONTEXT, veid) < 0) {
			logger(-1, 0, "Can not get context");
			goto err_undump;
		}
	}

	logger(10, 0, "* Undump done");
	status = 0;
err:
	if (error_pipe[0] != -1)
		close(error_pipe[0]);
	if (error_pipe[1] != -1)
		close(error_pipe[1]);

	if (write(param->h->ctx->err_p[1], &status, sizeof(status)) == -1)
		logger(-1, errno, "Failed to write to error pipe (restore_FN)");
	return status;

err_undump:
	logger(-1, 0, "Restoring failed:");
	while ((len = read(error_pipe[0], buf, PIPE_BUF)) > 0) {
		buf[len - 1] = '\0';
		logger(-1, 0, "%s", buf);
	}

	if (error_pipe[0] != -1)
		close(error_pipe[0]);
	if (error_pipe[1] != -1)
		close(error_pipe[1]);

	if (write(param->h->ctx->err_p[1], &status, sizeof(status)) == -1)
		logger(-1, errno, "Failed to write to error pipe");
	return status;
}

static void preserve_dumpfile(const char *dumpfile)
{
	char tmp[PATH_MAX];

	if (stat_file(dumpfile) == 1) {
		snprintf(tmp, sizeof(tmp), "%s.fail", dumpfile);
		logger(-1, 0, "Copying the dump file to %s", tmp);
		unlink(tmp);
		if (link(dumpfile, tmp))
			logger(-1, errno, "Failed to link %s %s", dumpfile, tmp);
	}
}

int vz_env_restore(struct vzctl_env_handle *h, struct start_param *start_param,
		struct vzctl_cpt_param *param, int flags)
{
	int ret, rst_fd;
	int dump_fd = -1;
	char dumpfile[PATH_LEN] = "";
	int cmd = param->cmd;

	logger(0, 0, "Restoring Container ...");
	ret = VZCTL_E_RESTORE;
	if ((rst_fd = open(PROC_RST, O_RDWR)) < 0) {
		if (errno == ENOENT)
			logger(-1, errno, "Error: No checkpointing"
				" support  is available, unable to open " PROC_RST);
		else
			logger(-1, errno, "Unable to open " PROC_RST);
		return VZCTL_E_RESTORE;
	}
	if (param->ctx) {
		if (ioctl(rst_fd, CPT_JOIN_CONTEXT, param->ctx) < 0) {
			logger(-1, errno, "Can not join cpt context");
			goto err;
		}
	}

	if (cmd == VZCTL_CMD_RESTORE || cmd == VZCTL_CMD_UNDUMP) {
		get_dumpfile(h, param, dumpfile, sizeof(dumpfile));
		logger(3, 0, "Open the dump file %s", dumpfile);
		dump_fd = open(dumpfile, O_RDONLY);
		if (dump_fd < 0) {
			logger(-1, errno, "Unable to open %s",
					dumpfile);
			goto err;
		}
		if (ioctl(rst_fd, CPT_SET_DUMPFD, dump_fd)) {
			logger(-1, errno, "Can't set dumpfile");
			goto err;
		}
	}
	start_param->fn = restore_FN;
	start_param->data = param;
	param->rst_fd = rst_fd;
	ret = get_env_ops()->env_create(h, start_param);
	if (ret)
		goto err;

err:
	close(rst_fd);
	if (dump_fd != -1)
		close(dump_fd);
	if (ret) {
		if (cmd == VZCTL_CMD_RESTORE || cmd == VZCTL_CMD_UNDUMP)
			preserve_dumpfile(dumpfile);
		logger(-1, 0, "Failed to restore the Container");
	}

	return ret;
}

static int get_cpt_state(const char *fname, unsigned envid, unsigned int *state)
{
	FILE *fp;
	char buf[1024];

	fp = fopen(fname, "r");
	if (fp == NULL) {
		if (errno == ENOENT)
			return 0;
		return vzctl_err(-1, 0, "Unable to get cpt state, failed to open %s",
				fname);
	}

	while (fgets(buf, sizeof(buf), fp)) {
		unsigned long long ul;
		unsigned int ui, id, mask, r;
		if ((r = sscanf(buf, "%llx %x %d %d",
				&ul, &ui, &id, &mask)) != 4)
			continue;
		if (id == envid) {
			*state = mask;
			break;
		}
	}
	fclose(fp);

	return 0;
}

static int env_get_cpt_state(unsigned envid, unsigned int *state)
{
	int ret;
	unsigned int mask = 0;

	*state = 0;
	ret = get_cpt_state(PROC_CPT, envid, &mask);
	if (ret)
		return ret;
	*state |= mask;

	ret = get_cpt_state(PROC_RST, envid, &mask);
	if (ret)
		return ret;
	*state |= mask;

	return 0;
}

int vz_env_get_cpt_state(struct vzctl_env_handle *h, int *state)
{
	int ret;
	unsigned int cpt_state;

	ret = env_get_cpt_state(h->veid, &cpt_state);
	if (ret)
		return ret;

	/* from linux/cpt_context.h */
	if (cpt_state == 2) /* CPT_CTX_SUSPENDED */
		*state |= ENV_STATUS_CPT_SUSPENDED;
	else if (cpt_state == 5) /* CPT_CTX_UNDUMPED */
		*state |= ENV_STATUS_CPT_UNDUMPED;

	return 0;
}

