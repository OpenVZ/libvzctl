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
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <string.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <linux/vzcalluser.h>
#include <linux/vzlist.h>
#include <vzsyscalls.h>
#include <sys/personality.h>
#include <time.h>

#include "env.h"
#include "env_config.h"
#include "env_configure.h"
#include "vzerror.h"
#include "vztypes.h"
#include "config.h"
#include "util.h"
#include "exec.h"
#include "net.h"
#include "meminfo.h"
#include "dev.h"
#include "readelf.h"
#include "vz.h"
#include "vzctl_param.h"
#include "technologies.h"
#include "veth.h"
#include "ub.h"
#include "dist.h"
#include "vztypes.h"
#include "lock.h"
#include "image.h"
#include "disk.h"
#include "tc.h"
#include "env_ops.h"
#include "iptables.h"
#include "cpt.h"

#define ENVRETRY	3

#define LINUX_REBOOT_MAGIC1	0xfee1dead
#define LINUX_REBOOT_MAGIC2     672274793
#define LINUX_REBOOT_CMD_POWER_OFF      0x4321FEDC

static int __vzctlfd = -1;
static int env_is_run(unsigned veid);

static inline int setluid(uid_t uid)
{
	return syscall(__NR_setluid, uid);
}

void vzctl_close(void)
{
	if (__vzctlfd != -1)
		close(__vzctlfd);
}

int vzctl_open(void)
{
	struct vzctl_env_create env_create = {};
	int ret;

	if (__vzctlfd != -1)
		return 0;

	__vzctlfd = open(VZCTLDEV, O_RDWR);
	if (__vzctlfd == -1)
		return vzctl_err(VZCTL_E_BAD_KERNEL, errno,
				"unable to open " VZCTLDEV);

	ret = ioctl(__vzctlfd, VZCTL_ENV_CREATE, &env_create);
	if (ret < 0 && (errno == ENOSYS || errno == EPERM)) {
		close(__vzctlfd);
		__vzctlfd = -1;
		return vzctl_err(VZCTL_E_BAD_KERNEL, 0, "Your kernel does not support working with virtual"
				" environments or necessary modules are not loaded\n");
	}
	return 0;
}

int get_vzctlfd(void)
{
	if (__vzctlfd == -1)
		vzctl_open();

	return __vzctlfd;
}

int vzctl2_get_vzctlfd(void)
{
	return get_vzctlfd();
}

/** Change root to specified directory
 *
 * @param		Container root
 * @return		0 on success
 */
int vzctl_chroot(const char *root)
{
	int i;
	sigset_t sigset;
	struct sigaction act;

	if (check_var(root, "CT root is not set"))
		return VZCTL_E_VE_ROOT_NOTSET;

        if (chdir(root))
                return vzctl_err(VZCTL_E_CHROOT, errno,
				"unable to change dir to %s", root);
	if (chroot(root))
		return vzctl_err(VZCTL_E_CHROOT, errno,
				"chroot %s failed", root);
	if (setsid() == -1)
		logger(0, errno, "setsid()");
	sigemptyset(&sigset);
	sigprocmask(SIG_SETMASK, &sigset, NULL);
	sigemptyset(&act.sa_mask);
	act.sa_handler = SIG_DFL;
	act.sa_flags = 0;
	for (i = 1; i <= NSIG; ++i)
		sigaction(i, &act, NULL);
	return 0;
}

int vzctl_setluid(struct vzctl_env_handle *h)
{
	int ret;
	unsigned veid = eid2veid(h);

	logger(10, 0, "* setluid %d", veid);
	ret = setluid(veid);
	if (ret == -1) {
		if (errno == ENOSYS)
			return vzctl_err(VZCTL_E_SETLUID, 0,
				"Error: kernel does not support"
				" user resources. Please, rebuild with"
				" CONFIG_USER_RESOURCE=y");
		else
			return vzctl_err(VZCTL_E_SETLUID, errno,
				"Cannot set luid");
	}
	return ret;
}

static int vz_setluid(struct vzctl_env_handle *h)
{
	return vzctl_setluid(h);
}

int env_create_data_ioctl(struct vzctl_env_create_data *data)
{
	int errcode;
	int retry = 0;

	do {
		if (retry)
			usleep(50000);
		errcode = ioctl(get_vzctlfd(), VZCTL_ENV_CREATE_DATA, data);
	} while (errcode < 0 && errno == EBUSY && retry++ < ENVRETRY);
#ifdef  __x86_64__
	/* Set personality PER_LINUX32 for i386 based VEs */
	if (errcode >= 0)
		set_personality32();
#endif
	return errcode;
}

static int env_create_ioctl(unsigned veid, int flags)
{
	struct vzctl_env_create env_create;
	int errcode;
	int retry = 0;

	memset(&env_create, 0, sizeof(env_create));
	env_create.veid = veid;
	env_create.flags = flags;
	do {
		if (retry)
			usleep(50000);
		errcode = ioctl(get_vzctlfd(), VZCTL_ENV_CREATE, &env_create);
	} while (errcode < 0 && errno == EBUSY && retry++ < ENVRETRY);
#ifdef  __x86_64__
	/* Set personality PER_LINUX32 for i386 based VEs */
	if (errcode >= 0 && (flags & VE_ENTER))
		set_personality32();
#endif
	return errcode;
}

static int env_get_pids_ioctl(unsigned veid, pid_t **pid)
{
	struct vzlist_vepidctl ve;
	int i, ret, size;
	pid_t buf[4096 * 2];
	pid_t *tmp;

	ve.veid = veid;
	ve.num = sizeof(buf) / 2;
	ve.pid = buf;
	while (1) {
		ret = ioctl(get_vzctlfd(), VZCTL_GET_VEPIDS, &ve);
		if (ret <= 0) {
			if (errno == ESRCH)
				ret = 0;
			else
				logger(-1, errno, "Failed to get the CT pid list");

			goto error;
		} else if (ret <= ve.num)
			break;
		size = ret + 20;
		if (ve.pid == buf)
			tmp = malloc(size * (2 * sizeof(pid_t)));
		else
			tmp = realloc(ve.pid, size * (2 * sizeof(pid_t)));
		if (tmp == NULL) {
			ret = -1;
			logger(-1, ENOMEM, "Failed to get the CT pid list");
			goto error;
		}
		ve.num = size;
		ve.pid = tmp;
	}
	*pid = malloc(ret * sizeof(pid_t));
	if (*pid == NULL) {
		ret = -1;
		goto error;
	}
	/* Copy pid from [pid:vpid] pair */
	for (i = 0; i < ret; i++)
		(*pid)[i] = ve.pid[2*i];
error:
	if (ve.pid != buf)
		free(ve.pid);
	return ret;
}

static int env_kill(struct vzctl_env_handle *h)
{
	int ret, i;
	pid_t *pids = NULL;
	unsigned veid = eid2veid(h);

	ret = env_get_pids_ioctl(veid, &pids);
	if (ret < 0)
		return -1;
	/* Kill all Container processes from VE0 */
	for (i = 0; i < ret; i++)
		kill(pids[i], SIGKILL);

	if (pids != NULL) free(pids);

	/* Wait for real Container shutdown */
	for (i = 0; i < (MAX_SHTD_TM / 2); i++) {
		if (!env_is_run(veid))
			return 0;
		usleep(500000);
	}
	return -1;
}

static int vz_env_stop(struct vzctl_env_handle *h, int stop_mode)
{
	const char *ve_root = h->env_param->fs->ve_root;
	int pid, child_pid, ret = 0;
	unsigned veid = eid2veid(h);

	/* Get ips from running Container before stop for latter cleanup */
	free_ip(&h->env_param->net->ip_del);
	vzctl_get_env_ip(h, &h->env_param->net->ip_del);

	if (stop_mode == M_KILL_FORCE)
		goto kill_force;

	if ((child_pid = fork()) < 0) {
		ret = vzctl_err(VZCTL_E_FORK, errno,
			"Unable to stop Container, fork failed");
		goto kill_force;
	} else if (child_pid == 0) {
		struct sigaction act;

		ret = vzctl_setluid(h);
		if (ret)
			_exit(ret);

		ret = vzctl_chroot(ve_root);
		if (ret)
			_exit(ret);

		sigemptyset(&act.sa_mask);
		act.sa_handler = SIG_IGN;
		act.sa_flags = SA_NOCLDSTOP;
		sigaction(SIGCHLD, &act, NULL);

		if (stop_mode == M_KILL)
			goto kill_vps;

		logger(0, 0, "Stopping the Container ...");
		if ((pid = fork()) < 0) {
			ret = vzctl_err(VZCTL_E_FORK, errno,
					"Unable to stop Container, fork failed");
			_exit(1);
		} else if (pid == 0) {
			ret = env_create_ioctl(veid, VE_ENTER);
			if (ret >= 0)
				ret = real_env_stop(stop_mode);
			_exit(ret);
		}

		if (wait_env_state(h, VZCTL_ENV_STOPPED, MAX_SHTD_TM) == 0)
			_exit(0);

kill_vps:
		logger(0, 0, "Forcibly stop the Container...");
		vzctl2_set_iolimit(h, 0);
		vzctl2_set_iopslimit(h, 0);

		if ((pid = fork()) < 0) {
			ret = vzctl_err(VZCTL_E_FORK, errno,
					"Unable to stop Container, fork failed");
			_exit(1);
		} else if (pid == 0) {
			ret = env_create_ioctl(veid, VE_ENTER);
			if (ret >= 0)
				ret = real_env_stop(M_KILL);
			_exit(ret);
		}
		if (wait_env_state(h, VZCTL_ENV_STOPPED, MAX_SHTD_TM) == 0)
			_exit(0);

		_exit(1);
	}
	env_wait(child_pid, 0, NULL);
	if (!is_env_run(h)) {
		logger(0, 0, "Container was stopped");
		return 0;
	}

kill_force:

	logger(0, 0, "Forcibly kill the Container...");
	if (env_kill(h))
		ret = vzctl_err(VZCTL_E_ENV_STOP, 0, "Unable to stop"
				" Container: operation timed out");

	return ret;
}

static int env_is_run(unsigned veid)
{
	struct vzctl_env_create env_create;
	int errcode;
	int retry = 0;

	bzero(&env_create, sizeof(env_create));
	env_create.veid = veid;
	env_create.flags = VE_TEST;
	do {
		if (retry)
			usleep(50000);
		errcode = ioctl(get_vzctlfd(), VZCTL_ENV_CREATE, &env_create);
	} while (errcode < 0 && errno == EBUSY && retry++ < ENVRETRY);

	if (errcode < 0 && (errno == ESRCH || errno == ENOTTY)) {
		return 0;
	} else if (errcode < 0) {
		return vzctl_err(-1, errno, "unable to get Container state");
	}
	return 1;
}

static int vz_is_env_run(struct vzctl_env_handle *h)
{
	return env_is_run(eid2veid(h));
}

static void build_feature_mask(struct vzctl_features_param *features,
        struct env_create_param3 *create_param)
{

	if (features->tech & VZ_T_NFS) {
		create_param->feature_mask |= VE_FEATURE_NFS;
		create_param->known_features |= VE_FEATURE_NFS;
	}
	if (features->tech & VZ_T_SYSFS) {
		create_param->feature_mask |= VE_FEATURE_SYSFS;
		create_param->known_features |= VE_FEATURE_SYSFS;
	}
	if (features->tech & VZ_T_NFS) {
		create_param->feature_mask |= VE_FEATURE_NFS;
		create_param->known_features |= VE_FEATURE_NFS;
	}

	if (features->known) {
		unsigned long long t = create_param->feature_mask;

		/* Merge features & technologies
		 * (f & t) ^ f | (t & k) ^ t
		 */
		create_param->feature_mask = (features->mask & t) ^
							features->mask;
		create_param->feature_mask |= (features->known & t) ^ t;
		create_param->known_features |= features->known;
	}
	if (create_param->feature_mask) {
		logger(3, 0, "Set features mask %016Lx/%016Lx",
				create_param->feature_mask,
				create_param->known_features);
	}
}

static int set_virt_osrelease(unsigned veid, const char *osrelease)
{
	char buf[1024];
	struct vzctl_ve_configure *param = (struct vzctl_ve_configure *) buf;
	int len;

	if (osrelease == NULL)
		return 0;

	logger(0, 0, "Os release: %s", osrelease);
	len = strlen(osrelease) + 1;
	if (len > sizeof(buf) - sizeof(struct vzctl_ve_configure))
		return VZCTL_E_INVAL;

	param->veid = veid;
	param->key = VE_CONFIGURE_OS_RELEASE;
	param->size = len;
	strcpy(param->data, osrelease);

	if (ioctl(get_vzctlfd(), VZCTL_VE_CONFIGURE, param))
		return vzctl_err(VZCTL_E_SET_OSRELEASE, errno, "Failed to configure osrelease '%s'",
				osrelease);
	return 0;
}

int _env_create(struct vzctl_env_handle *h, struct start_param *param)
{
	int ret, eno;
	struct vzctl_env_create_data env_create_data;
	struct env_create_param3 create_param;
	struct vzctl_env_param *env = h->env_param;
	unsigned veid = eid2veid(h);

	bzero(&create_param, sizeof(struct env_create_param3));

	create_param.iptables_mask = get_ipt_mask(env->features);
	logger(3, 0, "Setting iptables mask %#10.8llx",
			create_param.iptables_mask);

	if (env->cpu->vcpus != NULL) {
		logger(3, 0, "Set vcpu: %lu", *env->cpu->vcpus);
		create_param.total_vcpus = *env->cpu->vcpus;
	}
	build_feature_mask(env->features, &create_param);

	env_create_data.veid = veid;
	env_create_data.class_id = 0;
	env_create_data.flags = VE_CREATE | VE_EXCLUSIVE;
	env_create_data.data = &create_param;
	env_create_data.datalen = sizeof(create_param);

try:
	ret = env_create_data_ioctl(&env_create_data);
	if (ret < 0) {
		eno = errno;
		switch(eno) {
		case EINVAL:
			ret = VZCTL_E_ENVCREATE;
			/* Run-time kernel did not understand the
			 * latest create_parem -- so retry with
			 * the old env_create_param structs.
			 */
			switch (env_create_data.datalen) {
			case sizeof(struct env_create_param3):
				env_create_data.datalen =
					sizeof(struct env_create_param2);
				goto try;
			case sizeof(struct env_create_param2):
				env_create_data.datalen =
					sizeof(struct env_create_param);
				goto try;
			}
			break;
		case EACCES:
		/* License is not loaded */
			ret = VZCTL_E_NO_LICENSE;
			break;
		case ENOTTY:
		/* Some vz modules are not present */
			ret = VZCTL_E_BAD_KERNEL;
			break;
		default:
			return vzctl_err(VZCTL_E_ENVCREATE, errno,
					"VZCTL_ENV_CREATE_DATA");
		}
		return ret;
	}

	ret = set_virt_osrelease(veid, h->env_param->tmpl->osrelease);
	if (ret)
		return ret;

	ret = pre_setup_env(param);
	if (ret)
		return ret;

	return exec_init(param);
}

static int real_env_create(struct vzctl_env_handle *h, struct start_param *param)
{
	int ret, pid;
	struct vzctl_env_param *env = h->env_param;

	if ((ret = vzctl_chroot(env->fs->ve_root)))
		goto err;
	if ((ret = vzctl_setluid(h)))
		goto err;
	if ((ret = vzctl_res_setup_post(h)))
		goto err;
	/* Create another process for proper resource accounting */
	if ((pid = fork()) < 0) {
		ret = vzctl_err(VZCTL_E_FORK, errno, "Can not fork");
		goto err;
	} else if (pid == 0) {
		if (param->fn == NULL)
			ret = _env_create(h, param);
		else
			ret = param->fn(h, param);
		if (write(param->status_p[1], &ret, sizeof(ret)) != sizeof(ret))
			_exit(ret);
		_exit(ret);
	}

	return 0;

err:
	if (write(param->status_p[1], &ret, sizeof(ret)) == -1)
		logger(-1, errno, "Failed write()param->status_p[1] real_env_create");
	return ret;
}

static int vz_env_create(struct vzctl_env_handle *h, struct start_param *param)
{
	int ret, rc, pid, errcode = 0;
	int status_p[2];
	struct sigaction act;

	if (pipe(status_p) < 0)
		return vzctl_err(VZCTL_E_PIPE, errno, "Cannot create pipe");
	param->status_p = status_p;

	sigemptyset(&act.sa_mask);
	act.sa_handler = SIG_IGN;
	act.sa_flags = SA_NOCLDSTOP;
	sigaction(SIGPIPE, &act, NULL);
	if ((pid = fork()) < 0) {
		ret = vzctl_err(VZCTL_E_FORK, errno, "Cannot fork");
		goto err;
	} else if (pid == 0) {
		sigaction(SIGCHLD, &act, NULL);

		fcntl(status_p[1], F_SETFD, FD_CLOEXEC);
		close(status_p[0]);
		fcntl(param->err_p[1], F_SETFD, FD_CLOEXEC);
		close(param->err_p[0]);
		fcntl(param->wait_p[0], F_SETFD, FD_CLOEXEC);
		close(param->wait_p[1]);

		ret = real_env_create(h, param);

		_exit(ret);
	}
	/* Wait for environment created */
	close(param->wait_p[0]); param->wait_p[0] = -1;
	close(param->err_p[1]); param->err_p[1] = -1;
	close(status_p[1]); status_p[1] = -1;
	ret = 0;
	rc = read(status_p[0], &errcode, sizeof(errcode));
	if (rc == -1) {
		ret = vzctl_err(VZCTL_E_SYSTEM, errno, "Failed tp start the Container,"
				" read from status pipe is failed");
	} else if (rc == 0) {
		/* FIXME: CPT close status pipe on success */
		if (param->fn == NULL)
			ret = vzctl_err(VZCTL_E_SYSTEM, 0, "Failed tp start the Container,"
				" status pipe unexpectedly closed");
	} else if (errcode != 0) {
		ret = errcode;
		switch (ret) {
		case VZCTL_E_NO_LICENSE:
			logger(-1, 0, "This installation"
				" is not licensed. To unlock"
				" the installation, run"
				" the vzlicupdate utility and specify your"
				" license key");
			break;
		case VZCTL_E_BAD_KERNEL:
			logger(-1, 0, "Invalid kernel,"
				" or some kernel modules "
				"are not loaded");
			break;
		case VZCTL_E_CAP:
			logger(-1, 0, "Unable to set the capability");
			break;
		case VZCTL_E_WAIT_FAILED:
			logger(-1, 0, "Unable to set"
				" the wait functionality");
			break;
		case VZCTL_E_NO_INITTAB:
			logger(-1, 0, "Unable to set the wait functionality."
				" Unable to open /etc/inittab");
			break;
		case VZCTL_E_UNSUP_TECH:
			logger(-1, 0, "Unable to start the Container;"
				" the required technology (sysfs) is not supported");
			break;
		case VZCTL_E_SET_OSRELEASE:
			logger(-1, 0, "Unable to start the Container;"
				" failed to set osrelease");
			break;
		default:
			logger(-1, 0, "Unable to create the enviroment ret=%d", ret);
			break;
		}
	}
	logger(10, 0, "* Done wait status [%d]", ret);

	env_wait(pid, 0, NULL);
err:
	close(status_p[1]);
	close(status_p[0]);

	return ret;
}

/* Get val from config
 * return:	0	Ok
 *		1	not found
 *		-1	error
 */
static int conf_get_param_ul(const struct vzctl_config *conf,
		const char *name, unsigned long *limit)
{
	const char *data = NULL;

	if (vzctl2_conf_get_param(conf, name, &data))
		return vzctl_err(-1, 0, "vzctl2_conf_get_param %s", name);

	if (data == NULL)
		return 1;

	if (parse_ul(data, limit))
		return vzctl_err(-1, 0, "Invalid %s=%s", name, data);

	return 0;
}

int vzctl2_set_vzlimits(const char *name)
{
	int rc;
	char buf[64];
	const struct vzctl_config *conf;
	unsigned long limit;
	struct vzctl_env_handle h = {};
	unsigned long ul;
	unsigned bcid;

	conf = vzctl_global_conf();
	if (conf == NULL)
		return -1;

	snprintf(buf, sizeof(buf), "%s_BCID", name);
	rc = conf_get_param_ul(conf, buf, &ul);
	if (rc == -1)
		return -1;
	else if (rc == 1)
		return 0;

	bcid = (unsigned)ul;
	if (setluid(bcid))
		return vzctl_err(-1, errno, "setluid %u", bcid);

	snprintf(h.ctid, sizeof(ctid_t), "%08x-0000-0000-0000-000000000000", bcid);

	snprintf(buf, sizeof(buf), "%s_IOLIMIT", name);
	rc = conf_get_param_ul(conf, buf, &limit);
	if (rc == 0 && vzctl2_set_iolimit(&h, limit))
		return -1;

	snprintf(buf, sizeof(buf), "%s_IOPSLIMIT", name);
	rc = conf_get_param_ul(conf, buf, &limit);
	if (rc == 0 && vzctl2_set_iopslimit(&h, limit))
		return -1;

	snprintf(buf, sizeof(buf), "%s_MEMLIMIT", name);
	rc = conf_get_param_ul(conf, buf, &limit);
	if (rc == 0) {
		struct vzctl_2UL_res res;
		struct vzctl_ub_param ub = {
			.physpages = &res,
		};

		res.b = res.l = limit / 4096;
		if (set_ub(bcid, &ub))
			return -1;
	}

	return 0;
}

int vzctl2_set_vziolimit(const char *name)
{
	return vzctl2_set_vzlimits(name);
}

static int vz_env_apply_param(struct vzctl_env_handle *h, struct vzctl_env_param *env, int flags)
{
	int ret = 0;

	/* Do not apply parameters on stopped Container
	 * in case --save option specified
	 */
	if (is_env_run(h) || !(flags & VZCTL_SAVE)) {
		/* ubc/slm already set on Container start */
		if (h->state != VZCTL_STATE_STARTING) {
			if ((ret = vzctl_res_configure(h, env, flags)))
				goto err;
		}
		if ((ret = apply_cpu_param(h, env, flags)))
			goto err;
		if ((ret = apply_io_param(h, env, flags)))
			goto err;
		if ((ret = vzctl_apply_tc_param(h, env, flags)))
			goto err;
		if ((ret = apply_dev_param(h, env, flags)))
			goto err;
		if ((ret = apply_netdev_param(h, env, flags)))
			goto err;
		if ((ret = apply_venet_param(h, env, flags)))
			goto err;
		if ((ret = apply_veth_param(h, env, flags)))
			goto err;
		if ((ret = apply_meminfo_param(h, env, flags)))
			goto err;
				/* TODO
			ext_ip_setup(veid, param, 1)))
			vzctl_set_pci(veid, param->ve_root, param->pci))
		*/

		if ((ret = vzctl_setup_disk(h, env->disk, flags)))
			goto err;
		if ((ret = vzctl_env_configure(h, env, flags)))
			goto err;

		if (h->state == VZCTL_STATE_STARTING) {
			if ((ret = setup_vzlink_dev(h, flags)))
				goto err;
			if ((ret = env_console_configure(h, flags)))
				goto err;
			if (env->net->rps != VZCTL_PARAM_OFF)
				configure_net_rps(env->fs->ve_root, "venet0");
		}
		if (!(flags & VZCTL_RESTORE)) {
			if ((ret = apply_quota_param(h, env, flags)))
				goto err;
		}
	}
err:
	return ret;
}

static int vz_env_enter(struct vzctl_env_handle *h, int flags)
{
	int ret;
	unsigned veid = eid2veid(h);

	if ((ret = vzctl_chroot(h->env_param->fs->ve_root)))
		return ret;

	if (env_create_ioctl(veid, VE_ENTER |
				(flags & VE_SKIPLOCK)) < 0)
		return vzctl_err(errno == ESRCH ? VZCTL_E_ENV_NOT_RUN : VZCTL_E_ENVCREATE,
				errno, "Failed to enter");

	return 0;
}

static int vz_env_exec(struct vzctl_env_handle *h, struct exec_param *param,
		int flags, pid_t *pid)
{
	int ret;
	pid_t pid2;

	*pid = fork();
	if (*pid < 0) {
		return vzctl_err(VZCTL_E_FORK, errno, "Cannot fork");
	} else if (*pid == 0) {
		ret = vzctl_setluid(h);
		if (ret)
			goto err;

		pid2 = fork();
		if (pid2 < 0) {
			ret = vzctl_err(VZCTL_E_FORK, errno, "Cannot fork");
			goto err;
		} else if (pid2 == 0) {
			ret = vz_env_enter(h, flags);
			if (ret == 0)
				ret = real_env_exec(h, param, flags);
			_exit(ret);
		}

		real_env_exec_close(param);

		if (param->timeout)
			set_timeout_handler(pid2, param->timeout);

		ret = env_wait(pid2, param->timeout, NULL);
err:
		_exit(ret);
	}

	return 0;
}

static int vz_env_exec_fn(struct vzctl_env_handle *h, execFn fn, void *data,
		int *data_fd, int timeout, int flags, pid_t *pid)
{
	int ret;
	pid_t pid2;

	*pid = fork();
	if (*pid < 0) {
		return vzctl_err(VZCTL_E_FORK, errno, "Cannot fork");
	} else if (*pid == 0) { 
		ret = vzctl_setluid(h);
		if (ret)
			goto err;

		pid2 = fork();
		if (pid2 < 0) {
			ret = vzctl_err(VZCTL_E_FORK, errno, "Cannot fork");
			goto err;
		} else if (pid2 == 0) {
			ret = vz_env_enter(h, flags);
			if (ret == 0)
				ret = real_env_exec_fn(h, fn, data, data_fd, timeout, flags);

			_exit(ret);
		}

		if (timeout)
			set_timeout_handler(pid2, timeout);

		ret = env_wait(pid2, timeout, NULL);
err:
		_exit(ret);
	}

	return 0;
}

static int vz_env_set_devperm(struct vzctl_env_handle *h, struct vzctl_dev_perm *perm)
{
        struct vzctl_setdevperms devperms;
	unsigned veid = eid2veid(h);

        devperms.veid = veid;
        devperms.dev = perm->dev;
        devperms.mask = perm->mask;
        devperms.type = perm->type;

        logger(0, 0, "Setting permissions %o dev 0x%x",
                        devperms.mask, devperms.dev);
        if (ioctl(get_vzctlfd(), VZCTL_SETDEVPERMS, &devperms))
                return vzctl_err(VZCTL_E_SET_DEVICES, errno, "Unable to set devperms");

        return 0;
}

static int vz_env_set_cpumask(struct vzctl_env_handle *h, struct vzctl_cpumask *cpumask)
{
	return env_set_cpumask(h, cpumask);
}

static int vz_env_set_nodemask(struct vzctl_env_handle *h, struct vzctl_nodemask *nodemask)
{
	return env_set_nodemask(h, nodemask);
}

static int get_feature(void)
{
        return (F_SETLUID);
}

static struct vzctl_env_ops env_vzops = {
	.get_feature = get_feature,
	.open = vzctl_open,
	.env_create = vz_env_create,
	.env_chkpnt = vz_env_chkpnt,
	.env_restore = vz_env_restore,
	.env_cpt_cmd = vz_env_cpt_cmd,
	.env_get_cpt_state = vz_env_get_cpt_state,
	.env_stop = vz_env_stop,
	.env_apply_param = vz_env_apply_param,
	.is_env_run = vz_is_env_run,
	.env_enter = vz_env_enter,
	.env_setluid = vz_setluid,
	.env_set_devperm = vz_env_set_devperm,
	.env_set_cpumask = vz_env_set_cpumask,
	.env_set_nodemask = vz_env_set_nodemask,
	.env_set_iolimit = vz_set_iolimit,
	.env_set_ioprio  = vz_set_ioprio,
	.env_get_iolimit = vz_get_iolimit,
	.env_set_iopslimit = vz_set_iopslimit,
	.env_get_iopslimit = vz_get_iopslimit,
	.env_ip_ctl = vz_ip_ctl,
	.env_get_veip = get_env_ip_proc,
	.env_veth_ctl = vz_veth_ctl,
	.env_exec = vz_env_exec,
	.env_exec_fn = vz_env_exec_fn,
	.close = vzctl_close,
};

void env_vzops_init(struct vzctl_env_ops *ops)
{
	if (is_vz_kernel())
		memcpy(ops, &env_vzops, sizeof(*ops));
}
