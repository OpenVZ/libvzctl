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

#define _GNU_SOURCE
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
#include <sys/resource.h>
#include <sys/sysmacros.h>

#include <string.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <linux/vzcalluser.h>
#include <time.h>
#include <grp.h>
#include <sys/utsname.h>
#include <mntent.h>
#include <uuid/uuid.h>
#include <ext2fs/ext2_fs.h>
#include <grp.h>

#include "env.h"
#include "cgroup.h"
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
#include "veth.h"
#include "ub.h"
#include "dist.h"
#include "vztypes.h"
#include "lock.h"
#include "image.h"
#include "disk.h"
#include "tc.h"
#include "env_ops.h"
#include "ha.h"
#include "wrap.h"
#include "create.h"

#define ENVRETRY	3

int create_venet_link(void);

#define LINUX_REBOOT_MAGIC1     0xfee1dead
#define LINUX_REBOOT_MAGIC2     672274793
#define LINUX_REBOOT_CMD_POWER_OFF	0x4321FEDC

int real_env_stop(int stop_mode)
{
	logger(10, 0, "* stop mode %d", stop_mode);
	close_fds(1, -1);
	/* Disable fsync. The fsync will be done by umount() */
	configure_sysctl("/proc/sys/fs/fsync-enable", "0");
	configure_sysctl("/sys/fs/cgroup/systemd/release_agent", "");
	configure_sysctl("/sys/fs/cgroup/systemd/notify_on_release", "0");
	switch (stop_mode) {
	case M_HALT: {
		char *argv[] = {"halt", NULL};
		char *argv_init[] = {"init", "0", NULL};
		execvep(argv[0], argv, NULL);
		execvep(argv_init[0], argv_init, NULL);
		break;
	}
	case M_REBOOT: {
		char *argv[] = {"reboot", NULL};
		execvep(argv[0], argv, NULL);
		break;
	}
	case M_KILL:
		return syscall(__NR_reboot, LINUX_REBOOT_MAGIC1,
			LINUX_REBOOT_MAGIC2,
			LINUX_REBOOT_CMD_POWER_OFF, NULL);
	}
	return -1;
}

static int run_start_script(struct vzctl_env_handle *h)
{
	char buf[STR_SIZE];
	char *arg[2];
	char *env[2];
	char s_veid[STR_SIZE];

	arg[0] = get_script_path(VZCTL_START, buf, sizeof(buf));
	arg[1] = NULL;
	snprintf(s_veid, sizeof(s_veid), "VEID=%s", EID(h));
	env[0] = s_veid;
	env[1] = NULL;

	return vzctl2_wrap_exec_script(arg, env, 0);
}

int run_stop_script(struct vzctl_env_handle *h)
{
	char script[STR_SIZE];
	char buf[STR_SIZE];
	char *env[5] = {};
	int ret, i = 0;
	const char *bandwidth = NULL;
	char *arg[] = {get_script_path(VZCTL_STOP, script, sizeof(script)), NULL};

	snprintf(buf, sizeof(buf), "VEID=%s", EID(h));
	ret = xstrdup(&env[i++], buf);
	if (ret)
		return ret;

	if (h->env_param->vz->tc->traffic_shaping == VZCTL_PARAM_ON) {
		ret = xstrdup(&env[i++], "TRAFFIC_SHAPING=yes");
		if (ret)
			goto err;

		/* BANDWIDTH is needed for tc class removal */
		vzctl2_env_get_param(h, "BANDWIDTH", &bandwidth);
		if (bandwidth != NULL) {
			snprintf(buf, sizeof(buf), "BANDWIDTH=%s", bandwidth);
			ret = xstrdup(&env[i++], buf);
			if (ret)
				goto err;
		}
	}

	struct vzctl_veth_param *veth = h->env_param->veth;
	if (!list_empty(&veth->dev_list)) {
		char *p;
		struct vzctl_veth_dev *it;
		int len = sizeof("VETH=");

		list_for_each(it, &veth->dev_list, list)
			len += strlen(it->dev_name) + 1;
		p = malloc(len);
		if (p == NULL) {
			ret = VZCTL_E_NOMEM;
			goto err;
		}

		env[i++] = p;
		p += sprintf(p, "VETH=");
		list_for_each(it, &veth->dev_list, list)
			p += sprintf(p, "%s ", it->dev_name);
	}

	env[i] = NULL;

	ret = vzctl2_wrap_exec_script(arg, env, 0);
err:
	free_ar_str(env);

	return ret;
}

int is_env_run(struct vzctl_env_handle *h)
{
	return get_env_ops()->is_env_run(h);
}

int wait_env_state(struct vzctl_env_handle *h, int state, unsigned int timeout)
{
	int i, rc;

	for (i = 0; i < timeout * 2; i++) {
		rc = is_env_run(h);
		switch (state) {
		case VZCTL_ENV_STARTED:
			if (rc == 1)
				return 0;
			break;
		case VZCTL_ENV_STOPPED:
			if (rc == 0)
				return 0;
			break;
		}
		usleep(500000);
	}

	return vzctl_err(-1, 0, "Wait CT state %s timed out",
			state == VZCTL_ENV_STARTED ? "started" : "stopped");
}

static int do_env_stop(struct vzctl_env_handle *h, int stop_mode)
{
	/* Unregister before real stop to avoid races with vzevend */
	vzctl2_unregister_running_state(h->env_param->fs->ve_private);

	if (get_env_ops()->env_stop(h, stop_mode))
		return vzctl_err(VZCTL_E_ENV_STOP, 0,
			"Unable to stop the Container:"
			" operation timed out");
	return 0;
}

static int do_env_post_stop(struct vzctl_env_handle *h, int flags)
{
	int ret = 0;

	if (!(flags & VZCTL_SKIP_UMOUNT))
		ret = vzctl2_env_umount(h, flags);

	run_stop_script(h);

	return ret;
}

int vzctl_env_stop(struct vzctl_env_handle *h, stop_mode_e stop_mode, int flags)
{
	int ret;
	struct vzctl_env_status env_status = {};

	vzctl2_get_env_status_info(h, &env_status, ENV_STATUS_RUNNING);
	if (!(env_status.mask & ENV_STATUS_RUNNING)) {
		if (flags & VZCTL_FORCE)
			goto force;

                return vzctl_err(0, 0, "Container is not running");
	} else if (flags & VZCTL_FORCE)
		return 0;

	logger(0, 0, "Stopping the Container ...");
	if (env_status.mask & (ENV_STATUS_CPT_SUSPENDED | ENV_STATUS_CPT_UNDUMPED)) {
		struct vzctl_cpt_param cpt_param = {};
		logger(0, 0, "The Container is in the %s state",
				(env_status.mask & ENV_STATUS_CPT_SUSPENDED) ? "suspended" : "undumped");
		ret = vzctl2_cpt_cmd(h,
				(env_status.mask & ENV_STATUS_CPT_SUSPENDED) ? VZCTL_CMD_CHKPNT : VZCTL_CMD_RESTORE,
				VZCTL_CMD_RESUME, &cpt_param, flags);
		if (ret)
			return vzctl_err(VZCTL_E_ENV_STOP, 0, "Unable to stop the Container");
	}

	if (!(flags & VZCTL_SKIP_ACTION_SCRIPT)) {
		char buf[PATH_MAX];

		get_action_script_path(h, VZCTL_STOP_PREFIX, buf, sizeof(buf));
		if (stat_file(buf) &&
		    vzctl2_wrap_env_exec_script(h, NULL, NULL, buf, 0, EXEC_LOG_OUTPUT))
		{
			return vzctl_err(VZCTL_E_ACTIONSCRIPT, 0,
				"Error executing stop script %s", buf);
		}
	}

	ret = do_env_stop(h, stop_mode);
	if (ret)
		return ret;

	logger(0, 0, "Container was stopped");

force:
	return do_env_post_stop(h, flags);
}

int vzctl2_env_stop(struct vzctl_env_handle *h, stop_mode_e stop_mode, int flags)
{
	if (vzctl2_get_flags() & VZCTL_FLAG_DONT_USE_WRAP)
		return vzctl_env_stop(h, stop_mode, flags);

	return vzctl_wrap_env_stop(h, stop_mode, flags);
}

int vzctl2_env_pause(struct vzctl_env_handle *h, int flags)
{
	int ret;
	struct vzctl_cpt_param cpt = {};
	struct vzctl_env_status env_status = {};

	vzctl2_get_env_status_info(h, &env_status, ENV_STATUS_RUNNING);
	if (!(env_status.mask & ENV_STATUS_RUNNING))
		return vzctl_err(VZCTL_E_ENV_NOT_RUN, 0,
				"Container is not running");

	if (env_status.mask & ENV_STATUS_CPT_SUSPENDED)
		return vzctl_err(VZCTL_E_ENV_RUN, 0,
				"Container is already paused");

	logger(0, 0, "Pause the Container ...");
	ret = vzctl2_cpt_cmd(h, 0, VZCTL_CMD_SUSPEND, &cpt, flags);
	if (ret)
		return vzctl_err(ret, 0, "Unable to pause the Container");

	logger(0, 0, "The Container has been successfully paused");

	return 0;
}

#define K_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
static int get_virt_osrelease(struct vzctl_env_handle *h)
{
	int ret;
	int min_a, min_b, min_c;
	int max_a, max_b, max_c;
	int cur_a, cur_b, cur_c;
	char tm_osrelease[STR_SIZE];
	char osrelease[STR_SIZE];
	struct utsname utsbuf;
	const char *tail;
	const char *ostmpl = h->env_param->tmpl->ostmpl;

	if (h->env_param->tmpl->osrelease != NULL || ostmpl == NULL)
		return 0;

	if (uname(&utsbuf) != 0)
		return vzctl_err(-1, errno, "uname() failed");

	ret = vztmpl_get_osrelease(ostmpl, tm_osrelease, sizeof(tm_osrelease));
	if (ret)
		return ret;
	/* Osrelease is not provided */
	if (tm_osrelease[0] == '\0')
		return 0;

	logger(2, 0, "Template %s osrelease: %s", ostmpl, tm_osrelease);
	ret = sscanf(utsbuf.release, "%d.%d.%d",
			&cur_a, &cur_b, &cur_c);
	if (ret != 3)
		return vzctl_err(-1, 0, "Unable to parse node release: %s",
				utsbuf.release);

	ret = sscanf(tm_osrelease, "%d.%d.%d:%d.%d.%d",
			&min_a, &min_b, &min_c,
			&max_a, &max_b, &max_c);
	if (ret != 3 && ret != 6)
		return vzctl_err(-1, 0, "Incorrect osrelease syntax: %s", ostmpl);

	if (K_VERSION(cur_a, cur_b, cur_c) < K_VERSION(min_a, min_b, min_c)) {
		cur_a = min_a; cur_b = min_b; cur_c = min_c;
	}
	if (ret == 6 && (K_VERSION(cur_a, cur_b, cur_c) > K_VERSION(max_a, max_b, max_c))) {
		cur_a = max_a; cur_b = max_b; cur_c = max_c;
	}

	/* Make kernel version Vz specific like A.B.C-028stab070.1 */
	tail = strchr(utsbuf.release, '-');

	snprintf(osrelease, sizeof(osrelease), "%d.%d.%d%s",
			cur_a, cur_b, cur_c, tail ? tail : "");

	return xstrdup(&h->env_param->tmpl->osrelease, osrelease);
}

static void fix_ub(struct vzctl_ub_param *ub)
{
	unsigned long min_ipt;

	if (ub->numiptent == NULL) {
		ub->numiptent = malloc(sizeof(struct vzctl_2UL_res));
		if (ub->numiptent)
			ub->numiptent->b = ub->numiptent->l = DEF_NUMIPTENT;
	}

	min_ipt = min_ul(ub->numiptent->b, ub->numiptent->l);
	if (min_ipt < MIN_NUMIPTENT) {
		logger(0, 0, "Warning: NUMIPTENT %lu:%lu is less"
			" than minimally allowable value, set to %d:%d",
			ub->numiptent->b, ub->numiptent->l,
			MIN_NUMIPTENT, MIN_NUMIPTENT);
		ub->numiptent->b = ub->numiptent->l =  MIN_NUMIPTENT;
	}

	if (ub->numproc == NULL) {
		ub->numproc = malloc(sizeof(struct vzctl_2UL_res));
		if (ub->numproc)
			ub->numproc->b = ub->numproc->l = 131072;
	}
}

static void fix_cpu_param(struct vzctl_cpu_param *cpu)
{
	assert(cpu);
	if (cpu->units == NULL && cpu->weight == NULL) {
		cpu->units = malloc(sizeof(unsigned long));
		*cpu->units = UNLCPUUNITS;
	}
}

static void fix_param(struct vzctl_env_param *env)
{
	fix_ub(env->res->ub);
	fix_cpu_param(env->cpu);

	/* enable bridge by default #PSBM-50520 */
	if (!(env->features->known & VE_FEATURE_BRIDGE)) {
		env->features->known |= VE_FEATURE_BRIDGE;
		env->features->mask |= VE_FEATURE_BRIDGE;
	}
}

#define INITTAB_FILE		"/etc/inittab"
#define INITTAB_VZID		"vz:"
#define INITTAB_ACTION		INITTAB_VZID "12345:once:touch " VZFIFO_FILE

#define EVENTS_DIR		"/etc/event.d/"
#define EVENTS_FILE		EVENTS_DIR "call_on_default_rc"
#define EVENTS_SCRIPT	\
	"# This task runs if default runlevel is reached\n"	\
	"start on stopped rc2\n"					\
	"start on stopped rc3\n"					\
	"start on stopped rc4\n"					\
	"start on stopped rc5\n"					\
	"exec touch " VZFIFO_FILE "\n"

#define EVENTS_DIR_UBUNTU	"/etc/init/"
#define EVENTS_FILE_UBUNTU	EVENTS_DIR_UBUNTU "call_on_default_rc.conf"
#define EVENTS_SCRIPT_UBUNTU	\
	"# tell vzctl that start was successfull\n"		\
	"#\n"								\
	"# This task causes to tell vzctl that start was successfull\n"	\
	"\n"								\
	"description	\"tell vzctl that start was successfull\"\n"	\
	"\n"								\
	"start on stopped rc RUNLEVEL=[2345]\n"				\
	"\n"								\
	"task\n"							\
	"\n"								\
	"exec touch " VZFIFO_FILE

#define MAX_WAIT_TIMEOUT	60 * 60

#define SYSTEMD_BIN "systemd"
#define SBIN_INIT "/sbin/init"

static int add_inittab_entry(const char *entry, const char *id)
{
	FILE *rfp = NULL;
	int wfd =1, len, err = -1, found = 0;
	struct stat st;
	char buf[PATH_MAX];

	if (stat(INITTAB_FILE, &st))
		return vzctl_err(-1, errno, "Can't stat "INITTAB_FILE);

	if ((rfp = fopen(INITTAB_FILE, "r")) == NULL)
		return vzctl_err(-1, errno, "Unable to open " INITTAB_FILE);

	wfd = open(INITTAB_FILE ".tmp", O_WRONLY|O_TRUNC|O_CREAT, st.st_mode);
	if (wfd == -1) {
		logger(-1, errno, "Unable to open " INITTAB_FILE ".tmp");
		goto err;
	}

	set_fattr(wfd, &st);

	while (!feof(rfp)) {
		if (fgets(buf, sizeof(buf), rfp) == NULL) {
			if (ferror(rfp))
				goto err;
			break;
		}
		if (!strcmp(buf, entry)) {
			found = 1;
			break;
		}
		if (id != NULL && !strncmp(buf, id, strlen(id)))
			continue;

		len = strlen(buf);
		if (write(wfd, buf, len) == -1) {
			logger(-1, errno, "Unable to write to " INITTAB_FILE);
			goto err;
		}
	}

	if (!found) {
		if (write(wfd, entry, strlen(entry)) == -1 ||
				write(wfd, "\n", 1) == -1)
		{
			logger(-1, errno, "Unable to write to " INITTAB_FILE);
			goto err;
		}

		if (rename(INITTAB_FILE ".tmp", INITTAB_FILE)) {
			logger(-1, errno, "Unable to rename " INITTAB_FILE);
			goto err;
		}
	}
	err = 0;
err:

	if (wfd != -1)
		close(wfd);
	if (rfp != NULL)
		fclose(rfp);

	unlink(INITTAB_FILE ".tmp");

	return err;
}

static int replace_reach_runlevel_mark(void)
{
	int wfd, err, n, is_upstart = 0, is_systemd = 0;
	struct stat st;
	char buf[4096];
	char *p;

	unlink(VZFIFO_FILE);
	if (mkfifo(VZFIFO_FILE, 0644)) {
		fprintf(stderr, "Unable to create " VZFIFO_FILE " %s\n",
			strerror(errno));
		return -1;
	}
	/* Create upstart specific script */
	if (!stat(EVENTS_DIR_UBUNTU, &st)) {
		is_upstart = 1;
		wfd = open(EVENTS_FILE_UBUNTU, O_WRONLY|O_TRUNC|O_CREAT, 0644);
		if (wfd == -1) {
			fprintf(stderr, "Unable to create " EVENTS_FILE_UBUNTU " %s\n",
				strerror(errno));
			return -1;
		}
		if (write(wfd, EVENTS_SCRIPT_UBUNTU, sizeof(EVENTS_SCRIPT_UBUNTU) - 1) == -1) {
			fprintf(stderr, "Unable to write to "EVENTS_FILE_UBUNTU  " %s\n",
					strerror(errno));
			close(wfd);
			return -1;
		}
		close(wfd);
	} else if (!stat(EVENTS_DIR, &st)) {
		is_upstart = 1;
		wfd = open(EVENTS_FILE, O_WRONLY|O_TRUNC|O_CREAT, 0644);
		if (wfd == -1) {
			fprintf(stderr, "Unable to create " EVENTS_FILE " %s\n",
					strerror(errno));
			return -1;
		}
		if (write(wfd, EVENTS_SCRIPT, sizeof(EVENTS_SCRIPT) - 1) == -1) {
			fprintf(stderr, "Unable to write to " EVENTS_FILE  " %s\n",
					strerror(errno));
			close(wfd);
			return -1;
		}
		close(wfd);
	}

	/* Check for systemd */
	if (!is_upstart && (n = readlink(SBIN_INIT, buf, sizeof(buf) - 1)) > 0)
	{
		buf[n] = 0;
		if ((p = strrchr(buf, '/')) == NULL)
			p = buf;
		else
			p++;
		if (strncmp(p, SYSTEMD_BIN, sizeof(SYSTEMD_BIN) - 1) == 0)
			is_systemd = 1;
	}

	if (stat(INITTAB_FILE, &st)) {
		if (is_upstart || is_systemd)
			return 0;
		fprintf(stderr, "Warning: unable to stat " INITTAB_FILE " %s\n",
			strerror(errno));
		return -1;
	}

	err = add_inittab_entry(INITTAB_ACTION, INITTAB_VZID);

	return err;
}

static int check_requires(struct vzctl_env_param *env, int flags)
{
	int ret;
	unsigned long mask;

	if ((ret = check_var(env->fs->ve_private, "VE_PRIVATE is not set")))
		return ret;
	if ((ret = check_var(env->fs->ve_root, "VE_ROOT is not set")))
		return ret;
	if ((ret = check_res_requires(env)))
		return ret;
	if ((mask = vzctl2_check_tech(env->features->tech))) {
		char buf[512];
		tech2str(mask, buf, sizeof(buf));
		return vzctl_err(VZCTL_E_UNSUP_TECH, 0, "Unable to start Container"
			" unsupported technologie(s) required: %s", buf);
	}
	if (env->misc->start_disabled == VZCTL_PARAM_ON &&
			!(flags & VZCTL_FORCE))
		return vzctl_err(VZCTL_E_ENV_START_DISABLED, 0,
				"Container start disabled");
	if (env->misc->ve_type == VZCTL_ENV_TYPE_TEMPLATE)
		return vzctl_err(VZCTL_E_ENV_START_DISABLED, 0,
				"Container is template"
				" therefore cannot be started");
	if (stat_file(env->fs->ve_private) != 1)
		return vzctl_err(VZCTL_E_NO_PRVT, 0,
			"Container private area %s does not exist",
			env->fs->ve_private);

	if (env->fs->layout == VZCTL_LAYOUT_5 &&
			find_root_disk(env->disk) == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0,
			"Container root disk is not configured");

	return ret;
}

static void restore_mtab(void)
{
	struct stat st;

	if (stat("/etc/mtab", &st) == 0 && S_ISLNK(st.st_mode))
		return;

	if (unlink("/etc/mtab") && errno != ENOENT)
		logger(-1, errno, "failed to unlink /etc/mtab");

	if (symlink("/proc/mounts", "/etc/mtab"))
		logger(-1, errno, "symlink(/etc/mtab, /proc/mounts");
}

static struct devnode {
	int major;
	int minor;
	const char *name;
	mode_t mode;
	const char *group;
} _g_devs[] = {
	{2, 0x0, "/dev/ptyp0", S_IFCHR|0600},
	{2, 0x1, "/dev/ptyp1", S_IFCHR|0600},
	{2, 0x2, "/dev/ptyp2", S_IFCHR|0600},
	{2, 0x3, "/dev/ptyp3", S_IFCHR|0600},
	{2, 0x4, "/dev/ptyp4", S_IFCHR|0600},
	{2, 0x5, "/dev/ptyp5", S_IFCHR|0600},
	{2, 0x6, "/dev/ptyp6", S_IFCHR|0600},
	{2, 0x7, "/dev/ptyp7", S_IFCHR|0600},
	{2, 0x8, "/dev/ptyp8", S_IFCHR|0600},
	{2, 0x9, "/dev/ptyp9", S_IFCHR|0600},
	{2, 0xa, "/dev/ptypa", S_IFCHR|0600},
	{2, 0xb, "/dev/ptypb", S_IFCHR|0600},
	{3, 0x0, "/dev/ttyp0", S_IFCHR|0600},
	{3, 0x1, "/dev/ttyp1", S_IFCHR|0600},
	{3, 0x2, "/dev/ttyp2", S_IFCHR|0600},
	{3, 0x3, "/dev/ttyp3", S_IFCHR|0600},
	{3, 0x4, "/dev/ttyp4", S_IFCHR|0600},
	{3, 0x5, "/dev/ttyp5", S_IFCHR|0600},
	{3, 0x6, "/dev/ttyp6", S_IFCHR|0600},
	{3, 0x7, "/dev/ttyp7", S_IFCHR|0600},
	{3, 0x8, "/dev/ttyp8", S_IFCHR|0600},
	{3, 0x9, "/dev/ttyp9", S_IFCHR|0600},
	{3, 0xa, "/dev/ttypa", S_IFCHR|0600},
	{3, 0xb, "/dev/ttypb", S_IFCHR|0600},
	{5, 0x2, "/dev/ptmx", S_IFCHR|0666},
	{5, 0x0, "/dev/tty", S_IFCHR|0666},
#ifdef VZ8
	/*
	 * In VZ8 we need at least one /dev/ttyN
	 * device for successfull installation of makedev
	 * during CT creation #PSBM-131188, making one
	 * /dev/tty0 implemented as /dev/null does the job
	 */
	{1, 0x3, "/dev/tty0", S_IFCHR|0620, "tty"},
#else
	{5, 0x1, "/dev/console", S_IFCHR|0600},
	{4, 0x0, "/dev/tty0", S_IFCHR|0620, "tty"},
	{4, 0x1, "/dev/tty1", S_IFCHR|0620, "tty"},
	{4, 0x2, "/dev/tty2", S_IFCHR|0620, "tty"},
	{4, 0x3, "/dev/tty3", S_IFCHR|0620, "tty"},
	{4, 0x4, "/dev/tty4", S_IFCHR|0620, "tty"},
	{4, 0x5, "/dev/tty5", S_IFCHR|0620, "tty"},
	{4, 0x6, "/dev/tty6", S_IFCHR|0620, "tty"},
	{4, 0x7, "/dev/tty7", S_IFCHR|0620, "tty"},
	{4, 0x8, "/dev/tty8", S_IFCHR|0620, "tty"},
	{4, 0x9, "/dev/tty9", S_IFCHR|0620, "tty"},
	{4, 0xa, "/dev/tty10", S_IFCHR|0620, "tty"},
	{4, 0xb, "/dev/tty11", S_IFCHR|0620, "tty"},
	{4, 0xc, "/dev/tty12", S_IFCHR|0620, "tty"},
#endif
	{1, 0x3, "/dev/null", S_IFCHR|0666},
	{1, 0x5, "/dev/zero", S_IFCHR|0666},
	{1, 0x7, "/dev/full", S_IFCHR|0666},
	{1, 0x8, "/dev/random", S_IFCHR|0666},
	{1, 0x9, "/dev/urandom", S_IFCHR|0666},
	{10, 235, "/dev/autofs", S_IFCHR|0600},
	{1, 11, "/dev/kmsg", S_IFCHR|0644},
};

static int setup_devtmpfs()
{
	int i, ret = 0;

	logger(10, 0, "Setup devtmpfs");

	if (mount("none", "/dev", "devtmpfs", MS_NOSUID|MS_STRICTATIME, "mode=755"))
		return vzctl_err(-1, errno, "Failed to mount devtmpfs");

	mode_t m = umask(000);
	for (i = 0; i < sizeof(_g_devs)/sizeof(_g_devs[0]); i++) {
		dev_t dev = makedev(_g_devs[i].major, _g_devs[i].minor);
		if (mknod(_g_devs[i].name, _g_devs[i].mode, dev) &&
				errno != EEXIST)
		{
			ret = vzctl_err(-1, errno, "Failed to create %s",
					_g_devs[i].name);
			break;
		}
		if (_g_devs[i].group) {
			struct group *g = getgrnam(_g_devs[i].group);
			if (g) {
				if (chown(_g_devs[i].name, 0, g->gr_gid))
					vzctl_err(-1, errno, "Failed to chown(%s, 0, %d)",
							_g_devs[i].name, g->gr_gid);
			}
		}
	}
	umask(m);

	return ret;
}

static void set_def_rlimits()
{
	int i;
	struct rlimit rl[] = {
		[RLIMIT_CPU]            = {RLIM_INFINITY, RLIM_INFINITY},
		[RLIMIT_FSIZE]          = {RLIM_INFINITY, RLIM_INFINITY},
		[RLIMIT_DATA]           = {RLIM_INFINITY, RLIM_INFINITY},
		[RLIMIT_STACK]          = {8*1024*1024, RLIM_INFINITY},
		[RLIMIT_CORE]           = {0,  RLIM_INFINITY},
		[RLIMIT_RSS]            = {RLIM_INFINITY,  RLIM_INFINITY},
		[RLIMIT_NPROC]          = {62987, 62987},
		[RLIMIT_NOFILE]         = {1024, 4096},
		[RLIMIT_MEMLOCK]        = {65536, 65536},
		[RLIMIT_AS]             = {RLIM_INFINITY, RLIM_INFINITY},
		[RLIMIT_LOCKS]          = {RLIM_INFINITY, RLIM_INFINITY},
	};

	for (i = 0; i < sizeof(rl)/ sizeof(rl[0]); i++)
	{
		if (setrlimit(i, &rl[i]))
			vzctl_err(-1, errno, "Failed setrlimit(%d)", i);
	}
}

int pre_setup_env(const struct start_param *param)
{
	struct vzctl_env_param *env = param->h->env_param;
	int fd;
	int ret;
	int errcode = 0;

	/* Clear supplementary group IDs */
	if (setgroups(0, NULL))
		return vzctl_err(VZCTL_E_SYSTEM, errno, "setgroups");

	errcode = set_personality32();
	if (errcode)
		return errcode;

	/* Create /fastboot to skip run fsck */
	fd = creat("/fastboot", 0644);
	if (fd != -1)
		close(fd);

	const char *hn = env->misc->hostname ?: "localhost.localdomain";
	if (sethostname(hn, strlen(hn)))
		return vzctl_err(VZCTL_E_SYSTEM, errno, "Failed to set hostname %s", hn);

	if (access("/proc", F_OK) == 0 && mount("proc", "/proc", "proc", 0, 0))
		return vzctl_err(VZCTL_E_SYSTEM, errno, "Failed to mount /proc");
	if (create_venet_link())
		return vzctl_err(VZCTL_E_SYSTEM, 0, "Unable to create venet iface");

	if (setup_devtmpfs())
		return VZCTL_E_SYSTEM;

	if (stat_file("/sys"))
		mount("sysfs", "/sys", "sysfs", 0, 0);

	if (env->features->mask & VE_FEATURE_NFSD) {
		mount("nfsd", "/proc/fs/nfsd", "nfsd", 0, 0);
		make_dir("/var/lib/nfs/rpc_pipefs", 1);
		mount("sunrpc", "/var/lib/nfs/rpc_pipefs", "rpc_pipefs", 0, 0);
	}

	clean_static_dev("ploop");
	create_root_dev(NULL);
	unlink("/reboot");
	unlink(VZFIFO_FILE);
	if (env->fs->layout >= VZCTL_LAYOUT_5)
		restore_mtab();

	if (env->dq->ugidlimit != NULL && *env->dq->ugidlimit != 0) {
		ret = setup_env_quota(get_user_quota_mode(env->dq));
		if (ret)
			return ret;
	}

	if (env->fs->layout == VZCTL_LAYOUT_5 && env->disk != NULL &&
			!is_secondary_disk_present(env->disk))
	{
		env_fin_configure_disk(env->disk);
	}

	if (env->opts->wait == VZCTL_PARAM_ON &&
			replace_reach_runlevel_mark())
		return VZCTL_E_WAIT;

	if (env_configure_udev_rules())
		return VZCTL_E_SYSTEM;

	configure_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "0");

	logger(10, 0, "* Report env_created");
	/* report that environment is created. */
	if (write(param->h->ctx->status_p[1], &errcode, sizeof(errcode)) == -1)
		 vzctl_err(-1, errno, "Failed write(param->status_p[1])");

	logger(10, 0, "* Wait parent");
	/* Now we wait until Container setup will be done
	 * If no error, then start init, otherwise exit.
	 */
	if (TEMP_FAILURE_RETRY(read(param->h->ctx->wait_p[0], &errcode, sizeof(errcode))) == 0) {
		logger(0, 0, "Cancel init execution");
		return -1;
	}

	logger(10, 0, "* Setup done");
	if ((fd = open("/dev/null", O_WRONLY)) != -1) {
		dup2(fd, 0);
		dup2(fd, 1);
		dup2(fd, 2);
		close(fd);
	}

	if (param->pseudosuper_fd != -1) {
		ret = cg_disable_pseudosuper(param->pseudosuper_fd);
		if (ret) {
			close(param->pseudosuper_fd);
			return ret;
		}
	}

	close_fds(0, param->h->ctx->err_p[1], -1);

	return 0;
}

char **makeenv(char **env, list_head_t *head)
{
	struct vzctl_str_param *it;
	char **ar;
	int i;

	for (i = 0; env != NULL && env[i] != NULL; i++);
	list_for_each(it, head, list) { i++; }

	ar = calloc(1, (i + 1) * sizeof(char *));
	if (ar == NULL) {
		logger(-1, ENOMEM, "makeenv");
		return NULL;
	}
	for (i = 0; env != NULL && env[i] != NULL; i++) {
		if (xstrdup(&ar[i], env[i]))
			goto err;
	}
	list_for_each(it, head, list) {
		if (xstrdup(&ar[i++], it->str))
			goto err;
	}
	ar[i] = NULL;

	return ar;

err:
	free_ar_str(ar);
	free(ar);
	logger(-1, ENOMEM, "makeenv");
	return NULL;

}

int exec_init(const struct start_param *param)
{
	char cid[STR_SIZE];
	char *argv[] = {"init", "-z", "      ", NULL};
	char *envp[] = {"HOME=/", "TERM=linux", cid, NULL};
	char **env;
	int errcode = 0;
	logger(1, 0, "Starting init");

	if (stat_file("/sbin/init") == 0 &&
			stat_file("/bin/init") == 0)
		errcode = VZCTL_E_BAD_TMPL;

	if (write(param->h->ctx->err_p[1], &errcode, sizeof(errcode)) == -1)
		logger(-1, errno, "exec_init: write(param->h->ctx->err_p[1]");

	snprintf(cid, sizeof(cid), "container="SYSTEMD_CTID_FMT, EID(param->h));
	env = makeenv(envp, &param->h->env_param->misc->ve_env);
	if (env == NULL)
		return VZCTL_E_NOMEM;

	setsid();
	set_def_rlimits();

	execve("/sbin/init", argv, env);
	execve("/bin/init", argv, env);
	free_ar_str(env);
	free(env);

	return VZCTL_E_BAD_TMPL;
}

int read_p(int fd)
{
	int rc, errcode;

	rc = TEMP_FAILURE_RETRY(read(fd, &errcode, sizeof(errcode)));
	if (rc == -1)
		return vzctl_err(VZCTL_E_SYSTEM, errno, "Read from pipe failed");
	else if (rc == 0)
		return vzctl_err(VZCTL_E_SYSTEM, 0, "Error pipe unexpectedly closed");
	else if (errcode != 0)
		return errcode;

	return 0;
}

static int drop_dump_state(struct vzctl_env_handle *h)
{
	char fname[PATH_MAX];

	vzctl2_get_dump_file(h,	fname, sizeof(fname));

	return destroydir(fname);
}

/** Start and configure Container. */
int vzctl_env_start(struct vzctl_env_handle *h, int flags)
{
	int ret;
	struct vzctl_env_param *env = h->env_param;
	struct vzctl_env_status env_status = {};
	char *cidata_mnt = NULL;
	struct start_param param = {
		.h = h,
		.pseudosuper_fd = -1,
	};

	/* FIXME: */
	if (flags & VZCTL_WAIT)
		env->opts->wait = VZCTL_PARAM_ON;

	vzctl2_get_env_status_info(h, &env_status, ENV_STATUS_RUNNING);
	if (env_status.mask & ENV_STATUS_RUNNING) {
		if (!(env_status.mask & ENV_STATUS_CPT_SUSPENDED))
			return vzctl_err(VZCTL_E_ENV_RUN, 0,
				"Container is already running");

		logger(0, 0, "Unpause the Container");

		struct vzctl_cpt_param cpt = {};
		ret = vzctl2_cpt_cmd(h, 0, VZCTL_CMD_RESUME, &cpt, flags);
		if (ret)
			logger(-1, 0, "Unable to unpause the Container");
		else
			logger(0, 0, "The Container has been successfully unpaused");
	
		return ret;
	}

	logger(0, 0, "Starting Container ...");

	ret = ha_sync(h, flags);
	if (ret)
		return ret;

	/* check requred parameters for start */
	ret = check_requires(env, flags);
	if (ret)
		return ret;

	ret = init_runtime_ctx(h->ctx);
	if (ret)
		return ret;

        ret = get_virt_osrelease(h);
        if (ret)
		goto err_pipe;

	if (h->env_param->opts->cidata_fname) {
		ret = setup_cloud_init_data(h, h->env_param->opts->cidata_fname,
				&cidata_mnt);
		if (ret)
			goto err_pipe;
	}

	h->ctx->state = VZCTL_STATE_STARTING;
	if (flags & VZCTL_ENV_START_REPAIR)
	{
		ret = repair_start(h);
		if (ret)
			goto err_pipe;
	}

	if (!(flags & VZCTL_SKIP_MOUNT)) {
		/* If Container mounted umount first to cleanup mount state */
		if (vzctl2_env_is_mounted(h)) {
			ret = vzctl2_env_umount(h, flags);
			if (ret) {
				if (ret != VZCTL_E_UMOUNT_BUSY)
					goto err_pipe;
				flags |= VZCTL_FORCE;
			}
		}

		ret = vzctl2_env_mount(h, flags);
		if (ret)
			goto err_pipe;
	}

	if (!(flags & VZCTL_SKIP_SETUP)) {
		if ((ret = run_start_script(h)))
			goto err_pipe;
	}

	fix_param(env);

	if ((ret = get_env_ops()->env_create(h, &param)))
		goto err;

	logger(10, 0, "* env_create ret=%d ", ret);
	close(h->ctx->wait_p[0]); h->ctx->wait_p[0] = -1;
	close(h->ctx->err_p[1]); h->ctx->err_p[1] = -1;

	if (!(flags & VZCTL_SKIP_SETUP)) {
		ret = vzctl2_apply_param(h, env, flags);
		if (ret)
			goto err;
	}
	if (flags & VZCTL_ENV_START_REPAIR) {
		ret = repair_configure(h);
		if (ret)
			goto err;
	}

	if (!(flags & VZCTL_SKIP_ACTION_SCRIPT)) {
		char buf[PATH_MAX];

		get_action_script_path(h, VZCTL_START_PREFIX, buf, sizeof(buf));
		if (stat_file(buf) &&
			vzctl2_wrap_env_exec_script(h, NULL, NULL, buf, 0, EXEC_LOG_OUTPUT))
		{
			ret = vzctl_err(VZCTL_E_ACTIONSCRIPT, 0, "Error executing"
					" start script %s", buf);
			goto err;
		}
	}

	ret = 0;
	logger(10, 0, "* Report to parent to continue");
	if (write(h->ctx->wait_p[1], &ret, sizeof(ret)) == -1)
		ret = vzctl_err(VZCTL_E_SYSTEM, errno,
			"Unable to write to the wait file descriptor when starting the Container");
	if (ret)
		goto err;

	close(h->ctx->wait_p[1]); h->ctx->wait_p[1] = -1;

	h->ctx->state = 0;

	ret = read_p(h->ctx->err_p[0]);
	if (ret) {
		if (ret == VZCTL_E_BAD_TMPL)
			logger(-1, 0, "Unable to start init,"
					" probably incorrect template");
		goto err;
	}
	close(h->ctx->err_p[0]); h->ctx->err_p[0] = -1;

	if (env->opts->wait == VZCTL_PARAM_ON) {
		logger(0, 0, "Container start in progress"
				", waiting ...");
		ret = vzctl_env_exec_fn(h, wait_on_fifo, NULL, 0);
		if (ret) {
			logger(-1, 0, "Failed to start the Container%s",
					ret == VZCTL_E_EXEC_TIMEOUT ? \
					": timeout expired" : "");
			ret = VZCTL_E_WAIT_FAILED;
			goto err;
		}
		logger(0, 0, "Container was started"
				" successfully");
	} else
		logger(0, 0, "Container start in progress...");

	vzctl2_register_running_state(h->env_param->fs->ve_private);
	drop_dump_state(h);

err:
	if (ret) {
		if (dump_resources_failcnt(EID(h)))
			ret = VZCTL_E_RESOURCE;

		logger(10, 0, "* Failed to configure [%d]", ret);
		/* report error to waiter */
		if (h->ctx->wait_p[1] != -1 && close(h->ctx->wait_p[1]))
			logger(4, errno, "Failed to close wait pipe");

		wait_env_state(h, VZCTL_ENV_STOPPED, 5);

		if (is_env_run(h) == 1)
			vzctl2_env_stop(h, M_KILL, flags);

		if (vzctl2_env_is_mounted(h))
			vzctl2_env_umount(h, flags);

		logger(-1, 0, "Failed to start the Container");
	}

	if (param.pid > 0)
		env_wait(param.pid, 0, NULL);

err_pipe:
	if (ret && (flags & VZCTL_ENV_START_REPAIR))
		repair_finish(h);

	deinit_runtime_ctx(h->ctx);
	if (cidata_mnt) {
		umount(cidata_mnt);
		free(cidata_mnt);
	}

	return ret;
}

int vzctl2_env_start(struct vzctl_env_handle *h, int flags)
{
	if (vzctl2_get_flags() & VZCTL_FLAG_DONT_USE_WRAP)
		return vzctl_env_start(h, flags);

	return vzctl_wrap_env_start(h, flags);
}

int vzctl_env_chkpnt(struct vzctl_env_handle *h, int cmd,
		struct vzctl_cpt_param *param, int flags)
{
	int ret, lfd;

	if (!is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_NOT_RUN, 0, "Container is not running");

	if (cmd != VZCTL_CMD_CHKPNT || param->flags & VZCTL_CPT_CREATE_DEVMAP)
		return vzctl2_cpt_cmd(h, VZCTL_CMD_CHKPNT, cmd, param, flags);

	logger(0, 0, "Setting up checkpoint...");
	/* Deny to enter on SUSPEND stage */
	lfd = get_enter_lock(h);

	if ((ret = get_env_ops()->env_chkpnt(h, cmd, param, flags)))
		goto end;

	/* Dumped processes can live for a while after dump return success due to
	criu bug. Wait some time for dumped processes termination. */
	vzctl2_unregister_running_state(h->env_param->fs->ve_private);
	wait_env_state(h, VZCTL_ENV_STOPPED, 5);

	do_env_post_stop(h, flags);
end:

	if (ret)
		logger(-1, 0, "Checkpointing failed");
	else {
		vzctl2_send_state_evt(EID(h), VZCTL_ENV_SUSPENDED);
		logger(0, 0, "Checkpointing completed successfully");
	}

	release_enter_lock(lfd);

	return ret;
}

int vzctl2_env_chkpnt(struct vzctl_env_handle *h, int cmd,
		struct vzctl_cpt_param *param, int flags)
{
	if (vzctl2_get_flags() & VZCTL_FLAG_DONT_USE_WRAP)
		return vzctl_env_chkpnt(h, cmd, param, flags);

	return vzctl_wrap_env_chkpnt(h, cmd, param, flags);
}

static int _announce_ips(pid_t pid)
{
	char script_bin[PATH_MAX];
	char ve_root_via_proc[PATH_MAX];
	char *arg[] = {script_bin, ve_root_via_proc, NULL};
	
	get_script_path(VZCTL_ANNOUNCE_IPS, script_bin, sizeof(script_bin));
	snprintf(ve_root_via_proc, sizeof(ve_root_via_proc),
			"/proc/%d/root", pid);

	return vzctl2_wrap_exec_script(arg, NULL, 0);
}

static int announce_ips(struct vzctl_env_handle *h)
{
	int ret;
	pid_t ct_pid, pid;

	pid = fork();
	if (pid == 0) {
		ret = enter_net_ns(h, &ct_pid);
		if (ret == 0)
			ret = _announce_ips(ct_pid);

		_exit(ret);
	} else if (pid < 0)
		return vzctl_err(-1, errno, "Unable to fork!\n");

	return env_wait(pid, 0, NULL);
}

int vzctl_env_restore(struct vzctl_env_handle *h,
		struct vzctl_cpt_param *param, int flags)
{
	int ret, rc;
	struct vzctl_env_param *env = h->env_param;
	struct start_param start_param = {
		.h = h,
		.pseudosuper_fd = -1,
	};
	char dumpfile[PATH_MAX];

	if (param->cmd != VZCTL_CMD_RESTORE)
		return vzctl2_cpt_cmd(h, VZCTL_CMD_RESTORE, param->cmd, param, flags);

	flags |= VZCTL_SKIP_CONFIGURE | VZCTL_RESTORE;
	if (is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_RUN, 0,
				"Container is already running");
	vzctl2_get_dump_file(h, dumpfile, sizeof(dumpfile));
	if (stat_file(param->dumpfile ?: dumpfile) != 1)
			return vzctl_err(VZCTL_E_RESTORE, 0,
					"Container is not suspended");
		
	logger(0, 0, "Restoring the Container ...");

	ret = ha_sync(h, flags);
	if (ret)
		return ret;

	/* check requred parameters for start */
	ret = check_requires(env, flags);
	if (ret)
		return ret;

	ret = init_runtime_ctx(h->ctx);
	if (ret)
		return ret;

	/* If Container mounted umount first to cleanup mount state */
	if (vzctl2_env_is_mounted(h))
		vzctl2_env_umount(h, flags);

	h->ctx->state = VZCTL_STATE_STARTING;
	if (!vzctl2_env_is_mounted(h)) {
		/* increase quota to perform initial setup */
		if ((ret = vzctl2_env_mount(h, flags)))
			goto err_pipe;
	}

	if (!(flags & VZCTL_SKIP_SETUP)) {
		if ((ret = run_start_script(h)))
			goto err_pipe;
	}

	fix_param(env);

	ret = get_env_ops()->env_restore(h, &start_param, param, flags);
	if (ret)
		goto err;

	logger(10, 0, "* post-restore");

	if (!(flags & VZCTL_SKIP_SETUP)) {
		ret = vzctl2_apply_param(h, env, flags);
		if (ret)
			goto err;
	}

	if (!(flags & VZCTL_SKIP_ACTION_SCRIPT)) {
		char buf[PATH_MAX];

		get_action_script_path(h, VZCTL_START_PREFIX, buf, sizeof(buf));
		if (stat_file(buf) &&
			vzctl2_wrap_env_exec_script(h, NULL, NULL, buf, 0, EXEC_LOG_OUTPUT))
		{
			ret = vzctl_err(VZCTL_E_ACTIONSCRIPT, 0, "Error executing"
					" start script %s", buf);
			goto err;
		}
	}

	logger(10, 0, "* Continue post-restore action script");
	ret = 0;
	if (write(h->ctx->wait_p[1], &ret, sizeof(ret)) == -1)
		ret = vzctl_err(VZCTL_E_SYSTEM, errno, "Unable to write to the"
				" wait fd when post-restore the Container");
	if (ret)
		goto err;

	close(h->ctx->wait_p[1]); h->ctx->wait_p[1] = -1;

	h->ctx->state = 0;

	logger(10, 0, "* Wait on error pipe");
	ret = read_p(h->ctx->err_p[0]);
	if (ret) {
		logger(-1, 0, "Error %d reported from restore", ret);
		goto err;
	}
	close(h->ctx->err_p[0]); h->ctx->err_p[0] = -1;

	if (param->cmd == VZCTL_CMD_RESTORE && param->dumpfile == NULL)
		drop_dump_state(h);

	vzctl2_register_running_state(h->env_param->fs->ve_private);
	announce_ips(h);
	ret = 0;

err:
	if (ret) {
		if (dump_resources_failcnt(EID(h)))
			ret = VZCTL_E_RESOURCE;

		logger(10, 0, "* Failed to configure [%d]", ret);
		/* report error to waiter */
		if (h->ctx->wait_p[1] != -1) {
			if (close(h->ctx->wait_p[1]))
				logger(4, errno, "Failed to close wait pipe");
			h->ctx->wait_p[1] = -1;
		}
	}

	if (start_param.pid > 0) {
		if (env_wait(start_param.pid, 0, &rc))
			ret = VZCTL_E_SYSTEM;
		else if (rc)
			ret = vzctl_err(VZCTL_E_RESOURCE, 0,
				"criu exited with rc=%d", rc);
	}

	if (ret) {
		if (is_env_run(h))
			vzctl_env_stop(h, M_KILL, 0);
		else
			/* kill processes in the VE cgroup #PSBM-79465 */
			ns_env_kill(h);

		if (vzctl2_env_is_mounted(h))
			vzctl2_env_umount(h, flags);
		logger(-1, 0, "Failed to restore the Container");
	} else
		logger(0, 0, "Container was restored successfully");

err_pipe:
	deinit_runtime_ctx(h->ctx);

	return ret;
}

int vzctl2_env_restore(struct vzctl_env_handle *h,
		struct vzctl_cpt_param *param, int flags)
{
	if (vzctl2_get_flags() & VZCTL_FLAG_DONT_USE_WRAP)
		return vzctl_env_restore(h, param, flags);

	return vzctl_wrap_env_restore(h, param, flags);
}

int vzctl2_env_restart(struct vzctl_env_handle *h, int flags)
{
	int ret;

	logger(0, 0, "Restart the Container");
	if (is_env_run(h)) {
		ret = vzctl2_env_stop(h, M_HALT, flags);
		if (ret)
			return ret;
	}
	return vzctl2_env_start(h, flags);
}

int is_quotaugidlimit_changed(struct vzctl_env_handle *h,
		unsigned long ugidlimit)
{
	FILE *fp;
	struct mntent *ent, mntbuf;
	char dev[64];
	char tmp[PATH_MAX];
	int configured = 0;

	if (vzctl2_get_ploop_dev_by_mnt(h->env_param->fs->ve_root, dev, sizeof(dev)))
		return -1;

	fp = fopen("/proc/mounts", "r");
	if (fp == NULL)
		return vzctl_err(-1, errno, "Can't open /proc/mounts");
	while ((ent = getmntent_r(fp, &mntbuf, tmp, sizeof(tmp)))) {
		if (!strcmp(dev, ent->mnt_fsname)) {
			if (ent->mnt_opts != NULL &&
					strstr(ent->mnt_opts, "quota"))
				configured = 1;
			break;
		}
	}
	fclose(fp);

	return (configured != (ugidlimit > 0));
}

static void drom_ext_attr(const char *fname)
{
	int fd, f = 0;

	fd = open(fname, O_RDONLY);
	if (fd == -1)
		return;

	if (ioctl(fd, EXT2_IOC_SETFLAGS, &f) && errno != ENOTSUP)
		vzctl_err(-1, errno, "drom_ext_attr %s", fname);

	close(fd);
}

static int drop_quotaugidlimit(struct vzctl_env_handle *h)
{
	int ret;
	char buf[PATH_MAX];
	const char *ve_root = h->env_param->fs->ve_root;
	int mounted = vzctl2_env_is_mounted(h);

	logger(3, 0, "Drop user quota limits");
	if (!mounted) {
		ret = vzctl2_env_mount(h, VZCTL_SKIP_ACTION_SCRIPT);
		if (ret)
			return ret;
	}

	snprintf(buf, sizeof(buf), "%s/"QUOTA_U, ve_root);
	drom_ext_attr(buf);
	if (unlink(buf) && errno != EEXIST)
		logger(-1, errno, "Failed to unlink %s", buf);

	snprintf(buf, sizeof(buf), "%s/"QUOTA_G, ve_root);
	drom_ext_attr(buf);
	if (unlink(buf) && errno != EEXIST)
		logger(-1, errno, "Failed to unlink %s", buf);

	if (!mounted)
		vzctl2_env_umount(h, VZCTL_SKIP_ACTION_SCRIPT);

	return 0;
}

static int check_setmode(struct vzctl_env_handle *h, struct vzctl_env_param *env)
{
	int ret = 0;

	if (!is_env_run(h))
		return 0;

	if (env->dq->ugidlimit != NULL) {
		unsigned long ugidlimit = *env->dq->ugidlimit;
		if (is_quotaugidlimit_changed(h, ugidlimit)) {
			ret = ugidlimit ? VZCTL_E_DQ_UGID_NOTINIT : VZCTL_E_ENV_RUN;
			if (ret) {
				if (ugidlimit)
					logger(-1, 0, "Unable to turn ugid quota on:"
							" quota is not initialized");
				else
					logger(-1, 0, "Unable to turn ugid quota off"
							" for the running Container");
			}
		}
	}

	if (env->dq->journaled_quota != 0 &&
			h->env_param->dq->journaled_quota != env->dq->journaled_quota)
		ret = vzctl_err(VZCTL_E_ENV_RUN, 0, "Unable to change quota mode"
				" for the running Container");
	if (env->features->nf_mask &&
			env->features->nf_mask != h->env_param->features->nf_mask)
		ret = vzctl_err(VZCTL_E_ENV_RUN, 0, "Unable to set"
                                                " netfilter for the running Container");
	else if (env->features->ipt_mask)
		ret = vzctl_err(VZCTL_E_ENV_RUN, 0, "Unable to set"
                                                " iptables for the running Container");

	if (env->features->known)
		ret = vzctl_err(VZCTL_E_ENV_RUN, 0, "Unable to set"
                                                " features for the running Container");

	if (env->cap->on || env->cap->off)
		ret = vzctl_err(VZCTL_E_ENV_RUN, 0, "Unable to set the capability"
					" for the running Container");
	return ret;
}

int vzctl2_apply_param(struct vzctl_env_handle *h, struct vzctl_env_param *env,
		int flags)
{
	int ret = 0;
	int setmode_err = 0;
	int run;

	ret = merge_veth_ifname_param(h, env);
	if (ret)
		return ret;

	if (flags & VZCTL_SKIP_SETUP)
		goto err;

	run = is_env_run(h);
	if (h->ctx->state == 0 && run)
		h->ctx->state = VZCTL_STATE_RUNNING;

	if (h->ctx->state != VZCTL_STATE_STARTING) {
		setmode_err = check_setmode(h, env);
		if (setmode_err) {
			if (env->opts->setmode == VZCTL_SET_RESTART) {
				vzctl2_merge_env_param(h, env);
				ret = vzctl2_env_restart(h, 0);
				goto err;
			} else if (env->opts->setmode == VZCTL_SET_NONE) {
				ret = vzctl_err(setmode_err, 0, "WARNING: Some of the parameters could"
						" not be applied to a running container.\n"
						"\tPlease consider using --setmode option");
				goto err;
			}
		}
	}

	ret = get_env_ops()->env_apply_param(h, env, flags);
	if (ret)
		goto err;

	if (h->ctx->state != VZCTL_STATE_STARTING) {
		if (env->opts->ha_prio || env->opts->ha_enable) {
			struct ha_params p = {
				.ha_enable = env->opts->ha_enable,
				.ha_prio = env->opts->ha_prio,
			};
			struct ha_params c = {
				.ha_enable = h->env_param->opts->ha_enable,
				.ha_prio = h->env_param->opts->ha_prio,
			};

			ret = handle_set_cmd_on_ha_cluster(EID(h),
					h->env_param->fs->ve_private, &p, &c);
			if (ret) {
				/* Dont save parameter on error */
				free(env->opts->ha_prio);
				env->opts->ha_prio = NULL;
				env->opts->ha_enable = 0;
				goto err;
			}
		}


		if (!list_empty(&env->bindmount->mounts) && run) {
			ret = vzctl2_bind_mount(h, env->bindmount, 1);
			if (ret)
				goto err;
		}
		if (!run && env->dq->ugidlimit && *env->dq->ugidlimit == 0 &&
			h->env_param->dq->ugidlimit && *h->env_param->dq->ugidlimit)
		{
			ret = drop_quotaugidlimit(h);
			if (ret)
				goto err;
		}

		if (h->env_param->fs->layout == VZCTL_LAYOUT_5 &&
			env->dq->diskspace != NULL &&
			(ret = vzctl2_resize_image(h->env_param->fs->ve_private,
							  env->dq->diskspace->l, 0)))
		{
			free(env->dq->diskspace);
			env->dq->diskspace = NULL;
			goto err;
		}
	}
	ret = setmode_err;

err:
	merge_env_param(h, env, NULL, flags);

	// FIXME: merge param
	if (flags & VZCTL_SAVE) {
		if (vzctl2_env_save(h) == 0)
			logger(0, 0, "Saved parameters for Container");
	}

	return ret;
}

static int env_set_userpasswd(struct vzctl_env_handle *h, const char *user,
		const char *passwd, int flags)
{
	int i, ret;
	struct vzctl_env_param *env;
	int running;
	int was_mounted = 0;
	struct start_param param = {
		.h = h,
		.pseudosuper_fd = -1,
	};

	env = vzctl2_get_env_param(h);

	running = is_env_run(h);

	if (!running) {
		/* check requred parameters for start */
		if ((ret = check_requires(env, 0)))
			return ret;
		logger(0, 0, "Starting Container ...");
		if (!vzctl2_env_is_mounted(h)) {
			ret = vzctl2_env_mount(h, 0);
			if (ret)
				return ret;
			was_mounted = 1;
		}

		ret = init_runtime_ctx(h->ctx);
		if (ret)
			goto out;
		h->ctx->state = VZCTL_STATE_STARTING;
		if ((ret = get_env_ops()->env_create(h, &param)))
			goto out;
		close(h->ctx->wait_p[0]); h->ctx->wait_p[0] = -1;
		close(h->ctx->err_p[1]); h->ctx->err_p[1] = -1;
	}

	ret = env_pw_configure(h, user, passwd, flags);
out:
	if (!running) {
		/* Destroy env */
		close(h->ctx->wait_p[1]); h->ctx->wait_p[1] = -1;
		for (i = 0; i < 100; i++) {
			if (!is_env_run(h))
				break;
			usleep(100000);
		}

		if (was_mounted)
			vzctl2_env_umount(h, 0);

		deinit_runtime_ctx(h->ctx);
	}

	return ret;
}

int vzctl2_env_set_userpasswd(struct vzctl_env_handle *h, const char *user,
		const char *passwd, int flags)
{
	return env_set_userpasswd(h, user, passwd, flags);
}

static struct vzctl_runtime_ctx *alloc_runtime_ctx(void)
{
	struct vzctl_runtime_ctx *x;

	x = calloc(1, sizeof(struct vzctl_runtime_ctx));
	if (x == NULL) {
		vzctl_err(VZCTL_E_NOMEM, ENOMEM, "alloc_runtime_ctx");
		return NULL;
	}

	x->pid = -1;
	x->wait_p[0] = -1;
	x->wait_p[1] = -1;
	x->err_p[0] = -1;
	x->err_p[1] = -1;
	x->status_p[0] = -1;
	x->status_p[1] = -1;

	return x;
}

static void free_runtime_ctx(struct vzctl_runtime_ctx *ctx)
{
	deinit_runtime_ctx(ctx);
	free(ctx);
}

static void vzctl_free_env_handle(struct vzctl_env_handle *h)
{
	if (h == NULL)
		return;

	vzctl2_free_env_param(h->env_param);
	free_dist_action(h->dist_actions);
	vzctl2_conf_close(h->conf);
	free_runtime_ctx(h->ctx);
	free(h);
}

struct vzctl_env_handle *vzctl2_alloc_env_handle()
{
	struct vzctl_env_handle *h;

	if ((h = calloc(1, sizeof(struct vzctl_env_handle))) == NULL) {
		vzctl_err(VZCTL_E_NOMEM, ENOMEM, "vzctl2_alloc_env_handle");
		return NULL;
	}
	if ((h->env_param = vzctl2_alloc_env_param()) == NULL)
		goto err;
	if ((h->conf = alloc_conf()) == NULL)
		goto err;
	if ((h->ctx = alloc_runtime_ctx()) == NULL)
		goto err;

	return h;
err:
	vzctl_free_env_handle(h);
	return NULL;
}

void vzctl2_env_close(struct vzctl_env_handle *h)
{
	return vzctl_free_env_handle(h);
}

struct vzctl_env_param *vzctl2_get_env_param(struct vzctl_env_handle *h)
{
	return h->env_param;
}

static int ctid2veid(ctid_t ctid, int *veid)
{
	unsigned int id;

	if (sscanf(ctid, strlen(ctid) < 36 ? "%u" : "%x-", &id) != 1)
		return vzctl_err(VZCTL_E_INVAL, 0,
			"Unable to convert ctid=%s to veid: invalid format",
			ctid);

	*veid = id & 0x7fffffff;

	return 0;
}

struct vzctl_env_handle *vzctl2_env_open_conf(const ctid_t ctid,
		const char *fname, int flags, int *err)
{
	int lckfd = -1;
	struct vzctl_env_handle *h;

	*err = VZCTL_E_NOMEM;
	if ((h = vzctl2_alloc_env_handle()) == NULL)
		return NULL;

	if (ctid && !EMPTY_CTID(ctid)) {
		*err = vzctl2_parse_ctid(ctid, EID(h));
		if (*err) {
			*err = vzctl_err(VZCTL_E_INVAL, 0, "Invalid CTID: %s", ctid);
			goto err;
		}

		*err = ctid2veid(EID(h), &h->veid);
		if (*err)
			goto err;
	}

	flags |= VZCTL_CONF_PARAM;
	if (flags & VZCTL_CONF_SKIP_PARSE)
		goto out;

	lckfd = vzctl_env_conf_lock(h, VZCTL_LOCK_SH);
	*err = conf_parse(h->conf, fname, flags);
	if (*err)
		goto err;

	*err = vzctl_update_env_param(h, flags);
	if (*err)
		goto err;

	*err = 0;
out:
	vzctl_env_conf_unlock(lckfd);
	return h;
err:
	vzctl_env_conf_unlock(lckfd);
	vzctl_free_env_handle(h);
	return NULL;
}

int get_cid_uuid_pair(const char *ctid, const char *uuid,
		ctid_t ctid_out, ctid_t uuid_out)
{
	int n;

	if (ctid == NULL)
		return VZCTL_E_INVAL;

	/* autogenerated 
	 * CTID = UUID
	 */
	if (EMPTY_CTID(ctid)) {
		vzctl2_generate_ctid(ctid_out);
		SET_CTID(uuid_out, ctid_out);
		return 0;
	}

	/* Basic CTID schema
	 * CTID =UUID
	 */
	if (vzctl2_get_normalized_uuid(ctid, ctid_out, sizeof(ctid_t)) == 0) {
		if (uuid != NULL) {
			if (vzctl2_get_normalized_uuid(uuid, uuid_out, sizeof(ctid_t)))
				return vzctl_err(VZCTL_E_INVAL, 0, "Invalid uuid: %s", uuid);
		} else
			SET_CTID(uuid_out, ctid_out);

		return 0;
	}

	/* compability CTID schema
	 * CTID: VEID
	 * UUID: uuid
	 */
	if (parse_int(ctid, &n) || n < 0)
		return VZCTL_E_INVAL;

	snprintf(ctid_out, sizeof(ctid_t), "%d", n);
	if (uuid != NULL) {
		if (vzctl2_get_normalized_uuid(uuid, uuid_out, sizeof(ctid_t)))
			return vzctl_err(VZCTL_E_INVAL, 0, "Invalid uuid %s",
					uuid);
	} else
		vzctl2_generate_ctid(uuid_out);

	return 0;
}

int vzctl2_parse_ctid(const char *in, ctid_t out)
{
	ctid_t t;

	if (EMPTY_CTID(in))
		return VZCTL_E_INVAL;

	return get_cid_uuid_pair(in, NULL, out, t);
}

struct vzctl_env_handle *vzctl2_env_open(const char *ctid, int flags, int *err)
{
	char fname[PATH_MAX];
	ctid_t id;

	if (vzctl2_parse_ctid(ctid, id)) {
		*err = vzctl_err(VZCTL_E_INVAL, 0, "Invalid CTID: %s", ctid);
		return NULL;
	}

	vzctl2_get_env_conf_path(id, fname, sizeof(fname));
	return vzctl2_env_open_conf(id, fname, flags, err);
}

int vzctl2_env_save_conf(struct vzctl_env_handle *h, const char *fname)
{
	int ret;
	char path[4096];
	int lckfd = -1;

	if (fname == NULL)
		vzctl2_get_env_conf_path(EID(h), path, sizeof(path));
	else
		snprintf(path, sizeof(path), "%s", fname);

	lckfd = vzctl_env_conf_lock(h, VZCTL_LOCK_EX);
	ret = vzctl2_conf_save(h->conf, path);
	vzctl_env_conf_unlock(lckfd);
	if (ret == 0)
		vzctl2_send_state_evt(EID(h), VZCTL_ENV_CONFIG_CHANGED);

	return ret;
}

static void restore_config_link(struct vzctl_env_handle *h)
{
	struct stat st;
	char conf[PATH_MAX];
	char dst_tmp[PATH_MAX];
	char dst[PATH_MAX];
	const char *ve_private = h->env_param->fs->ve_private;

	if (h->env_param->fs->layout < VZCTL_LAYOUT_4 ||
			EID(h) == 0 ||
			ve_private == NULL)
		return;

	vzctl2_get_env_conf_path(EID(h), conf, sizeof(conf));
	if (lstat(conf, &st))
		return;

	if (S_ISLNK(st.st_mode))
		return;

	logger(-1, 0, "Inconsistent Container configuration is detected:"
			" restoring link...");
	snprintf(dst_tmp, sizeof(dst_tmp), "%s/"VZCTL_VE_CONF".tmp", ve_private);
	unlink(dst_tmp);
	if (cp_file(conf, dst_tmp))
		return;

	snprintf(dst, sizeof(dst), "%s/"VZCTL_VE_CONF, ve_private);
	if (rename(dst_tmp, dst)) {
		unlink(dst_tmp);
		return;
	}

	unlink(conf);
	if (symlink(dst, conf))
		logger(-1, errno, "Unable to create symlink %s %s", dst, conf);
}

int vzctl2_env_save(struct vzctl_env_handle *h)
{
	restore_config_link(h);
	return vzctl2_env_save_conf(h, NULL);
}

int vzctl2_env_set_cpuunits(struct vzctl_env_param *env, unsigned long units)
{
	struct vzctl_cpu_param *cpu = env->cpu;

	if (units < MINCPUUNITS || units > MAXCPUUNITS)
		return VZCTL_E_INVAL;

	if (cpu->units == NULL) {
		cpu->units = malloc(sizeof(*cpu->units));
		if (cpu->units == NULL)
			return VZCTL_E_NOMEM;
	}
	*cpu->units = units;

	return 0;
}

int vzctl2_env_get_cpuunits(struct vzctl_env_param *env, unsigned long *units)
{
	struct vzctl_cpu_param *cpu = env->cpu;

	if (cpu->units == NULL)
		return VZCTL_E_NOT_INITIALIZED;

	*units = *cpu->units;

	return 0;
}

int vzctl2_env_set_cpulimit(struct vzctl_env_param *env, struct vzctl_cpulimit_param *res)
{
	return vzctl_parse_cpulimit(env->cpu, res);
}

int vzctl2_env_get_cpulimit(struct vzctl_env_param *env, struct vzctl_cpulimit_param *res)
{
	struct vzctl_cpu_param *cpu = env->cpu;

	if (cpu->limit_res == NULL)
		return VZCTL_E_NOT_INITIALIZED;

	memcpy(res, cpu->limit_res, sizeof(struct vzctl_cpulimit_param));

	return 0;
}

int vzctl2_env_set_diskspace(struct vzctl_env_param *env, struct vzctl_2UL_res *res)
{
	struct vzctl_dq_param *dq = env->dq;

	if (dq->diskspace == NULL) {
		dq->diskspace = malloc(sizeof(*dq->diskspace));
		if (dq->diskspace == NULL)
			return VZCTL_E_NOMEM;
	}
	dq->diskspace->b = res->b;
	dq->diskspace->l = res->l;

	return 0;
}



int vzctl2_env_get_diskspace(struct vzctl_env_param *env, struct vzctl_2UL_res *res)
{
	struct vzctl_dq_param *dq = env->dq;

	if (dq->diskspace == NULL)
		return VZCTL_E_NOT_INITIALIZED;

	res->b = dq->diskspace->b;
	res->l = dq->diskspace->l;

	return 0;
}

int vzctl2_env_set_diskinodes(struct vzctl_env_param *env, struct vzctl_2UL_res *res)
{
	struct vzctl_dq_param *dq = env->dq;

	if (dq->diskinodes == NULL) {
		dq->diskinodes = malloc(sizeof(*dq->diskinodes));
		if (dq->diskinodes == NULL)
			return VZCTL_E_NOMEM;
	}
	dq->diskinodes->b = res->b;
	dq->diskinodes->l = res->l;

	return 0;
}

int vzctl2_env_get_diskinodes(struct vzctl_env_param *env, struct vzctl_2UL_res *res)
{
	struct vzctl_dq_param *dq = env->dq;

	if (dq->diskinodes == NULL)
		return VZCTL_E_NOT_INITIALIZED;

	res->b = dq->diskinodes->b;
	res->l = dq->diskinodes->l;

	return 0;
}

int vzctl2_env_get_quotaugidlimit(struct vzctl_env_param *env, unsigned long *limits)
{
	struct vzctl_dq_param *dq = env->dq;

	if (dq->ugidlimit == NULL)
		return VZCTL_E_NOT_INITIALIZED;

	*limits = *dq->ugidlimit;

	return 0;
}

int vzctl2_env_set_quotaugidlimit(struct vzctl_env_param *env, unsigned long limits)
{
	struct vzctl_dq_param *dq = env->dq;

	if (dq->ugidlimit == NULL) {
		dq->ugidlimit = malloc(sizeof(*dq->ugidlimit));
		if (dq->ugidlimit == NULL)
			return VZCTL_E_NOMEM;
	}
	*dq->ugidlimit = limits;

	return 0;
}

int vzctl2_env_set_ub_resource(struct vzctl_env_param *env, int id, struct vzctl_2UL_res *res)
{
	return vzctl_add_ub_param(env->res->ub, id, res);
}

int vzctl2_env_get_ub_resource(struct vzctl_env_param *env, int id, struct vzctl_2UL_res *res)
{
	const struct vzctl_2UL_res *_res;

	_res = vzctl_get_ub_res(env->res->ub, id);
	if (_res == NULL)
		return VZCTL_E_NOT_INITIALIZED;

	memcpy(res, _res, sizeof(struct vzctl_2UL_res));

	return 0;
}

int vzctl2_env_set_ramsize(struct vzctl_env_param *env, unsigned long ramsize)
{
	unsigned long pages = ramsize << 8;

	if (env->res->ub->physpages == NULL) {
		env->res->ub->physpages = malloc(sizeof(struct vzctl_2UL_res));
		if (env->res->ub->physpages == NULL)
			return VZCTL_E_NOMEM;
	}
	env->res->ub->physpages->b = pages;
	env->res->ub->physpages->l = pages;

	return 0;
}

int vzctl2_env_get_ramsize(struct vzctl_env_param *env, unsigned long *ramsize)
{
	switch (get_conf_mm_mode(env->res)) {
	case MM_VSWAP:
		/* Pages to Mbytes */
		*ramsize = env->res->ub->physpages->l >> 8;
		return 0;
	case MM_SLM:
		/* Bytes to Mbytes */
		*ramsize = env->res->slm->memorylimit->quality >> 20;
		return 0;
	case MM_UBC:
		if (env->res->ub->privvmpages != NULL) {
			/* Pages to Mbytes */
			*ramsize = env->res->ub->privvmpages->l >> 8;
			return 0;
		}
		break;
	}
	return VZCTL_E_NOT_INITIALIZED;
}

int vzctl2_env_set_memguarantee(vzctl_env_param_ptr env,
                struct vzctl_mem_guarantee *param)
{
	if (param->type < 0 || 
			param->type > VZCTL_MEM_GUARANTEE_BYTES)
		return VZCTL_E_INVAL;

	if (env->res->memguar == NULL) {
		env->res->memguar = malloc(sizeof(struct vzctl_mem_guarantee));
		if (env->res->memguar == NULL)
			return VZCTL_E_NOMEM;
	}

	env->res->memguar->type = param->type;
	env->res->memguar->value = param->value;

	return 0;
}

int vzctl2_env_get_memguarantee(vzctl_env_param_ptr env,
		struct vzctl_mem_guarantee *param)
{
	if (env->res->memguar == NULL) {
		param->type = VZCTL_MEM_GUARANTEE_AUTO;
		param->value = 0;
	} else {
		param->type = env->res->memguar->type;
		param->value = env->res->memguar->value;
	}

	return 0;
}

int vzctl2_env_set_iolimit(struct vzctl_env_param *env, unsigned int limit)
{
	env->io->limit = limit;

	return 0;
}

int vzctl2_env_get_iolimit(struct vzctl_env_param *env, unsigned int *limit)
{
	*limit = env->io->limit;

	return 0;
}

int vzctl2_env_set_ioprio(struct vzctl_env_param *env, int prio)
{
	if (prio < VE_IOPRIO_MIN || prio > VE_IOPRIO_MAX)
		return VZCTL_E_INVAL;

	env->io->prio = prio;

	return 0;
}

int vzctl2_env_get_ioprio(struct vzctl_env_param *env, int *prio)
{
	if (env->io->prio < 0)
		return VZCTL_E_NOT_INITIALIZED;

	*prio = env->io->prio;

	return 0;
}

int vzctl2_env_set_iopslimit(struct vzctl_env_param *env, unsigned int limit)
{
	env->io->iopslimit = limit;

	return 0;
}

int vzctl2_env_get_iopslimit(struct vzctl_env_param *env, unsigned int *limit)
{
	*limit = env->io->iopslimit;

	return 0;
}

int vzctl2_env_add_ipaddress(struct vzctl_env_param *env, const char *ipstr)
{
	int ret;
	struct vzctl_ip_param *ip;

	if (ipstr == NULL)
		return VZCTL_E_INVAL;

	if ((ret = parse_ip(ipstr, &ip)))
		return ret;

	list_add_tail(&ip->list, &env->net->ip);

	return 0;
}

int vzctl2_env_del_ipaddress(struct vzctl_env_param *env, const char *ipstr)
{
	int ret;
	struct vzctl_ip_param *ip;

	if (ipstr == NULL || strcmp(ipstr, "all") == 0) {
		env->net->delall = 1;
		return 0;
	}
	if ((ret = parse_ip(ipstr, &ip)))
		return ret;

	list_add_tail(&ip->list, &env->net->ip_del);

	return 0;
}

struct vzctl_ip_param *vzctl2_env_get_ipaddress(struct vzctl_env_param *env,
			struct vzctl_ip_param *ip)
{
	struct vzctl_ip_param *entry;
	list_head_t *head = &env->net->ip;

	if (ip == NULL)
		entry = list_entry(head->next, typeof(*entry), list);
	else
		entry = list_entry(ip->list.next, typeof(*entry), list);

	if (&entry->list == (list_elem_t*)head)
		return NULL;

	return entry;
}

int vzctl2_env_get_ipstr(struct vzctl_ip_param *ip, char *buf, int len)
{
	return get_ip_str(ip, buf, len);
}

int vzctl2_env_add_veth_ipaddress(struct vzctl_veth_dev *dev, const char *ipstr)
{
	int ret;
	struct vzctl_ip_param *ip;

	if ((ret = parse_ip(ipstr, &ip)))
		return ret;
	/* turn dhcp off on ip address set */
	if (is_ip6(ipstr))
		dev->dhcp6 = VZCTL_PARAM_OFF;
	else
		dev->dhcp = VZCTL_PARAM_OFF;

	list_add_tail(&ip->list, &dev->ip_list);

	return 0;
}

int vzctl2_env_del_veth_ipaddress(struct vzctl_veth_dev *dev, const char *ipstr)
{
	int ret;
	struct vzctl_ip_param *ip;

	if (!strcmp(ipstr, "all")) {
		dev->ip_delall = 1;
		return 0;
	}
	if ((ret = parse_ip(ipstr, &ip)))
		return ret;

	list_add_tail(&ip->list, &dev->ip_del_list);

	return 0;
}

struct vzctl_ip_param *vzctl2_env_get_veth_ipaddress(struct vzctl_veth_dev *dev,
		struct vzctl_ip_param *ip)
{
	struct vzctl_ip_param *entry;
	list_head_t *head = &dev->ip_list;

	if (ip == NULL)
		entry = list_entry(head->next, typeof(*entry), list);
	else
		entry = list_entry(ip->list.next, typeof(*entry), list);

	if (&entry->list == (list_elem_t*)head)
		return NULL;

	return entry;
}

int vzctl2_env_set_veth_param(struct vzctl_veth_dev *dev,
		struct vzctl_veth_dev_param *param, int size)
{
	int ret;
	struct vzctl_ip_param *ip = NULL;
	struct vzctl_veth_dev_param tmp = {};

	if (param == NULL || param->dev_name_ve == NULL)
		return VZCTL_E_INVAL;

	memcpy(&tmp, param, size);

	if (strlen(tmp.dev_name_ve) >= IFNAMSIZE)
		return VZCTL_E_INVAL;

	strncpy(dev->dev_name_ve, tmp.dev_name_ve, IFNAMSIZE);

	if (tmp.dev_name && strlen(tmp.dev_name) >= IFNAMSIZE)
		return VZCTL_E_INVAL;

	if (tmp.mac_renew)
		generate_mac(&dev->mac_ve, 0);
	else if (tmp.mac_ve != NULL) {
		ret = set_hwaddr(tmp.mac_ve, &dev->mac_ve);
		if (ret)
			return ret;
	}

	if (tmp.mac_renew) {
		generate_mac(&dev->mac, 1);
		generate_veth_name(dev);
	} else if (tmp.mac != NULL) {
		ret = set_hwaddr(tmp.mac, &dev->mac);
		if (ret)
			return ret;
	}
	dev->mac_filter = tmp.allow_mac_spoof ? VZCTL_PARAM_OFF : VZCTL_PARAM_ON;
	dev->ip_filter = tmp.allow_ip_spoof ? VZCTL_PARAM_OFF : VZCTL_PARAM_ON;
	if (tmp.dev_name != NULL)
		strncpy(dev->dev_name, tmp.dev_name, IFNAMSIZE);

	if (tmp.network != NULL) {
		free(dev->network);
		dev->network = strdup(tmp.network);
	}
	if (tmp.gw != NULL) {
		free(dev->gw);
		dev->gw = NULL;
		if (tmp.gw[0] == '\0')
			dev->gw = strdup("");
		else if (parse_ip(tmp.gw, &ip) == 0) {
			dev->gw = strdup(ip->ip);
			free_ip_param(ip);
		} else
			return VZCTL_E_INVAL;

	}
	if (tmp.gw6 != NULL) {
		free(dev->gw6);
		dev->gw6 = NULL;
		if (tmp.gw6[0] == '\0')
			dev->gw6 = strdup("");
		else if (parse_ip(tmp.gw6, &ip) == 0) {
			dev->gw6 = strdup(ip->ip);
			free_ip_param(ip);
		} else
			return VZCTL_E_INVAL;
	}
	if (tmp.configure_mode)
		dev->configure_mode = tmp.configure_mode;

	if (tmp.nettype) {
		if (tmp.nettype > VZCTL_NETTYPE_VNET)
			return VZCTL_E_INVAL;
		dev->nettype = tmp.nettype;
	}

	if (dev->dhcp != -1)
		dev->dhcp = tmp.dhcp ? VZCTL_PARAM_ON : VZCTL_PARAM_OFF;
	if (dev->dhcp6 != -1)
		dev->dhcp6 = tmp.dhcp6 ? VZCTL_PARAM_ON : VZCTL_PARAM_OFF;

	dev->ip_delall = tmp.ip_apply_mode;
	dev->vporttype = tmp.vporttype;

	return 0;
}

struct vzctl_veth_dev *vzctl2_create_veth_dev(struct vzctl_veth_dev_param *param, int size)
{
	struct vzctl_veth_dev *dev;

	dev = alloc_veth_dev();
	if (dev == NULL)
		return NULL;

	if (param != NULL) {
		if (vzctl2_env_set_veth_param(dev, param, size)) {
			free_veth_dev(dev);
			dev = NULL;
		}
	}

	return dev;
}

void vzctl2_free_veth_dev(struct vzctl_veth_dev *dev)
{
	free_veth_dev(dev);
}

int vzctl2_env_add_veth(struct vzctl_env_param *env, struct vzctl_veth_dev *dev)
{
	list_add_tail(&dev->list, &env->veth->dev_list);

	return 0;
}

int vzctl2_env_del_veth(struct vzctl_env_param *env, const char *ifname)
{
	struct vzctl_veth_dev *dev;

	if (ifname == NULL)
		return VZCTL_E_INVAL;
	if (strcmp(ifname, "*") == 0 ||
	    strcmp(ifname, "all") == 0)
	{
		env->veth->delall = 1;
		return 0;
	}

	dev = alloc_veth_dev();
	if (dev == NULL)
		return VZCTL_E_NOMEM;

	memcpy(dev->dev_name_ve, ifname, IFNAMSIZE);

	list_add_tail(&dev->list, &env->veth->dev_del_list);

	return 0;
}

int vzctl2_env_get_veth_param(struct vzctl_veth_dev *dev, struct vzctl_veth_dev_param *res, int size)
{
	struct vzctl_veth_dev_param tmp = {};

	tmp.mac = dev->mac;
	tmp.dev_name = dev->dev_name;
	tmp.mac_ve = dev->mac_ve;
	tmp.dev_name_ve = dev->dev_name_ve;
	tmp.gw = dev->gw;
	tmp.network = dev->network;
	tmp.dhcp = dev->dhcp == VZCTL_PARAM_ON ? 1 : 0;
	tmp.allow_mac_spoof = dev->mac_filter == VZCTL_PARAM_OFF ? 1 : 0;
	tmp.allow_ip_spoof = dev->ip_filter == VZCTL_PARAM_OFF ? 1 : 0;
	tmp.dhcp6 = dev->dhcp6 == VZCTL_PARAM_ON ? 1 : 0;
	tmp.gw6 = dev->gw6;
	tmp.configure_mode = dev->configure_mode;
	if (dev->nettype == 0)
		tmp.nettype = VZCTL_NETTYPE_VNET;
	else
		tmp.nettype = dev->nettype;
	tmp.vporttype = dev->vporttype;

	memcpy(res, &tmp, size);

	return 0;
}

struct vzctl_veth_dev *vzctl2_env_get_veth(struct vzctl_env_param *env,
			struct vzctl_veth_dev *dev)
{
	struct vzctl_veth_dev *entry;
	list_head_t *head = &env->veth->dev_list;

	if (dev == NULL)
		entry = list_entry(head->next, typeof(*entry), list);
	else
		entry = list_entry(dev->list.next, typeof(*entry), list);

	if (&entry->list == (list_elem_t*)head)
		return NULL;

	return entry;
}

int vzctl2_env_get_disk_param(struct vzctl_disk *disk, struct vzctl_disk_param *out, int size)
{
	struct vzctl_disk_param tmp = {};

	if (disk == NULL)
		 return VZCTL_E_INVAL;

	memcpy(tmp.uuid, disk->uuid, sizeof(tmp.uuid));
	tmp.enabled = disk->enabled;
	tmp.size = disk->size;
	tmp.path = disk->path;
	tmp.mnt = disk->mnt;
	tmp.autocompact = disk->autocompact;
	tmp.storage_url = disk->storage_url;
	tmp.use_device = disk->use_device;
	tmp.enc_keyid = disk->enc_keyid;

	memcpy(out, &tmp, size);

	return 0;
}

int vzctl2_env_get_root_disk_param(struct vzctl_env_param *env, struct vzctl_disk_param *out, int size)
{
	return VZCTL_E_INVAL;
}

struct vzctl_disk *vzctl2_env_get_disk(struct vzctl_env_param *env,
		struct vzctl_disk *disk)
{
	struct vzctl_disk *entry;
	list_head_t *head = &env->disk->disks;

	if (disk == NULL)
		entry = list_entry(head->next, typeof(*entry), list);
	else
		entry = list_entry(disk->list.next, typeof(*entry), list);

	if (&entry->list == (list_elem_t*)head)
		return NULL;

	return entry;
}

static int save_disk_param(struct vzctl_env_handle *h)
{
	int ret;
	char *str;
	int root_disk = h->env_param->disk->root;

	str = disk2str(h, h->env_param->disk);
	vzctl2_env_set_param(h, "DISK", str);
	free(str);

	if (root_disk)
		vzctl2_env_set_param(h, "ROOT_DISK",
				root_disk == VZCTL_PARAM_OFF ?  "no"  : NULL);

	ret = vzctl2_env_save_conf(h, h->conf ?	h->conf->fname : NULL);
	if (ret)
		return ret;

	return 0;
}

int vzctl2_env_add_disk(struct vzctl_env_handle *h, struct vzctl_disk_param *param, int flags)
{
	int ret;

	ret = vzctl2_add_disk(h, param, flags);
	if (ret)
		return ret;

	return save_disk_param(h);
}

int vzctl2_env_attach_disk(struct vzctl_env_handle *h, struct vzctl_disk_param *param)
{
	int ret;

	ret = vzctl2_add_disk(h, param, VZCTL_DISK_SKIP_CREATE);
	if (ret)
		return ret;

	return save_disk_param(h);
}

int vzctl2_env_del_disk(struct vzctl_env_handle *h, const char *guid, int flags)
{
	int ret;

	ret = vzctl2_del_disk(h, guid, flags);
	if (ret)
		return ret;

	return save_disk_param(h);
}

int vzctl2_env_detach_disk(struct vzctl_env_handle *h, const char *guid)
{
	int ret;

	ret = vzctl2_del_disk(h, guid, VZCTL_DISK_DETACH);
	if (ret)
		return ret;

	return save_disk_param(h);
}

int vzctl2_env_set_disk(struct vzctl_env_handle *h, struct vzctl_disk_param *param)
{
	int ret;

	ret = vzctl2_set_disk(h, param);
	if (ret)
		return ret;

	return save_disk_param(h);
}

int vzctl2_env_resize_disk(struct vzctl_env_handle *h, const char *uuid,
		unsigned long size, int offline)
{
	int ret;

	ret = vzctl2_resize_disk(h, uuid, size, offline);
	if (ret)
		return ret;

	return save_disk_param(h);
}

int vzctl2_env_get_ostemplate(struct vzctl_env_param *env, const char **res)
{
	if (env->tmpl->ostmpl == NULL)
		return VZCTL_E_NOT_INITIALIZED;

	*res = env->tmpl->ostmpl;

	return 0;
}

int vzctl2_env_get_apptemplates(struct vzctl_env_param *env, const char **res)
{
	if (env->tmpl->templates == NULL)
		return VZCTL_E_NOT_INITIALIZED;

	*res = env->tmpl->templates;

	return 0;
}

int vzctl2_env_set_autostart(struct vzctl_env_param *env, int mode)
{
	env->opts->onboot = mode > VZCTL_AUTOSTART_AUTO ?
			VZCTL_AUTOSTART_ON : mode;
	return 0;
}

int vzctl2_env_get_autostart(struct vzctl_env_param *env, int *mode)
{
	if (env->opts->onboot == VZCTL_AUTOSTART_NONE)
		return VZCTL_E_NOT_INITIALIZED;

	*mode = env->opts->onboot;

	return 0;
}

int vzctl2_env_set_autostop(struct vzctl_env_param *env, int mode)
{
	if (mode > VZCTL_AUTOSTOP_SUSPEND)
		return VZCTL_E_INVAL;

	env->opts->autostop = mode;

	return 0;
}

int vzctl2_env_get_autostop(struct vzctl_env_param *env, int *mode)
{
	*mode = env->opts->autostop;

	return 0;
}

int vzctl2_env_set_apply_iponly(struct vzctl_env_param *env, int enable)
{
	env->opts->apply_iponly = enable ? VZCTL_PARAM_ON : VZCTL_PARAM_OFF;

	return 0;
}

int vzctl2_env_get_apply_iponly(struct vzctl_env_param *env, int *enable)
{
	*enable = (env->opts->apply_iponly == VZCTL_PARAM_ON) ? 1 : 0;

	return 0;
}

int vzctl2_env_get_param(struct vzctl_env_handle *h, const char *name, const char **res)
{
	return vzctl2_conf_get_param(h->conf, name, res);
}

int vzctl2_env_get_param_bool(struct vzctl_env_handle *h, const char *name)
{
	const char *data = NULL;

	vzctl2_conf_get_param(h->conf, name, &data);

	return yesno2id(data);
}

int vzctl2_env_set_param(struct vzctl_env_handle *h, const char *name, const char *str)
{
	return vzctl_conf_add_param(h->conf, name, str);
}

int vzctl2_env_get_description(struct vzctl_env_param *env, const char **desc)
{
	if (env->misc->description_eq == NULL)
		return VZCTL_E_NOT_INITIALIZED;

	free(env->misc->description);
	env->misc->description = get_description(env->misc->description_eq);

	*desc = env->misc->description;

	return 0;
}

int vzctl2_env_set_description(struct vzctl_env_param *env, const char *desc)
{
	return set_description(&env->misc->description_eq, desc);
}

int vzctl2_env_set_hostname(struct vzctl_env_param *env, const char *name)
{
	free(env->misc->hostname);

	env->misc->hostname = strdup(name);

	return 0;
}

int vzctl2_env_get_hostname(struct vzctl_env_param *env, const char **name)
{
	if (env->misc->hostname == NULL)
		return VZCTL_E_NOT_INITIALIZED;

	* name = env->misc->hostname;

	return 0;
}

int vzctl2_env_get_ve_private_path(struct vzctl_env_param *env, const char **path)
{
	if (env->fs->ve_private == NULL)
		return VZCTL_E_NOT_INITIALIZED;

	*path = env->fs->ve_private;

	return 0;
}

int vzctl2_env_get_ve_private_orig_path(struct vzctl_env_param *env, const char **path)
{
	if (env->fs->ve_private_orig == NULL)
		return VZCTL_E_NOT_INITIALIZED;

	*path = env->fs->ve_private_orig;

	return 0;
}

int vzctl2_env_set_ve_private_path(struct vzctl_env_param *env,
		const char *ve_private)
{
	int ret;
	int layout;

	layout = vzctl2_env_layout_version(ve_private);
	if (layout == -1)
		return VZCTL_E_INVAL;

	if (layout)
		env->fs->layout = layout;

	ret = xstrdup(&env->fs->ve_private, ve_private);
	if (ret)
		return ret;

	return set_disk_param(env, 0);
}

int vzctl2_env_get_ve_root_path(struct vzctl_env_param *env, const char **path)
{
	if (env->fs->ve_root == NULL)
		return VZCTL_E_NOT_INITIALIZED;

	*path = env->fs->ve_root;

	return 0;
}

int vzctl2_env_get_ve_root_orig_path(struct vzctl_env_param *env, const char **path)
{
	if (env->fs->ve_root_orig == NULL)
		return VZCTL_E_NOT_INITIALIZED;

	*path = env->fs->ve_root_orig;

	return 0;
}

int vzctl2_env_set_ve_root_path(struct vzctl_env_param *env,
		const char *ve_root)
{
	return xstrdup(&env->fs->ve_root, ve_root);
}

int vzctl2_get_name(struct vzctl_env_handle *h, const char **name)
{
	return vzctl2_env_get_name(h, name);
}

int vzctl2_env_get_name(struct vzctl_env_handle *h, const char **name)
{
	*name = h->env_param->name->name;
	if (*name == NULL)
		return VZCTL_E_NOT_INITIALIZED;

	return 0;
}

int vzctl2_env_set_cpu_count(struct vzctl_env_param *env, unsigned long num)
{
	if (env->cpu->vcpus == NULL) {
		env->cpu->vcpus = malloc(sizeof(unsigned long));
		if (env->cpu->vcpus == NULL)
			return VZCTL_E_NOMEM;
	}

	*env->cpu->vcpus = num;

	return 0;
}

int vzctl2_env_get_cpu_count(struct vzctl_env_param *env, unsigned long *num)
{
	if (env->cpu->vcpus == NULL)
		*num = 0; /* unlimited */
	else
		*num = *env->cpu->vcpus;

	return 0;
}

struct vzctl_rate *vzctl2_create_rate(struct vzctl_rate_param *param)
{
	struct vzctl_rate *rate;

	if (param->dev == NULL) {
		logger(-1, 0, "Invalid parameter: device is not specified");
		return NULL;
	}

	rate = alloc_rate();
	if (rate == NULL) {
		logger(-1, ENOMEM, "alloc_rate");
		return NULL;
	}

	if (xstrdup(&rate->dev, param->dev)) {
		free_rate(rate);
		return NULL;
	}

	rate->net_class = param->net_class;
	rate->rate = param->rate;

	return rate;
}

int vzctl2_env_add_rate(struct vzctl_env_param *env,  struct vzctl_rate *rate)
{
	if (rate == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0, "Invalid parameter: rate is not specified");

	list_add_tail(&rate->list, &env->vz->tc->rate_list);
	return 0;
}

struct vzctl_rate *vzctl2_env_get_rate(struct vzctl_env_param *env, struct vzctl_rate *rate)
{
	struct vzctl_rate *entry;
	list_head_t *head = &env->vz->tc->rate_list;

	if (rate == NULL)
		entry = list_entry(head->next, typeof(*entry), list);
	else
		entry = list_entry(rate->list.next, typeof(*entry), list);

	if (&entry->list == (list_elem_t*)head)
		return NULL;

	return entry;
}

int vzctl2_env_get_rate_param(struct vzctl_rate *rate, struct vzctl_rate_param *param)
{
	param->dev = rate->dev;
	param->net_class = rate->net_class;
	param->rate = rate->rate;

	return 0;
}

int vzctl2_env_set_ratebound(struct vzctl_env_param *env, int ratebound)
{
	if (ratebound)
		env->vz->tc->ratebound = VZCTL_PARAM_ON;
	else
		env->vz->tc->ratebound = VZCTL_PARAM_OFF;

	return 0;
}

int vzctl2_env_get_ratebound(struct vzctl_env_param *env, int *ratebound)
{
	if (env->vz->tc->ratebound == VZCTL_PARAM_ON)
		*ratebound = 1;
	else
		*ratebound = 0;

	return 0;
}

const char *vzctl2_env_get_str_param(struct vzctl_str_param *param)
{
	return param->str;
}

int vzctl2_env_add_nameserver(struct vzctl_env_param *env, const char *server)
{
	unsigned int addr[4];

	if (server == NULL)
		return VZCTL_E_INVAL;
	if (server[0] != '\0' && get_netaddr(server, addr) == -1)
		return VZCTL_E_INVAL;
	if (find_str(&env->misc->nameserver, server) != NULL)
		return 0;
	if (add_str_param(&env->misc->nameserver, server) == NULL)
		return VZCTL_E_NOMEM;

	return 0;
}

struct vzctl_str_param *vzctl2_env_get_nameserver(struct vzctl_env_param *env,
		struct vzctl_str_param *it)
{
	struct vzctl_str_param *entry;
	list_head_t *head = &env->misc->nameserver;

	if (it == NULL)
		entry = list_entry(head->next, typeof(*entry), list);
	else
		entry = list_entry(it->list.next, typeof(*entry), list);

	if (&entry->list == (list_elem_t*)head)
		return NULL;

	return entry;
}

int vzctl2_env_add_searchdomain(struct vzctl_env_param *env, const char *domain)
{
	if (domain == NULL)
		return VZCTL_E_INVAL;
	if (find_str(&env->misc->searchdomain, domain) != NULL)
		return 0;
	if (add_str_param(&env->misc->searchdomain, domain) == NULL)
		return VZCTL_E_NOMEM;

	return 0;
}

struct vzctl_str_param *vzctl2_env_get_searchdomain(struct vzctl_env_param *env,
		struct vzctl_str_param *it)
{
	struct vzctl_str_param *entry;
	list_head_t *head = &env->misc->searchdomain;

	if (it == NULL)
		entry = list_entry(head->next, typeof(*entry), list);
	else
		entry = list_entry(it->list.next, typeof(*entry), list);

	if (&entry->list == (list_elem_t*)head)
		return NULL;

	return entry;
}

#define PROC_VZ_IOACCT "/proc/bc/%s/ioacct"

int vzctl2_get_env_iostat(const ctid_t ctid, struct vzctl_iostat *stat, int size)
{
	struct vzctl_iostat statbuf;
	FILE *f;
	char buf[128];
	char fname[256];
	int found;
	ctid_t id;

	if (vzctl2_parse_ctid(ctid, id))
		return vzctl_err(VZCTL_E_INVAL, 0, "Invalid CTID: %s", ctid);

	snprintf(fname, sizeof(fname), PROC_VZ_IOACCT, id);

	f = fopen(fname, "rt");
	if (f == NULL) {
		if (errno == ENOENT)
			return vzctl_err(VZCTL_E_ENV_NOT_RUN, 0,
					"Container is not running");
		return vzctl_err(VZCTL_E_SYSTEM, errno, "Statistics not available");
	}


	found = 0;
	while (!feof(f))
	{
		if (!fgets(buf, sizeof(buf), f))
			break;

		if (sscanf(buf, " read %llu", &statbuf.read) == 1)
			found++;
		if (sscanf(buf, " write %llu", &statbuf.write) == 1)
			found++;
		if (found == 2)
			break;
	}
	memcpy(stat, &statbuf, size);

	fclose(f);
	return 0;
}

int vzctl2_get_env_meminfo(const ctid_t ctid, struct vzctl_meminfo *meminfo, int size)
{
	FILE *fp;
	char buf[128];
	struct vzctl_meminfo data = {};
	unsigned long long recl = 0;
	ctid_t id;

	if (vzctl2_parse_ctid(ctid, id))
		return vzctl_err(VZCTL_E_INVAL, 0, "Invalid CTID: %s", ctid);

	bzero(meminfo, size);

	snprintf(buf, sizeof(buf), "/proc/bc/%s/meminfo", id);
	if ((fp = fopen(buf, "r")) == NULL) {
		if (errno != ENOENT)
			logger(-1, errno, "Cannot open %s", buf);
		return -1;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		if (sscanf(buf, "MemTotal: %llu", &data.total) == 1)
			data.total *= 1024;
		else if (sscanf(buf, "MemFree: %llu", &data.free) == 1)
			data.free *= 1024;
		else if (sscanf(buf, "Cached: %llu", &data.cached) == 1)
			data.cached *= 1024;
		else if (sscanf(buf, "SReclaimable: %llu", &recl) == 1)
			recl *= 1024;
	}
	fclose(fp);

	/* account SReclaimable to cached memory
	 *
	`* NB: dcachesize consist of reclaimable and
	 * nonreclaimable parts, but there no direct way to get
	 * this info for CT and no possibility get info for
	 * Host/VM so account whole dcachesize to cached memory
	 */
	data.cached += recl;

	/* workaround for #PSBM-31006 */
	if (data.cached > (data.total - data.free))
		data.cached = data.total - data.free;

	snprintf(buf, sizeof(buf), "/proc/bc/%s/vmaux", id);
	if ((fp = fopen(buf, "r")) == NULL) {
		if (errno != ENOENT)
			logger(-1, errno, "Cannot open %s", buf);
		return -1;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		sscanf(buf, " swapin %llu", &data.swap_in);
		sscanf(buf, " swapout %llu", &data.swap_out);
	}
	fclose(fp);

	memcpy(meminfo, &data, size);

	return 0;
}

static unsigned long long get_env_run_uptime(struct vzctl_env_handle *h)
{
	struct vzctl_cpustat stat;

	if (vzctl2_env_cpustat(h, &stat, sizeof(stat)))
		return 0;
	return stat.uptime;
}

#define CT_UPTIME_FILENAME	".uptime"

static int get_env_uptime(struct vzctl_env_handle *h,
	unsigned long long *uptime, unsigned long long *start_time,
	unsigned long long *run_uptime_jif)
{
	int i, found, expected;
	char buf[4096];
	FILE *f;

	snprintf(buf, sizeof(buf), "%s/%s", h->env_param->fs->ve_private,
			CT_UPTIME_FILENAME);
	f = fopen(buf, "r");
	if (!f) {
		if (errno == ENOENT)
			return VZCTL_E_SYSTEM;
		return vzctl_err(VZCTL_E_SYSTEM, errno,
			"Uptime information can't be read from disk");
	}

	expected = 0;
	if (uptime)
		expected++;
	if (start_time)
		expected++;
	if (run_uptime_jif)
		expected++;
	found = 0;
	for (i = 0; !feof(f) && i < 3; i++) {
		if (!fgets(buf, sizeof(buf), f))
			break;

		if (i == 0 && run_uptime_jif) {
			*run_uptime_jif = atoll(buf);
			found++;
		} else if (i == 1 && uptime) {
			*uptime = atoll(buf);
			found++;
		} else if (i == 2 && start_time) {
			*start_time = atoll(buf);
			found++;
		}
	}
	fclose(f);

	if (found != expected)
		return vzctl_err(VZCTL_E_SYSTEM, ENOENT,
			"Uptime information is incomplete");
	return 0;
}

int vzctl2_env_set_uptime(struct vzctl_env_handle *h, unsigned long long uptime,
	unsigned long long start_date)
{
	char buf[4096];
	FILE *f;

	snprintf(buf, sizeof(buf), "%s/%s", h->env_param->fs->ve_private,
			CT_UPTIME_FILENAME);
	f = fopen(buf, "w+");
	if (!f)
		return vzctl_err(VZCTL_E_SYSTEM, errno,
			"Uptime information can't be stored to disk");

	/* current run-time watermark */
	snprintf(buf, sizeof(buf), "%llu\n",
		get_env_run_uptime(h));
	fputs(buf, f);

	/* save uptime */
	snprintf(buf, sizeof(buf), "%llu\n", uptime);
	fputs(buf, f);

	/* reset start date */
	snprintf(buf, sizeof(buf), "%llu\n", start_date);
	fputs(buf, f);

	fclose(f);
	return 0;
}

int vzctl2_env_reset_uptime(struct vzctl_env_handle *h)
{
	return vzctl2_env_set_uptime(h, 0, time(NULL));
}

int vzctl2_env_get_uptime(struct vzctl_env_handle *h, unsigned long long *uptime,
		unsigned long long *date_time)
{
	return get_env_uptime(h, uptime, date_time, NULL);
}

int vzctl2_env_sync_uptime(struct vzctl_env_handle *h)
{
	unsigned long long uptime, start_date;
	unsigned long long old_run_uptime, run_uptime;
	int ret;

	ret = get_env_uptime(h, &uptime, &start_date, &old_run_uptime);
	if (ret) {
		/* failed to retrieve uptime - initialize it */
		return vzctl2_env_set_uptime(h, 0, time(NULL));
	}

	run_uptime = get_env_run_uptime(h);
	if (run_uptime < old_run_uptime)
		old_run_uptime = 0; /* restart detected */
	uptime += run_uptime - old_run_uptime;

	return vzctl2_env_set_uptime(h, uptime, start_date);
}

int vzctl2_env_set_type(struct vzctl_env_param *env, vzctl_env_type type)
{
	if (type <= 0 || type >  VZCTL_ENV_TYPE_MAX)
		return VZCTL_E_INVAL;
	env->misc->ve_type = type;

	return 0;
}

int vzctl2_env_get_type(struct vzctl_env_param *env, vzctl_env_type *type)
{
	if (env->misc->ve_type == 0)
		*type = VZCTL_ENV_TYPE_REGULAR;
	else
		*type = env->misc->ve_type;

	return 0;
}

int vzctl2_env_set_uuid(struct vzctl_env_param *env, const char *uuid)
{
	char _uuid[40];

	if (vzctl2_get_normalized_uuid(uuid, _uuid, sizeof(_uuid)))
		return vzctl_err(VZCTL_E_INVAL, 0, "Incorrect uuid is specified: %s", uuid);

	return xstrdup(&env->misc->uuid, _uuid);
}

int vzctl2_env_get_uuid(struct vzctl_env_param *env, const char **uuid)
{
	if (env->misc->uuid == NULL)
		return VZCTL_E_NOT_INITIALIZED;

	*uuid = env->misc->uuid;

	return 0;
}

const char *vzctl2_env_get_ctid(struct vzctl_env_handle *h)
{
	return EID(h);
}

int vzctl2_env_get_veid(struct vzctl_env_handle *h)
{
	return h->veid;
}

int vzctl2_env_set_cpumask(struct vzctl_env_param *env, const char *str)
{
	return parse_cpumask(str, &env->cpu->cpumask);
}

int vzctl2_env_get_cpumask(struct vzctl_env_param *env, char *buf, int buflen)
{
	char *mask;

	if (env->cpu->cpumask == NULL)
		return VZCTL_E_NOT_INITIALIZED;

	mask = cpumask2str(env->cpu->cpumask);
	if (mask == NULL)
		return VZCTL_E_NOMEM;

	strncpy(buf, mask, buflen - 1);
	buf[buflen - 1] = '\0';
	free(mask);

	return 0;
}

int vzctl2_env_set_nodemask_ex(struct vzctl_env_param *env,
		struct vzctl_cpumask *cpumask, struct vzctl_nodemask *nodemask)
{
	if (cpumask != NULL) {
		free(env->cpu->cpumask);
		env->cpu->cpumask = malloc(sizeof(struct vzctl_cpumask));
		if (env->cpu->cpumask == NULL)
			return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "malloc");
		memcpy(env->cpu->cpumask, cpumask, sizeof(struct vzctl_cpumask));
	}
	if (nodemask != NULL) {
		free(env->cpu->nodemask);
		env->cpu->nodemask = malloc(sizeof(struct vzctl_nodemask));
		if (env->cpu->nodemask == NULL)
			return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "malloc");
		memcpy(env->cpu->nodemask, nodemask, sizeof(struct vzctl_nodemask));
	}

	return 0;
}

int vzctl2_env_set_nodemask(struct vzctl_env_param *env, const char *str)
{
	return parse_nodemask(str, &env->cpu->nodemask);
}

int vzctl2_env_get_nodemask(struct vzctl_env_param *env, char *buf, int buflen)
{
	char *mask;

	if (env->cpu->nodemask == NULL)
		return VZCTL_E_NOT_INITIALIZED;

	mask = nodemask2str(env->cpu->nodemask);
	if (mask == NULL)
		return VZCTL_E_NOMEM;

	strncpy(buf, mask, buflen - 1);
	buf[buflen - 1] = '\0';
	free(mask);

	return 0;
}

int vzctl2_env_set_node(struct vzctl_env_handle *h, struct vzctl_nodemask *nodemask,
		struct vzctl_cpumask *cpumask)
{
	int ret;

	if (cpumask != NULL && !cpumask->auto_assigment) {
		if ((ret = get_env_ops()->env_set_cpumask(h, cpumask)))
			return ret;
	}

	if (nodemask != NULL) {
		if ((ret = get_env_ops()->env_set_nodemask(h, nodemask)))
			return ret;
		if (cpumask == NULL || cpumask->auto_assigment) {
			struct vzctl_cpumask mask;

			if ((ret = get_node_cpumask(nodemask, &mask)))
				return ret;
			/* Auto calculation */
			if ((ret = get_env_ops()->env_set_cpumask(h, &mask)))
				return ret;
		}
	}
	return 0;
}

int vzctl2_env_get_layout(struct vzctl_env_param *env, int *layout)
{
	*layout = env->fs->layout;
	return 0;
}

int vzctl2_env_set_layout(struct vzctl_env_param *env, int layout, int flags)
{
	if (layout < VZCTL_LAYOUT_3 || layout > VZCTL_LAYOUT_5)
		return vzctl_err(VZCTL_E_INVAL, 0, "An invalid layout is specified %d",
				layout);

	env->fs->layout = layout;

	return set_disk_param(env, flags);
}

int vzctl2_env_get_ha_enable(vzctl_env_param_ptr env, int *enable)
{
	/* High Availability should be enabled by default */
	*enable = (env->opts->ha_enable == VZCTL_PARAM_OFF) ? 0 : 1;
	return 0;
}

int vzctl2_env_set_ha_enable(vzctl_env_param_ptr env, int enable)
{
	env->opts->ha_enable = enable ? VZCTL_PARAM_ON : VZCTL_PARAM_OFF;
	return 0;
}

int vzctl2_env_get_ha_prio(vzctl_env_param_ptr env, unsigned long *prio)
{
	if (env->opts->ha_prio == NULL)
		return VZCTL_E_NOT_INITIALIZED;

	*prio = *env->opts->ha_prio;

	return 0;
}

int vzctl2_env_set_ha_prio(vzctl_env_param_ptr env, unsigned long prio)
{
	struct vzctl_opts *opts = env->opts;

	if (prio > MAXHAPRIO)
		return VZCTL_E_INVAL;

	if (opts->ha_prio == NULL) {
		opts->ha_prio = malloc(sizeof(*opts->ha_prio));
		if (opts->ha_prio == NULL)
			return VZCTL_E_NOMEM;
	}
	*opts->ha_prio = prio;

	return 0;
}

int vzctl2_env_set_meminfo(vzctl_env_param_ptr env, int mode, unsigned long val)
{
	struct vzctl_meminfo_param *meminfo;

	if (mode != VZCTL_MEMINFO_NONE &&
			mode != VZCTL_MEMINFO_PAGES)
		return vzctl_err(VZCTL_E_INVAL, 0, "Invalid mode specified %d", mode);

	meminfo = alloc_meminfo_param();
	if (meminfo == NULL)
		return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "alloc_meminfo_param");

	meminfo->mode = mode;
	meminfo->val = val;

	free(env->meminfo);
	env->meminfo = meminfo;

	return 0;
}

int vzctl2_env_add_pcidev(vzctl_env_param_ptr env, const char *dev)
{
	return parse_pcidev(&env->dev->pci, dev, 1, 0);
}

int vzctl2_env_del_pcidev(vzctl_env_param_ptr env, const char *dev)
{
	return parse_pcidev(&env->dev->pci_del, dev, 0, 0);
}

int vzctl2_env_add_device(vzctl_env_param_ptr env, const char *dev)
{
	int ret;
	struct vzctl_dev_perm perm;

	ret = parse_devices_str(&perm, dev);
	if (ret)
		return ret;
	ret = add_dev_param(&env->dev->dev, &perm);
	if (ret)
		return ret;
	return 0;
}

int vzctl2_env_del_device(vzctl_env_param_ptr env, const char *dev)
{
	int ret;
	struct vzctl_dev_perm perm;

	ret = parse_devices_str(&perm, dev);
	if (ret)
		return ret;
	ret = add_dev_param(&env->dev->dev_del, &perm);
	if (ret)
		return ret;
	return 0;
}

int vzctl2_env_add_devnodes(vzctl_env_param_ptr env, const char *dev)
{
	int ret;
	struct vzctl_dev_perm perm;

	ret = parse_devnodes_str(&perm, dev, 1);
	if (ret)
		return ret;
	ret = add_dev_param(&env->dev->dev, &perm);
	if (ret)
		return ret;
	return 0;
}

int vzctl2_env_del_devnodes(vzctl_env_param_ptr env, const char *dev)
{
	int ret;
	struct vzctl_dev_perm perm;

	ret = parse_devnodes_str(&perm, dev, 0);
	if (ret)
		return ret;
	ret = add_dev_param(&env->dev->dev_del, &perm);
	if (ret)
		return ret;
	return 0;
}

int vzctl2_env_get_autocompact(struct vzctl_env_param *env, int *enable)
{
	/* enabled by default */
	*enable = (env->misc->autocompact == VZCTL_PARAM_OFF) ? 0 : 1;

	return 0;
}

int vzctl2_env_set_autocompact(struct vzctl_env_param *env, int enable)
{
	env->misc->autocompact = enable ? VZCTL_PARAM_ON : VZCTL_PARAM_OFF;

	return 0;
}

int vzctl2_env_get_bootorder(struct vzctl_env_param *env, unsigned long *bootorder)

{
	*bootorder = env->opts->bootorder ? *env->opts->bootorder : 0;
	return 0;
}

int vzctl2_env_set_bootorder(struct vzctl_env_param *env, unsigned long bootorder)
{
	if (env->opts->bootorder == NULL) {
		env->opts->bootorder = malloc(sizeof(*env->opts->bootorder));
		if (env->opts->bootorder == NULL)
			return VZCTL_E_NOMEM;
	}

	*env->opts->bootorder = bootorder;
	return 0;
}

int vzctl2_env_set_setmode(struct vzctl_env_param *env, vzctl_setmode_t mode)
{
	if (mode > VZCTL_SET_MODE_MAX)
		return VZCTL_E_INVAL;

	env->opts->setmode = mode;

	return 0;
}

int vzctl2_env_set_cidata_fname(struct vzctl_env_param *env, const char *fname)
{
	return xstrdup(&env->opts->cidata_fname, fname);
}

int vzctl2_env_get_disabled(struct vzctl_env_param *env, int *disabled)
{
	*disabled = (env->misc->start_disabled == VZCTL_PARAM_ON) ? 1 : 0;

	return 0;
}

int vzctl2_cpt_cmd(struct vzctl_env_handle *h, int action, int cmd,
		struct vzctl_cpt_param *param, int flags)
{
	return get_env_ops()->env_cpt_cmd(h, action, cmd, param, flags);
}

int vzctl2_env_compact(struct vzctl_env_handle *h,
		struct vzctl_compact_param *param, int size)
{
	int ret = 0, rc;
	struct vzctl_disk *d;
	struct vzctl_compact_param p = {};

	memcpy(&p, param, size);
	list_for_each(d, &h->env_param->disk->disks, list) {
		rc = vzctl_compact_disk_image(d, &p);
		if (rc)
			ret = rc;
		
	}

	return ret;
}

#define CIDATA_DIR	"/var/lib/cloud/seed/nocloud-net"
extern int loop_create(const char *delta, char *ldev, int size);
static int mount_iso(const char *fname, const char *dst)
{
	int fd;
	int rc = 0;
	char ldev[STR_SIZE];

	rc = make_dir(dst, 1);
	if (rc)
		return rc;

	fd = loop_create(fname, ldev, sizeof(ldev));
	if (fd == -1)
		return VZCTL_E_SYSTEM;

	if (mount(ldev, dst, "iso9660", MS_RDONLY, NULL))
		rc = vzctl_err(VZCTL_E_SYSTEM, errno, "Cannot mount %s %s",
				ldev, dst);
	close(fd);

	return rc;
}

int setup_cloud_init_data(struct vzctl_env_handle *h, const char *fname,
		char **cidata_mnt)
{
	int rc;
	char dst[PATH_MAX];
	const char *p;
	struct vzctl_bindmount m = {};

	logger(0, 0, "Setup cloud init data %s", fname);
	if (access(fname, F_OK))
		return vzctl_err(VZCTL_E_INVAL, errno, "Unable to access cloud-init file '%s'",
				fname);

	p = strrchr(fname, '.');
	if (p && strcmp(p, ".iso") == 0) {
		snprintf(dst, sizeof(dst), "%s/cidata_mnt",
				h->env_param->fs->ve_private);
		rc = xstrdup(cidata_mnt, dst);
		if (rc)
			return rc;

		rc = mount_iso(fname, dst);
		if (rc)
			return rc;
		m.src = dst;
	} else {
		m.src = (char *)fname;
	}
	m.dst = CIDATA_DIR;
	m.mntopt = MS_RDONLY;

	return add_bindmount(h->env_param->bindmount, &m);
}

/** Get list of private areas
 * This function scan file system and return found VE_PRIBVATE.
 * Algo: Read shared file system from STORAGE_LIST if not exists read from
 * /proc/mounts and look for fs && ve.conf && .ve_layout pattern.
 *
 * @return	Return array of (char *) found Container private areas terminated by 0
 *		NULL in case error
 */
char **vzctl2_scan_private(void)
{
	list_head_t head;
	char **storage, **p;
	char **out = NULL;

	if ((storage = vzctl2_get_storage()) == NULL)
		return NULL;
	list_head_init(&head);
	for (p = storage; *p != NULL; p++) {
		if (get_dir_list(&head, *p, 5))
			goto err;
	}

	out = list2ar_str(&head);
err:

	free_ar_str(storage);
	free(storage);
	free_str(&head);

	return out;
}
