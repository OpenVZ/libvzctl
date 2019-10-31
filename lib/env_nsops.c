/*
 * Copyright (c) 2015-2017, Parallels International GmbH
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
 */
#define	_GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <dirent.h>
#include <grp.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/veth.h>
#include <sys/ioctl.h>
#include <libgen.h>
#include <sched.h>

#include "env.h"
#include "env_ops.h"
#include "logger.h"
#include "cgroup.h"
#include "vzerror.h"
#include "util.h"
#include "ub.h"
#include "dev.h"
#include "env_configure.h"
#include "exec.h"
#include "disk.h"
#include "iptables.h"
#include "vzfeatures.h"
#include "vcmm.h"
#include "vzctl_param.h"
#include "sysfs_perm.h"
#include "exec.h"
#include "cleanup.h"

#ifndef HAVE_SETNS

#ifndef __NR_setns
#if defined __i386__
#define __NR_setns	346
#elif defined __x86_64__
#define __NR_setns	308
#else
#error "No setns syscall known for this arch"
#endif
#endif /* ! __NR_setns */
#endif /* ! HAVE_SETNS */


static int sys_setns(int fd, int nstype)
{
	return syscall(__NR_setns, fd, nstype);
}
#define setns sys_setns

int ns_open(void)
{
	if (mkdir(NETNS_RUN_DIR, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH) &&
				errno != EEXIST)
		return vzctl_err(VZCTL_E_CREATE_DIR, errno,
				"Can't create directory " NETNS_RUN_DIR);
	return 0;
}

void ns_close()
{
	return;
}

/*
 * Move self into systemd.
 */
static int move_self_to_systemd(void)
{

	char self[20], fd, len;

	len = snprintf(self, sizeof(self), "%d", getpid());

	fd = open("/sys/fs/cgroup/systemd/tasks", O_RDWR);
	if (fd < 0)
		return vzctl_err(-1, errno, "Can't open /sys/fs/cgroup/systemd/tasks");

	if (write(fd, self, len) == -1) {
		close(fd);
		return vzctl_err(-1, errno,
				"Failed write to /sys/fs/cgroup/systemd/tasks <%s>",
				self);
	}

	close(fd);

	return 0;
}

/* This function is there in GLIBC, but not in headers */
extern int pivot_root(const char * new_root, const char * put_old);
static int setup_rootfs(struct vzctl_env_handle *h)
{
	int ret;
	const char *oldroot = ".old-root";
	const char *root = h->env_param->fs->ve_root;

	logger(10, 0, "* setup rootfs %s", root);

	if (chdir(root))
		return vzctl_err(-1, 0, "Unable to chdir %s", root);

	if (mount("", root, NULL, MS_SLAVE|MS_REC, NULL) < 0)
		return vzctl_err(-1, errno, "Can't make slave %s", root);

	ret = vzctl2_bind_mount(h, h->env_param->bindmount, 0);
	if (ret)
		return ret;

	ret = bindmount_env_cgroup(h);
	if (ret)
		return ret;

	if (access(oldroot, F_OK) && mkdir(oldroot, 0755))
		return vzctl_err(-1, errno, "Can't make dir %s", oldroot);

	if (mount(root, root, NULL, MS_BIND|MS_REC, NULL) < 0)
		return vzctl_err(-1, errno, "Can't bindmount root %s", root);

	if (chdir(root))
		return vzctl_err(1, 0, "Unable to chdir %s", root);

	logger(10, 0, "* pivot_root %s", root);
	if (pivot_root(".", oldroot))
		return vzctl_err(-1, errno, "Can't pivot_root");

	if (chdir("/"))
		return vzctl_err(-1, errno, "Can't chdir /");

	if (mount("", oldroot, NULL, MS_SLAVE|MS_REC, NULL) < 0)
		return vzctl_err(-1, errno, "Can't remount root with MS_PRIVATE");

	if (umount2(oldroot, MNT_DETACH))
		return vzctl_err(-1, errno, "Can't umount old root");

	ret = move_self_to_systemd();
	if (ret)
		return ret;

	if (rmdir(oldroot))
		logger(-1, errno, "Can't rmdir %s", oldroot);

	if (mount(NULL, "/", NULL, MS_SHARED | MS_REC, NULL) < 0)
		return vzctl_err(-1, errno, "Can't remount root as a shared %s",
				root);

	return 0;
}

static int set_virt_osrelease(struct vzctl_env_handle *h, const char *osrelease)
{
	if (osrelease == NULL)
		return 0;

	logger(0, 0, "Os release: %s", osrelease);
	return cg_set_param(EID(h), CG_VE, "ve.os_release", osrelease);
}

static int start_container(struct vzctl_env_handle *h)
{
	if (!is_vz_kernel())
		return 0;

	if (cg_set_param(EID(h), CG_VE, "ve.state", "START") == -1)
		return vzctl_err(VZCTL_E_SYSTEM, 0,
				"Failed to switch CT to the START state");

	return set_virt_osrelease(h, h->env_param->tmpl->osrelease);
}

static int real_ns_env_create(void *arg)
{
	int ret;
	struct start_param *param = (struct start_param *) arg;
	struct vzctl_runtime_ctx *ctx = param->h->ctx;	

	close(param->init_p[1]);
	fcntl(ctx->status_p[1], F_SETFD, FD_CLOEXEC);
	fcntl(ctx->err_p[1], F_SETFD, FD_CLOEXEC);
	fcntl(ctx->wait_p[0], F_SETFD, FD_CLOEXEC);

	/* Wait while user id mappings have been configuraed */
	ret = TEMP_FAILURE_RETRY(read(param->init_p[0], &ret, sizeof(ret)));
	if (ret)
		return VZCTL_E_SYSTEM;

	if (setuid(0) || setgid(0) || setgroups(0, NULL)) {
		ret = vzctl_err(VZCTL_E_SYSTEM, errno, "Unable to set uid or gid");
		goto err;
	}
	/* preload libnss_files.so */
	getgrnam("");

	ret = start_container(param->h);
	if (ret)
		goto err;

	ret = setup_rootfs(param->h);
	if (ret)
		goto err;

	ret = pre_setup_env(param);
	if (ret)
		goto err;

	ret = exec_init(param);
	if (ret)
		goto err;

	return 0;

err:
	if (write(ctx->status_p[1], &ret, sizeof(ret)) == -1 && errno != EPIPE)
		logger(-1, errno, "real_ns_env_create write(param->status_p[1]");

	return ret;
}

static int ns_set_ub(struct vzctl_env_handle *h,
		struct vzctl_ub_param *ub)
{
#define SET_UB_LIMIT(name)						\
	if (ub->name != NULL || h->ctx->state & VZCTL_STATE_STARTING) {	\
		if (cg_env_set_ub(h->ctid, #name,			\
				ub->name ? ub->name->b : LONG_MAX,	\
				ub->name ? ub->name->l : LONG_MAX))	\
			return VZCTL_E_SETUBC;				\
	}

	SET_UB_LIMIT(lockedpages)
	SET_UB_LIMIT(privvmpages)
	SET_UB_LIMIT(shmpages)
	SET_UB_LIMIT(numproc)
	SET_UB_LIMIT(vmguarpages)
	SET_UB_LIMIT(numflock)
	SET_UB_LIMIT(numpty)
	SET_UB_LIMIT(numsiginfo)
	SET_UB_LIMIT(numfile)
	SET_UB_LIMIT(numiptent)
#undef SET_UB_LIMIT
	if (ub->num_memory_subgroups != NULL) {
		if (cg_env_set_memory(h->ctid, "cgroup.subgroups_limit",
						 ub->num_memory_subgroups->l))
			return VZCTL_E_SETUBC;
	}

	if (ub->num_netif != NULL) {
		if (cg_set_ul(EID(h), CG_VE, "ve.netif_max_nr", ub->num_netif->l))
			return VZCTL_E_SETUBC;
	}
	if (ub->kmemsize) {
		if (cg_env_set_memory(h->ctid, CG_KMEM_LIMIT, ub->kmemsize->l))
			return VZCTL_E_SETUBC;
	}

	return 0;
}

#define PAGE_COUNTER_MAX ((unsigned long)LONG_MAX)

static int set_memlimit_iteratively(const char *ctid, unsigned long l,
		unsigned long r)
{
	unsigned long m = l;

	do {
		int rc = cg_env_set_memory(ctid, CG_MEM_LIMIT, m);
		if (rc) {
			if (errno != EBUSY)
				return rc;
			l = m;
		} else {
			r = m;
		}

		m = l + (r - l) / 2;
	} while ((r - l) >  1024 * 1024);

	return 0;
}

static int ns_set_memory_param(struct vzctl_env_handle *h,
		struct vzctl_ub_param *ub, int flags)
{
	int ret = 0;
	int pagesize = get_pagesize();
	float x;
	unsigned long cur_ms, cur_mem, new_ms, new_mem = 0;
	unsigned long cur_mem_usage = 0, cur_ms_usage = 0;

	if (ub->physpages == NULL && ub->swappages == NULL)
		return 0;

	cg_env_get_memory(h->ctid, CG_MEM_USAGE, &cur_mem_usage);
	cg_env_get_memory(h->ctid, CG_SWAP_USAGE, &cur_ms_usage);

	logger(3, 0, "current mem %lu and swap %lu usage",
	       cur_mem_usage, cur_ms_usage);

	ret = cg_env_get_memory(h->ctid, CG_SWAP_LIMIT, &cur_ms);
	if (ret)
		return ret;

	ret = cg_env_get_memory(h->ctid, CG_MEM_LIMIT, &cur_mem);
	if (ret)
		return ret;

	x = ub->swappages ? (float)pagesize * ub->swappages->l : cur_ms;
	x += ub->physpages ? (float)pagesize * ub->physpages->l : cur_mem;
	new_ms = x > PAGE_COUNTER_MAX ? PAGE_COUNTER_MAX : (unsigned long) x;

	if (ub->physpages) {
		x = (float)pagesize * ub->physpages->l;
		new_mem = x > PAGE_COUNTER_MAX ? PAGE_COUNTER_MAX : (unsigned long) x;

		if (new_ms < cur_mem) {
			if (flags & VZCTL_RESTORE)
				ret = set_memlimit_iteratively(h->ctid,
						new_mem, cur_mem);
			else
				ret = cg_env_set_memory(h->ctid, CG_MEM_LIMIT,
						new_mem);
			if (ret)
				goto err;

			ret = cg_env_set_memory(h->ctid, CG_SWAP_LIMIT, new_ms);
			if (ret)
				goto err;
		} else {
			ret = cg_env_set_memory(h->ctid, CG_SWAP_LIMIT, new_ms);
			if (ret)
				goto err;

			if (flags & VZCTL_RESTORE)
				ret = set_memlimit_iteratively(h->ctid,
						new_mem, cur_mem);
			else
				ret = cg_env_set_memory(h->ctid, CG_MEM_LIMIT,
						new_mem);
			if (ret)
				goto err;
		}
	}

	ret = cg_env_set_memory(h->ctid, CG_SWAP_LIMIT, new_ms);
	if (ret)
		goto err;

	return 0;

err:
	return vzctl_err(ret, 0, "Current/set memsw: %lu/%lu mem: %lu/%lu",
			cur_ms, new_ms, cur_mem, new_mem);
}

static int ns_apply_memory_param(struct vzctl_env_handle *h,
		struct vzctl_env_param *env, int update, int flags)
{
	int ret;
	struct vzctl_ub_param *ub;

	if (env->res->ub->physpages == NULL &&
			env->res->slm == NULL &&
			env->res->ub->swappages == NULL &&
			env->res->memguar == NULL)
		return 0;

	ret = get_vswap_param(h, env, &ub);
	if (ret)
		return ret;
#ifdef USE_VCMMD
	if (is_managed_by_vcmmd()) {
		if (h->ctx->state == VZCTL_STATE_STARTING) {
			/* apply parameters to avoid running with
			 * unlimited memory resources until
			 * configuration was activated by vcmmd
			 */
			ret = ns_set_memory_param(h, ub, flags);
		}

		ret = update ? vcmm_update(h, env) : vcmm_register(h, env, ub);
		if (ret) {
			free(env->res->memguar);
			env->res->memguar = NULL;
		}
	} else
#endif
		ret = ns_set_memory_param(h, ub, flags);

	free_ub_param(ub);

	return ret;
}

static int ns_apply_res_param(struct vzctl_env_handle *h,
		struct vzctl_env_param *env, int flags)
{
	int ret;

	if (is_vz_kernel()) {
		ret = ns_set_ub(h, env->res->ub);
		if (ret)
			return ret;
	}


	if (env->res->ub->pagecache_isolation) {
		ret = cg_env_set_memory(EID(h), "memory.disable_cleancache",
			env->res->ub->pagecache_isolation == VZCTL_PARAM_ON ?
				1 : 0);
		if (ret)
			return ret;
	}

	if (env->res->ub->numproc) {
		ret = cg_set_ull(EID(h), CG_PIDS, "pids.max",
				env->res->ub->numproc->l >= PIDS_MAX ?
				PID_MAX_LIMIT :
				env->res->ub->numproc->l);
		if (ret == -1)
			return ret;
	}

	return 0;
}

static int ns_apply_cpu_param(struct vzctl_env_handle *h, struct vzctl_cpu_param *cpu)
{
	int ret;

	if (cpu->units) {
		ret = cg_env_set_cpuunits(h->ctid, *cpu->units);
		if (ret)
			return ret;
	}
	if (cpu->limit_res) {
		logger(0, 0, "CPU limit: %0.1f%%", cpu->limit);
		ret = cg_env_set_cpulimit(h->ctid, cpu->limit);
		if (ret)
			return ret;
	}
	if (cpu->vcpus) {
		ret = cg_env_set_vcpus(h->ctid, *cpu->vcpus);
		if (ret)
			return ret;
	}

	if (cpu->nodemask != NULL || cpu->cpumask != NULL) {
		ret = vzctl2_env_set_node(h, cpu->nodemask, cpu->cpumask);
		if (ret)
			return ret;
	}

	return 0;
}

/* format for net_cls.classid values is 0xAAAABBBB;
 * AAAA is the major handle number and
 * BBBB is the minor handle number.
 */
static int set_net_classid(struct vzctl_env_handle *h)
{
	int ret;
	unsigned int classid = 0;

	if (h->env_param->vz->tc->traffic_shaping != VZCTL_PARAM_ON)
		return 0;

	ret = tc_get_base(h, (int *) &classid);
	if (ret)
		return ret;

	return cg_env_set_net_classid(h->ctid, classid);
}

static int set_features(struct vzctl_env_handle *h,
		struct vzctl_features_param *features)
{
	int ret;
	unsigned long long t;
	unsigned long long known = features->known;
	unsigned long long mask = features->mask;

	ret = cg_set_ull(EID(h), CG_VE, "ve.iptables_mask", get_ipt_mask(features));
	if (ret)
		ret = 0;

	t = tech2features(features->tech);
	mask |= t;
	known |= t;
	if (known) {
		unsigned long long m;

		ret = cg_get_ull(EID(h), CG_VE, "ve.features", &m);
		if (ret)
			return ret;
		m &= ~known;
		m |= (known & mask);
		logger(3, 0, "Set features mask: %LX", m);
		ret = cg_set_ull(EID(h), CG_VE, "ve.features", m);
		if (ret)
			return ret;
	}

	return 0;
}

static int setup_env_cgroup(struct vzctl_env_handle *h, struct vzctl_env_param *env, int flags)
{
	int ret;

	if (flags & VZCTL_SKIP_SETUP)
		return 0;

	ret = set_features(h, env->features);
	if (ret)
		return ret;

	ret = ns_apply_memory_param(h, h->env_param, 0, flags);
	if (ret)
		return ret;

	if (flags & VZCTL_RESTORE && h->env_param->res->ub->physpages) {
		struct vzctl_2UL_res physpages = {
			.l = h->env_param->res->ub->physpages->l * 2,
			.b = h->env_param->res->ub->physpages->b * 2,
		};
		struct vzctl_2UL_res swappages = {
			.l = ULONG_MAX,
			.b = ULONG_MAX
		};
		struct vzctl_ub_param ub = {
			.physpages = &physpages,
			.swappages = &swappages,
		};

		ret = ns_set_memory_param(h, &ub, 0);
	}

	return ret;
}

static int init_env_cgroup(struct vzctl_env_handle *h, int flags)
{
	int ret, i;
	char buf[4096];
	struct vzctl_disk *d;
	const char *devices[] = {
		"c *:* m",		/* anyone can mknod for char devices */
		"b *:* m",		/* same for block devices */
		"c 128:* rmw",		/* unix98 pty masters */
		"c 136:* mrw",		/* unix98 pty slaves */
		"c 2:* rmw",		/* pty masters */
		"c 3:* rmw",		/* pty slaves */
		"c 1:3 rmw",		/* null */
		"c 1:5 rmw",		/* zero */
		"c 1:7 rmw",		/* full */
		"c 5:0 rmw",		/* tty */
		"c 5:1 rmw",		/* console */
		"c 5:2 rmw",		/* ptmx */
		"c 4:* rmw",		/* tty{N} devices (virtual terminals} */
		"c 1:8 rmw",		/* random */
		"c 1:9 rmw",		/* urandom */
		"c 1:11 rmw",		/* kmsg */
		"c 10:200 rmw",		/* tun */
		"c 10:235 rwm",		/* autofs */
		"c 10:229 rwm",		/* fuse */
	};
	char *cpu[] = {
		"cpuset.cpus",
		"cpuset.mems"
	};
	char *bc[] = {
		"beancounter.memory",
		"beancounter.blkio",
		"beancounter.pids"
	};

	logger(10, 0, "* init Container cgroup");
	if (h->veid && cg_set_veid(EID(h), h->veid) == -1)
		return vzctl_err(VZCTL_E_SYSTEM, 0,
				"Failed to set VEID=%u", h->veid);

	/* Bind beancounter with blkio/memory/pids cgroups */
	for (i = 0; i < sizeof(bc)/sizeof(bc[0]); i++) {
		snprintf(buf, sizeof(buf), "/%s/%s", cg_get_slice_name(), EID(h));
		ret = cg_set_param(EID(h), CG_UB, bc[i], buf);
		if (ret == -1)
			return ret;
	}

	ret = cg_env_set_memory(h->ctid, "memory.use_hierarchy", 1);
	if (ret)
		return ret;

	/* Init cpu: copy settings from parent */
	for (i = 0; i < sizeof(cpu)/sizeof(cpu[0]); i++) {
		ret = cg_get_param("", CG_CPUSET, cpu[i], buf, sizeof(buf));
		if (ret)
			return -1;

		if (buf[0] == '\0') {
			/* Setup parent */
			ret = cg_get_param(NULL, CG_CPUSET, cpu[i], buf,
					sizeof(buf));
			if (ret)
				return -1;

			ret = cg_set_param("", CG_CPUSET, cpu[i], buf);
			if (ret)
				return ret;
		}

		ret = cg_set_param(h->ctid, CG_CPUSET, cpu[i], buf);
		if (ret)
			return ret;
	}

	/* Init devices: set default perm */
	ret = cg_env_set_devices(h->ctid, "devices.deny", "a");
	if (ret)
		return ret;

	for (i = 0; i <  sizeof(devices)/sizeof(devices[0]); i++) {
		ret = cg_env_set_devices(h->ctid, "devices.allow", devices[i]);
		if (ret)
			return vzctl_err(-1, 0, "Failed to set %s", devices[i]);
	}

	list_for_each(d, &h->env_param->disk->disks, list) {
		if (d->enabled == VZCTL_PARAM_OFF)
			continue;
		if (!is_root_disk(d)) {
			ret = configure_mount_opts(h, d);
			if (ret)
				return ret;
		}

		ret = configure_disk_perm(h, d, 0);
		if (ret)
			return ret;
	}

	return setup_env_cgroup(h, h->env_param, flags);
}

static int destroy_cgroup(struct vzctl_env_handle *h)
{
	char nspath[STR_SIZE];
	pid_t pid;

	logger(10, 0, "* Destroy cgroup");
	relase_venet_ips(h);
	get_netns_path(h, nspath, sizeof(nspath));
	if (unlink(nspath) && errno != ENOENT)
		logger(-1, errno, "Failed to unlink %s", nspath);

	if (cg_env_get_init_pid(h->ctid, &pid) == 0 && pid != 0) {
		logger(10, 0, "* Kill pid=%d", pid);
		kill(pid, SIGKILL);
	}

	return cg_destroy_cgroup(h->ctid);
}

static int create_cgroup(struct vzctl_env_handle *h, int flags)
{
	int ret;

	ret = destroy_cgroup(h);
	if (ret)
		return ret;

	logger(10, 0, "* Create cgroup");
	ret = cg_new_cgroup(h->ctid);
	if (ret)
		return ret;

	ret = init_env_cgroup(h, flags);
	if (ret)
		return ret;

	return 0;
}

static int wait_on_pipe(const char *msg, int status_p)
{
	int ret, errcode = 0;

	logger(10, 0, "* Wait status %s pid=%d", msg, getpid());
	ret = TEMP_FAILURE_RETRY(read(status_p, &errcode, sizeof(errcode)));
	logger(10, 0, "* Done wait status %s ret=%d errcode=%d", msg, ret, errcode);
	if (ret == -1)
		return vzctl_err(VZCTL_E_SYSTEM, errno, "Failed to %s the Container,"
				" read from status pipe is failed", msg);
	if (ret == 0)
		return vzctl_err(VZCTL_E_SYSTEM, 0, "Failed to %s the Container,"
				" status pipe unexpectedly closed", msg);
	return errcode;
}

static int write_id_maps(int pid)
{
	int fd, i;
	char path[PATH_MAX];
	const char id[] = "0 0 4294967295";

	logger(10, 0, "Setup ugid mappings: %s", id);
	for (i = 0; i < 2; i++) {
		if (i == 0)
			snprintf(path, sizeof(path), "/proc/%d/gid_map", pid);
		else
			snprintf(path, sizeof(path), "/proc/%d/uid_map", pid);

		fd = open(path, O_WRONLY);
		if (write(fd, id, sizeof(id)) != sizeof(id)) {
			int saved_errno = errno;
			close(fd);
			return vzctl_err(VZCTL_E_SYSTEM, saved_errno, "Unable to write id mappings");
		}
		close(fd);
	}

	return 0;
}

static int reset_loginuid()
{
	int fd;
	static const char luid[] = "4294967295";

	logger(10, 0, "Reset loginuid");
	fd = open("/proc/self/loginuid", O_RDWR);
	if (fd == -1) {
		if (errno == ENOENT)
			return 0;
		return vzctl_err(-1, errno, "Cannot open /proc/self/loginuid");
	}

	if (write(fd, luid, sizeof(luid) -1) == -1) {
		vzctl_err(-1, errno, "Cannot reset loginuid");
		close(fd);

		return -1;
	}

	close(fd);

	return 0;
}

static int do_env_create(struct vzctl_env_handle *h, struct start_param *param)
{
	char child_stack[4096 * 10];
	int ret;
	pid_t pid = -1;
	int clone_flags = 0;
	struct sigaction act;
	int flags = param->fn ? VZCTL_RESTORE : 0;

	sigemptyset(&act.sa_mask);
	act.sa_handler = SIG_IGN;
	act.sa_flags = SA_NOCLDSTOP;
	sigaction(SIGPIPE, &act, NULL);

	ret = make_dir(VZCTL_VE_RUN_DIR, 1);
	if (ret)
		return ret;

	ret = create_cgroup(h, flags);
	if (ret)
		goto err;

	ret = cg_enable_pseudosuper(h->ctid);
	if (ret && errno != ENOENT)
		goto err;

	ret = cg_pseudosuper_open(h->ctid, &param->pseudosuper_fd);
	if (ret && errno != ENOENT)
		goto err;

	/*
	 * When plain container start we should
	 * exec init from inside of VE and other
	 * cgroups, in turn restore procedure
	 * always start on VE0 so joining inside
	 * VEX made by CRIU. Still we have to
	 * enter the rest of cgoups to properly
	 * hide cgroup roots in /proc/$pid/cgroup
	 * from inside of container (grep CGRP_VE_ROOT
	 * in kernel source code).
	 */
	if (!param->fn) {
		ret = cg_attach_task(h->ctid, getpid(), NULL);
		if (ret)
			goto err;
	} else {
		ret = cg_attach_task(h->ctid, getpid(), CG_VE);
		if (ret)
			goto err;
	}

	if (param->fn != NULL) {
		ret = param->fn(h, param);
		if (ret)
			goto err;
	} else {
		int init_p[2];

		if (reset_loginuid()) {
			ret = VZCTL_E_SYSTEM;
			goto err;
		}

		if (pipe(init_p)) {
			ret = vzctl_err(VZCTL_E_PIPE, errno, "Cannot create pipe");
			goto err;
		}
		param->init_p = init_p;

		clone_flags |= CLONE_NEWUTS|CLONE_NEWPID|CLONE_NEWIPC|
			CLONE_NEWNET|CLONE_NEWNS|CLONE_NEWUSER;
		pid = clone(real_ns_env_create,
				child_stack + sizeof(child_stack),
				clone_flags|SIGCHLD , (void *) param);
		if (pid < 0) {
			ret = vzctl_err(VZCTL_E_RESOURCE, errno, "Unable to clone");
			goto err;
		}
		
		ret = write_init_pid(h->ctid, pid);
		if (ret == 0) {
			ret = write_id_maps(pid);
			close(param->init_p[1]);
		}
		if (ret)
			goto err;

		char nspath[STR_SIZE];
		char pidpath[STR_SIZE];

		/* Setup netns link */
		get_netns_path(h, nspath, sizeof(nspath));
		snprintf(pidpath, sizeof(pidpath), "/proc/%d/ns/net", pid);
		unlink(nspath);
		if (symlink(pidpath, nspath)) {
			ret = vzctl_err(VZCTL_E_SYSTEM, errno,
					"Can't symlink into netns file %s", nspath);
			goto err;
		}
	}

err:

	if (ret) {
		if (pid != -1)
			kill(pid, SIGKILL);
#if USE_VCMMD
		vcmm_unregister(h);
#endif
	}

	if (param->pseudosuper_fd != -1)
		close(param->pseudosuper_fd);

	return ret;
}

static int ns_env_create(struct vzctl_env_handle *h, struct start_param *param)
{
	int ret;
	struct vzctl_runtime_ctx *ctx = param->h->ctx;

	param->pid = fork();
	if (param->pid < 0) {
		return vzctl_err(VZCTL_E_FORK, errno, "Cannot fork");
	} else if (param->pid == 0) {
		close(ctx->status_p[0]); ctx->status_p[0] = -1;
		close(ctx->err_p[0]); ctx->err_p[0] = -1;
		close(ctx->wait_p[1]); ctx->wait_p[1] = -1;
		ret = do_env_create(h, param);
		if (ret && write(ctx->status_p[1], &ret, sizeof(ret)) == -1)
			vzctl_err(-1, errno, "ns_env_create: failed to write to the status pipe");
		_exit(ret);
	}

	close(ctx->status_p[1]); ctx->status_p[1] = -1;
	close(ctx->err_p[1]); ctx->err_p[1] = -1;
	close(ctx->wait_p[0]);ctx->wait_p[0] = -1;

	return wait_on_pipe("start", ctx->status_p[0]);
}

static int ns_is_env_run(struct vzctl_env_handle *h)
{
	return cg_env_get_ve_state(EID(h));
}

int set_ns(pid_t pid, const char *name, int flags)
{
	int ret, fd;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "/proc/%d/ns/%s", pid, name);
	if ((fd = open(path, O_RDONLY)) < 0)
		return vzctl_err(-1, errno, "Failed to open %s", path);

	logger(10, 0, "* attach to %s", name);
	ret = setns(fd, flags);
	if (ret)
		logger(-1, errno, "Failed to set context for %s", name);
	close(fd);

	return ret;
}

int enter_net_ns(struct vzctl_env_handle *h, pid_t *ct_pid)
{
	pid_t pid;
	int i;
	const char *ns[] = {"net", "uts", "ipc", "pid"};

	if (cg_env_get_init_pid(h->ctid, &pid))
		return -1;

	for (i = 0; i < sizeof(ns) / sizeof(ns[0]); ++i)
		if (set_ns(pid, ns[i], 0))
			return vzctl_err(-1, errno,
					"Cannot switch to namespace %s", ns[i]);
	if (ct_pid != NULL)
		*ct_pid = pid;

	return 0;
}

static int ns_env_enter(struct vzctl_env_handle *h, int flags)
{
	DIR *dp;
	struct dirent *ep;
	pid_t pid;
	char path[PATH_MAX];
	int ret;

	ret = reset_loginuid();
	if (ret)
		return ret;

	if (cg_env_get_init_pid(h->ctid, &pid))
		return vzctl_err(VZCTL_E_SYSTEM, 0, "Unable to get init pid");

	logger(10, 0, "* Attach by pid %d", pid);

	snprintf(path, sizeof(path), "/proc/%d/ns", pid);
	dp = opendir(path);
	if (dp == NULL)
		return vzctl_err(-1, errno, "Unable to open dir %s", path);

	ret = cg_attach_task(EID(h), getpid(), NULL);
	if (ret)
		goto err;

	while ((ep = readdir (dp))) {
		if (!strcmp(ep->d_name, ".") ||
		    !strcmp(ep->d_name, ".."))
			continue;

		ret = set_ns(pid, ep->d_name, 0);
		if (ret)
			goto err;
	}

	/* Clear supplementary group IDs */
	if (setgroups(0, NULL)) {
		ret = vzctl_err(-1, errno, "ns_env_enter: setgroups()");
		goto err;
	}
	
	ret = set_personality32();

err:
	closedir(dp);

	return ret;
}

static int ns_env_exec(struct vzctl_env_handle *h, struct exec_param *param,
		int flags, pid_t *pid)
{
	int ret;
	pid_t pid2;

	*pid = fork();
	if (*pid < 0) {
		return vzctl_err(VZCTL_E_FORK, errno, "Cannot fork");
	} else if (*pid == 0) {
		struct vzctl_cleanup_hook *hook;

		ret = ns_env_enter(h, flags);
		if (ret)
			goto err;
		/* Extra fork to apply setns() */
		pid2 = fork();
		if (pid2 < 0) {
			ret = vzctl_err(VZCTL_E_FORK, errno, "Cannot fork");
			goto err;
		} else if (pid2 == 0) {
			if (setsid() == -1) {
				ret = vzctl_err(VZCTL_E_SYSTEM, errno, "setsid");
				_exit(ret);
			}

			ret = real_env_exec(h, param, flags);

			_exit(ret);
		}

		hook = register_cleanup_hook(cleanup_kill_process, (void *) &pid2);
		close_array_fds(VZCTL_CLOSE_STD, NULL, -1);

		if (param->timeout)
			set_timeout_handler(pid2, param->timeout);

		ret = env_wait(pid2, param->timeout, NULL);
		unregister_cleanup_hook(hook);
err:

		_exit(ret);
	}

	return 0;
}

static int ns_env_exec_fn(struct vzctl_env_handle *h, execFn fn, void *data,
		int *data_fd, int timeout, int flags, pid_t *pid)
{
	int ret;
	pid_t pid2;

	fflush(stderr);
	fflush(stdout);

	*pid = fork();
	if (*pid < 0) {
		return vzctl_err(VZCTL_E_FORK, errno, "Cannot fork");
	} else if (*pid == 0) {
		ret = ns_env_enter(h, flags);
		if (ret)
			goto err;

		pid2 = fork();
		if (pid2 < 0) {
			ret = vzctl_err(VZCTL_E_FORK, errno, "Cannot fork");
			goto err;
		} else if (pid2 == 0) {
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

static int write_sunrpc_kill(pid_t pid)
{
	int fd;
	ssize_t res;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "/proc/%d/net/rpc/kill-tasks", pid);
	fd = open(path, O_WRONLY);
	if (fd == -1) {
		if (errno == ENOENT)
			return 0;
		return vzctl_err(-1, errno, "Failed to open %s", path);
	}

	res = write(fd, "1", 2);
	close(fd);
	if (res != 2)
		return vzctl_err(-1, errno, "Unable to suppress SUNRPC traffic");

	return 1;
}

int ns_env_kill(struct vzctl_env_handle *h)
{
	int ret;
	struct vzctl_str_param *it;
	LIST_HEAD(pids);

	ret = cg_env_get_pids(EID(h), &pids);
	if (ret)
		return ret;

	list_for_each(it, &pids, list) {
		unsigned long pid;

		if (parse_ul(it->str, &pid)) {
			vzctl_err(-1, 0, "ns_env_kill: invalid pid %s", it->str);
			continue;
		}

		write_sunrpc_kill(pid);

		logger(5, 0, "kill CT process pid %lu", pid);
		if (kill(pid, SIGKILL) && errno != ESRCH)
			vzctl_err(-1, errno, "Failed to kill CT pid=%lu", pid);
	}

	free_str(&pids);

	return 0;
}

static int ns_env_stop_force(struct vzctl_env_handle *h)
{
	int ret, rc;

	logger(0, 0, "Forcibly stop the Container...");

	ret = ns_env_kill(h);
	if (ret)
		return ret;

	ret = cg_freezer_cmd(EID(h), VZCTL_CMD_FREEZE);
	if (ret)
		return ret;

	rc = ns_env_kill(h);

	/* Unfreeze unconditionally */
	ret = cg_freezer_cmd(EID(h), VZCTL_CMD_RESUME);
	if (ret || rc)
		return ret ?: rc;

	if (wait_env_state(h, VZCTL_ENV_STOPPED, MAX_SHTD_TM))
		return vzctl_err(-1, 0, "Failed to stop Container:"
				" operation timed out");
	return 0;
}

static int ns_env_cleanup(struct vzctl_env_handle *h, int flags)
{
	char x[] = "XXXX";
#ifdef USE_VCMMD
	vcmm_unregister(h);
#endif
	clear_init_pid(EID(h));
	if (get_global_param("SKIP_CGROUP_DESTROY", x, sizeof(x)) == 0 &&
			strcmp(x, "yes") == 0)
		return 0;

	return destroy_cgroup(h);
}

static int ns_env_stop(struct vzctl_env_handle *h, int stop_mode)
{
	int ret;
	pid_t pid;

	if (stop_mode == M_KILL_FORCE || stop_mode == M_KILL) {
		ret = -1;
		goto force;
	}

	pid = fork();
	if (pid == 0) {
		pid_t pid2;

		ret = ns_env_enter(h, 0);
		if (ret)
			_exit(ret);
		close_fds(1, -1);
		pid2 = fork();
		if (pid2 == -1) {
			ret = vzctl_err(VZCTL_E_FORK, errno, "failed to fork");
			 _exit(ret);
		} else if (pid2 == 0) {
			ret = real_env_stop(stop_mode);
			_exit(ret);
		}

		ret = env_wait(pid2, 0, NULL);
		_exit(ret);
	} else if (pid == -1) {
		ret = vzctl_err(VZCTL_E_FORK, errno, "failed to fork");
		goto force;
	}

	ret = wait_env_state(h, VZCTL_ENV_STOPPED, MAX_SHTD_TM);
	if (ret) {
		logger(0, 0, "Container stop timeout has expired");
		kill(pid, SIGKILL);
	}
	env_wait(pid, 0, NULL);

force:
	if (ret) {
		ret = ns_env_stop_force(h);
		if (ret)
			goto out;
	}

out:
	return ret ? VZCTL_E_ENV_STOP : 0;
}

static int ns_set_devperm(struct vzctl_env_handle *h, struct vzctl_dev_perm *dev)
{
	char dev_str_part[STR_SIZE];
	char dev_str[STR_SIZE];
	char perms[5];
	int i = 0;
	int deny = 0;
	int ret;

	if (dev->mask & S_IXGRP)
		return 0;

	if (dev->mask & S_IROTH)
		perms[i++] = 'r';
	if (dev->mask & S_IWOTH)
		perms[i++] = 'w';
	if (dev->mask & S_IXUSR)
		perms[i++] = 'M';

	/* if no perm specifyed deny device */
	if (i == 0)
		deny = 1;
	perms[i++] = 'm'; /* mknod */
	perms[i] = '\0';

	if (dev->use_major)
		snprintf(dev_str_part, sizeof(dev_str_part), "%c %d:*",
			S_ISBLK(dev->type) ? 'b' : 'c',
			major(dev->dev));
	else
		snprintf(dev_str_part, sizeof(dev_str_part), "%c %d:%d",
			S_ISBLK(dev->type) ? 'b' : 'c',
			major(dev->dev), minor(dev->dev));

	snprintf(dev_str, sizeof(dev_str), "%s rwmM", dev_str_part);
	ret = cg_env_set_devices(h->ctid, "devices.deny", dev_str);
	if (ret) {
		snprintf(dev_str, sizeof(dev_str), "%s rwm", dev_str_part);
		ret = cg_env_set_devices(h->ctid, "devices.deny", dev_str);
	}
	if (ret || deny)
		return ret;

	snprintf(dev_str, sizeof(dev_str), "%s %s", dev_str_part, perms);
	return cg_env_set_devices(h->ctid, "devices.allow", dev_str);
}

static int ns_set_cpumask(struct vzctl_env_handle *h, struct vzctl_cpumask *cpumask)
{
	return cg_env_set_cpumask(h->ctid, cpumask->mask, sizeof(cpumask->mask));
}

static int ns_set_nodemask(struct vzctl_env_handle *h, struct vzctl_nodemask *nodemask)
{
	return cg_env_set_nodemask(h->ctid, nodemask->mask, sizeof(nodemask->mask));
}

static int ns_env_apply_param(struct vzctl_env_handle *h,
		struct vzctl_env_param *env, int flags)
{
	int ret;

	if (flags & VZCTL_RESTORE) {
		char f[PATH_MAX];
		pid_t p;

		get_criu_pidfile(h->ctid, f);
		if (read_pid(f, &p) == 0) {
			ret = cg_attach_task(NULL, p, CG_VE);
			if (ret)
				return ret;
		}
		unlink(f);

		struct vzctl_ub_param ub = {
			.physpages = h->env_param->res->ub->physpages,
			.swappages = h->env_param->res->ub->swappages,
		};

		ret = ns_set_memory_param(h, &ub, flags);
		if (ret)
			return ret;
	}

	if (ns_is_env_run(h)) {
		if (h->ctx->state == VZCTL_STATE_STARTING) {
			ret = set_net_classid(h);
			if (ret)
				return ret;
		}

		if (h->ctx->state != VZCTL_STATE_STARTING) {
			ret = ns_apply_memory_param(h, env, 1, flags);
			if (ret)
				return ret;
		}
		ret = ns_apply_res_param(h, env, flags);
		if (ret)
			return ret;
		ret = vzctl_setup_disk(h, env->disk, flags);
		if (ret)
			return ret;
		ret = ns_apply_cpu_param(h, env->cpu);
		if (ret)
			return ret;
		ret = apply_io_param(h, env, flags);
		if (ret)
			return ret;
		ret = apply_dev_param(h, env, flags);
		if (ret)
			return ret;
		ret = apply_venet_param(h, env, flags);
		if (ret)
			return ret;
		ret = apply_veth_param(h, env, flags);
		if (ret)
			return ret;
		ret = apply_netdev_param(h, env, flags);
		if (ret)
			return ret;
		if ((ret = vzctl_apply_tc_param(h, env, flags)))
			return ret;
		ret = apply_quota_param(h, env, flags);
		if (ret)
			return ret;
		ret = vzctl_env_configure(h, env, flags);
		if (ret)
			return ret;

		if (h->ctx->state == VZCTL_STATE_STARTING) {
			ret = env_console_configure(h, flags);
			if (ret)
				return ret;
#ifdef USE_VCMMD
			ret = vcmm_activate(h);
#endif
			if (ret)
				return ret;
		}
	}

	return 0;
}

static int ns_dummy(struct vzctl_env_handle *h)
{
	return 0;
}

static int get_feature(void)
{
	return 0;
}

static int env_dump(struct vzctl_env_handle *h, int cmd,
		struct vzctl_cpt_param *param)
{
	int ret;
	struct vzctl_runtime_ctx *ctx = h->ctx;

	logger(0, 0, "Dumping CT to %s", param->dumpfile);
	ctx->pid = fork();
	if (ctx->pid == -1) {
		return vzctl_err(VZCTL_E_FORK, errno, "Cannot fork");
	} else if (ctx->pid == 0) {
		close(ctx->status_p[0]); ctx->status_p[0] = -1;
		close(ctx->wait_p[1]); ctx->wait_p[1] = -1;

		ret = criu_cmd(h, cmd, param, NULL);
		_exit(ret);
	}

	close(ctx->status_p[1]); ctx->status_p[1] = -1;
	close(ctx->wait_p[0]); ctx->wait_p[0] = -1;

	ret = wait_on_pipe("dump", ctx->status_p[0]);
	ctx->state = VZCTL_STATE_CHECKPOINTING;

	return ret;
}

static int env_resume(struct vzctl_env_handle *h, int status)
{
	int ret = 0;

	if (h->ctx->state != VZCTL_STATE_CHECKPOINTING)
		return vzctl_err(VZCTL_E_INVAL, 0,
				"state != VZCTL_STATE_CHECKPOINTING");

	logger(0, 0, "\tpost dump");
	if (write(h->ctx->wait_p[1], &status, sizeof(status)) == -1) {
		if (status && errno != EPIPE)
			ret = vzctl_err(VZCTL_E_SYSTEM, errno, "Failed to resume");
	}

	p_close(h->ctx->wait_p);

	env_wait(h->ctx->pid, 0, &ret);
	h->ctx->pid = -1;

	cg_freezer_cmd(EID(h), VZCTL_CMD_RESUME);

	return ret;
}

static int ns_env_chkpnt(struct vzctl_env_handle *h, int cmd,
		struct vzctl_cpt_param *param, int flags)
{
	switch(cmd) {
	case VZCTL_CMD_SUSPEND:
		return cg_freezer_cmd(EID(h), VZCTL_CMD_SUSPEND);
	case VZCTL_CMD_RESUME:
		if (h->ctx->state == VZCTL_STATE_CHECKPOINTING)
			return env_resume(h, flags);
		return cg_freezer_cmd(EID(h), cmd);
	case VZCTL_CMD_DUMP:
	case VZCTL_CMD_DUMP_LEAVE_FROZEN:
		return env_dump(h, cmd, param);
	case VZCTL_CMD_CHKPNT:
		return criu_cmd(h, cmd, param, NULL);
	default:
		return vzctl_err(VZCTL_E_INVAL, 0,
				"ns_env_chkpnt: Unsupported action %d", cmd);
	}
}

static int restore_FN(struct vzctl_env_handle *h, struct start_param *data)
{
	int ret;
	struct vzctl_cpt_param *cpt = (struct vzctl_cpt_param *)data->data;

	ret = criu_cmd(h, VZCTL_CMD_RESTORE, cpt, data);
	if (write(h->ctx->err_p[1], &ret, sizeof(ret)) == -1)
		vzctl_err(-1, errno, "Failed to write to the error pipe");

	return ret;
}

int ns_env_restore(struct vzctl_env_handle *h, struct start_param *start_param,
		struct vzctl_cpt_param *param, int flags)
{
	start_param->fn = restore_FN;
	start_param->data = param;

	return get_env_ops()->env_create(h, start_param);
}

static int ns_env_cpt_cmd(struct vzctl_env_handle *h, int action, int cmd,
                struct vzctl_cpt_param *param, int flags)
{
	switch (cmd) {
	case VZCTL_CMD_KILL:
		return ns_env_stop_force(h);
	case VZCTL_CMD_DUMP:
		return criu_cmd(h, cmd, param, NULL);
	default:
		return ns_env_chkpnt(h, cmd, param, flags);
	}
}

static int ns_env_get_cpt_state(struct vzctl_env_handle *h, int *state)
{
	char buf[STR_SIZE];
	int ret;

	ret = cg_get_param(EID(h), CG_FREEZER, "freezer.state", buf, sizeof(buf));
	if (ret)
		return ret;

	if (strcmp(buf, "FROZEN") == 0)
		*state |= ENV_STATUS_CPT_SUSPENDED;

	return 0;
}

static int ns_ip_ctl(struct vzctl_env_handle *h, int op, const char *ip, int flags)
{
	if (!is_vz_kernel())
		return vzctl_err(0, 0, "Warning: venet support is not emplemented");

	switch (op) {
	case VE_IP_ADD:
		return cg_add_veip(EID(h), ip);
	case VE_IP_DEL:
		return cg_del_veip(EID(h), ip);
	default:
		return vzctl_err(VZCTL_E_INVAL, 0, "ns_ip_ctl: invalid op %d", op);
	}
}

static int ns_get_veip(struct vzctl_env_handle *h, list_head_t *list)
{
	return cg_get_veip(EID(h), list);
}

static int _set_mac_filter(struct vzctl_env_handle *h,
		struct vzctl_veth_dev *veth)
{
	int sk, ret;
	struct ifreq req = {};
	int deny = veth->mac_filter == VZCTL_PARAM_OFF ? 0 : 1;

	logger(3, 0, "%s to change mac for %s",
			deny ? "Deny" : "Allow",
			veth->dev_name_ve);

	if (enter_net_ns(h, NULL))
		return -1;

	sk = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0)
		return vzctl_err(-1, errno, "Can't create socket");

	strncpy(req.ifr_ifrn.ifrn_name, veth->dev_name_ve,
			sizeof(req.ifr_ifrn.ifrn_name) - 1);
	req.ifr_ifru.ifru_flags = deny;

	ret = ioctl(sk, SIOCSFIXEDADDR, &req);
	if (ret)
		ret = vzctl_err(-1, errno, "ioctl SIOCSFIXEDADDR %s",
				veth->dev_name);
	close(sk);

	return ret;
}

static int set_mac_filter(struct vzctl_env_handle *h,
		struct vzctl_veth_dev *veth)
{
	pid_t pid;

	pid = fork();
	if (pid < 0)
		return vzctl_err(-1, errno, "Cannot fork");
	else if (pid == 0)
		_exit(_set_mac_filter(h, veth));

	return env_wait(pid, 0, NULL);
}

static int veth_configure(struct vzctl_env_handle *h,
		struct vzctl_veth_dev *veth)
{
	int sk, ret;
	struct ifreq req = {};

	sk = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0)
		return vzctl_err(VZCTL_E_VETH, errno, "Can't creaet socket");

	strncpy(req.ifr_ifrn.ifrn_name, veth->dev_name,
			sizeof(req.ifr_ifrn.ifrn_name)-1);
	ret = VZCTL_E_VETH;
	if (ioctl(sk, SIOCSVENET, &req)) {
		logger(-1, errno, "ioctl SIOCSVENET %s",
				veth->dev_name);
		goto err;
	}

	if (veth->mac_filter && set_mac_filter(h, veth))
		goto err;

	ret = 0;

err:
	close(sk);

	return ret;
}

/*
 * This function is the simplest one among the network handling functions.
 * It will create a veth pair, and move one of its ends to the container.
 *
 * MAC addresses and Bridge parameters are optional
 */
static int veth_ctl(struct vzctl_env_handle *h, int op,
		struct vzctl_veth_dev *dev, int flags)
{
	int ret = 0;
	char *arg[] = { NULL, NULL };
	char *envp[11];
	char buf[STR_SIZE];
	char script[PATH_MAX];
	int i = 0;

	snprintf(buf, sizeof(buf), "VEID=%s", EID(h));
	envp[i++] = strdup(buf);

	snprintf(buf, sizeof(buf), "VNAME=%s", dev->dev_name_ve);
	envp[i++] = strdup(buf);

	if (dev->mac_ve) {
		snprintf(buf, sizeof(buf), "VMAC=%s" , dev->mac_ve);
		envp[i++] = strdup(buf);
	}

	if (dev->mac) {
		snprintf(buf, sizeof(buf), "HMAC=%s", dev->mac);
		envp[i++] = strdup(buf);
	}

	if (dev->dev_name[0] != '\0') {
		snprintf(buf, sizeof(buf), "HNAME=%s", dev->dev_name);
		envp[i++] = strdup(buf);
	}

	envp[i] = NULL;

	arg[0] = get_script_path((op == ADD) ? VZCTL_NETNS_DEV_ADD : VZCTL_NETNS_DEV_DEL,
			script, sizeof(script));
	if (vzctl2_wrap_exec_script(arg, envp, 0))
		ret = VZCTL_E_VETH;

	free_ar_str(envp);

	return ret;
}

static int ns_veth_ctl(struct vzctl_env_handle *h, int op,
		struct vzctl_veth_dev *dev, int flags)
{
	int ret;

	if (flags & VZCTL_RESTORE)
		return 0;

	ret = veth_ctl(h, op, dev, flags);
	if (ret)
		return ret;

	if (op == ADD)
		ret = veth_configure(h, dev);

	return ret;
}

static int ns_netdev_ctl(struct vzctl_env_handle *h, int add, const char *dev)
{
	int ret;
	char script[PATH_MAX];
	char sysfs[PATH_MAX];
	char id_s[STR_SIZE];
	char vname_s[STR_SIZE];
	char hname_s[STR_SIZE];
	char *arg[] = {script, NULL};
	char *envp[] = {id_s, vname_s, hname_s, NULL};
	const char *mode = "-";

	logger(0, 0, "%s the network device: %s", add ? "Add" : "Delete", dev);

	if (add) {
		ret = get_sysfs_device_path("net", dev, sysfs, sizeof(sysfs));
		if (ret)
			return ret;
		mode = "rwx";
	}

	snprintf(id_s, sizeof(id_s), "VEID=%s", EID(h));
	snprintf(vname_s, sizeof(vname_s), "VNAME=%s", dev);
	snprintf(hname_s, sizeof(hname_s), "HNAME=%s", dev);
	get_script_path(add ? VZCTL_NETNS_DEV_ADD : VZCTL_NETNS_DEV_DEL,
			script, sizeof(script));
	if (vzctl2_wrap_exec_script(arg, envp, 0))
		return VZCTL_E_NETDEV;

	if (!add) {
		/* get sysfs device name after it moved on host */
		ret = get_sysfs_device_path("net", dev, sysfs, sizeof(sysfs));
		if (ret)
			return ret;
	}

	return add_sysfs_dir(h, dirname(sysfs), NULL, mode);
}

static int ns_set_iolimit(struct vzctl_env_handle *h, unsigned int speed)
{
	logger(0, 0, "Set up iolimit: %u", speed);
	if (cg_env_set_iolimit(EID(h), speed, speed * 3, 10*1000))
		return VZCTL_E_SET_IO;

	return 0;
}

static int ns_get_iolimit(struct vzctl_env_handle *h, unsigned int *speed)
{
	int ret;
	unsigned long n;

	ret = cg_get_ul(EID(h), CG_UB, CG_UB".iolimit.speed", &n);

	*speed = (unsigned int) n;

	return ret;
}

static int ns_set_ioprio(struct vzctl_env_handle *h, int prio)
{
	static unsigned long ioprio_weight[] = {
		320, 365, 410, 460, 500, 550, 600, 640
	};

	if (prio < 0 || prio > sizeof(ioprio_weight)/sizeof(ioprio_weight[0]))
		return vzctl_err(VZCTL_E_INVAL, 0,
				"Invalid ioprio %d", prio);

	logger(0, 0, "Set up ioprio: %d", prio);
	if (cg_set_ul(EID(h), CG_BLKIO, "blkio.weight", ioprio_weight[prio]))
		return VZCTL_E_SET_IO;

	return 0;
}

static int ns_set_iopslimit(struct vzctl_env_handle *h, unsigned int speed)
{
	logger(0, 0, "Set up iopslimit: %u", speed);
	if (cg_env_set_iopslimit(EID(h), speed, speed * 3, 10*1000))
		return VZCTL_E_SET_IO;

	return 0;
}

static int ns_get_iopslimit(struct vzctl_env_handle *h, unsigned int *speed)
{
	int ret;
	unsigned long n;

	ret = cg_get_ul(EID(h), CG_UB, CG_UB".iopslimit.speed", &n);
	*speed = (unsigned int) n;

	return ret;
}

static int ns_get_runtime_param(struct vzctl_env_handle *h, int flags)
{
	float limit = 0;
	unsigned int iolimit = 0, iopslimit = 0;

	if (!ns_is_env_run(h))
		return 0;

	if (cg_env_get_cpulimit(EID(h), &limit) == 0 && limit != 0) {
		struct vzctl_cpu_param *cpu = h->env_param->cpu;
		if (cpu->limit_res == NULL) {
			cpu->limit_res = xmalloc(sizeof(struct vzctl_cpulimit_param));
			if (cpu->limit_res == NULL)
				return VZCTL_E_NOMEM;
		}

		cpu->limit_res->type = VZCTL_CPULIMIT_PCT;
		cpu->limit_res->limit = (unsigned long)limit;
	}

	ns_get_iopslimit(h, &iopslimit);
	ns_get_iolimit(h, &iolimit);
	if (iolimit != 0 || iopslimit != 0) {
		if (h->env_param->io == NULL) {
			h->env_param->io = xmalloc(sizeof(struct vzctl_io_param));
			if (h->env_param->io == NULL)
				return VZCTL_E_NOMEM;
		}

		h->env_param->io->iopslimit = iopslimit;
		h->env_param->io->limit = iolimit;
	}

	return 0;
}

int vzctl2_set_limits(struct vzctl_env_handle *h, int release)
{
	int ret;

	if (release) {
		cg_set_ul("", CG_UB, "tasks", getpid());
		return cg_destroy_cgroup(EID(h));
	}

	if (EMPTY_CTID(h->ctid))
		vzctl2_generate_ctid(EID(h));

	ret = create_cgroup(h, VZCTL_SKIP_SETUP);
	if (ret)
		goto err;

	if (h->env_param->io->limit != UINT_MAX ||
			h->env_param->io->iopslimit != UINT_MAX) {
		if (h->env_param->io->limit != UINT_MAX) {
			ret = ns_set_iolimit(h, h->env_param->io->limit);
			if (ret)
				goto err;
		}

		if (h->env_param->io->iopslimit != UINT_MAX) {
			ret = ns_set_iopslimit(h, h->env_param->io->iopslimit);
			if (ret)
				goto err;
		}

		ret = cg_set_ul(EID(h), CG_UB, "tasks", getpid());
		if (ret)
			goto err;
	}

	return 0;

err:
	cg_destroy_cgroup(EID(h));
	return ret;
}

static struct vzctl_env_ops env_nsops = {
	.get_feature = get_feature,
	.open = ns_open,
	.env_create = ns_env_create,
	.env_chkpnt = ns_env_chkpnt,
	.env_restore = ns_env_restore,
	.env_cpt_cmd = ns_env_cpt_cmd,
	.env_get_cpt_state = ns_env_get_cpt_state,
	.env_stop = ns_env_stop,
	.env_apply_param = ns_env_apply_param,
	.is_env_run = ns_is_env_run,
	.env_enter = ns_env_enter,
	.env_setluid = ns_dummy,
	.env_set_devperm = ns_set_devperm,
	.env_set_cpumask = ns_set_cpumask,
	.env_set_nodemask = ns_set_nodemask,
	.env_set_iolimit = ns_set_iolimit,
	.env_get_iolimit = ns_get_iolimit,
	.env_set_ioprio = ns_set_ioprio,
	.env_set_iopslimit = ns_set_iopslimit,
	.env_get_iopslimit = ns_get_iopslimit,
	.env_ip_ctl = ns_ip_ctl,
	.env_get_veip = ns_get_veip,
	.env_veth_ctl = ns_veth_ctl,
	.env_netdev_ctl = ns_netdev_ctl,
	.env_exec = ns_env_exec,
	.env_exec_fn = ns_env_exec_fn,
	.env_cleanup = ns_env_cleanup,
	.env_get_runtime_param = ns_get_runtime_param,
	.close = ns_close,
};

void env_nsops_init(struct vzctl_env_ops *ops)
{
	struct utsname u;

	uname(&u);
	if (kver_cmp(u.release, "3.9") >= 0)
		memcpy(ops, &env_nsops, sizeof(*ops));
}
