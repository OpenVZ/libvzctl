/*
 * Copyright (c) 2015 Parallels IP Holdings GmbH
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
 */

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mount.h>

#include "list.h"
#include "cgroup.h"
#include "bitmap.h"
#include "vzerror.h"
#include "logger.h"
#include "util.h"
#include "net.h"

struct cg_ctl {
	char subsys[64];
	int is_prvt;
	char *mount_path;
};

static struct cg_ctl cg_ctl_map[] = {
	{CG_CPU},
	{CG_CPUSET},
	{CG_NET_CLS},
	{CG_MEMORY},
	{CG_DEVICES},
	{CG_BLKIO},
	{CG_FREEZER},
	{CG_UB, 1},
	{CG_VE, 1},
	{CG_SYSTEMD},
};

static pthread_mutex_t cg_ctl_map_mtx = PTHREAD_MUTEX_INITIALIZER;
typedef int (*cgroup_filter_f)(const char *subsys);

static int cg_is_systemd(const char *subsys)
{
	return strcmp(subsys, CG_SYSTEMD) == 0;
}

static int has_substr(char *buf, const char *str)
{
	char *token;
	char *str_ptr = buf;

	while ((token = strsep(&str_ptr, ",")) != NULL) {
		if (!strcmp(token, str))
			return 1;
	}
	return 0;
}

static int get_mount_path(const char *subsys, char *out, int size)
{
	FILE *fp;
	int n;
	char buf[PATH_MAX];
	char target[4096];
	char ops[4096];
	int ret = 1;

	fp = fopen("/proc/mounts", "r");
	if (fp == NULL)
		return vzctl_err(-1, errno, "Can't open /proc/mounts");

	while (fgets(buf, sizeof(buf), fp)) {
		/* cgroup /sys/fs/cgroup/devices cgroup rw,nosuid,nodev,noexec,relatime,devices */
		n = sscanf(buf, "%*s %4095s cgroup %4095s",
				target, ops);
		if (n != 2)
			continue;

		if (has_substr(ops, !cg_is_systemd(subsys) ?
					subsys : "name=systemd"))
		{
			strncpy(out, target, size -1);
			out[size-1] = '\0';
			ret = 0;
			break;
		}
	}
	fclose(fp);

	return ret;
}

static struct cg_ctl *find_cg_ctl(const char *subsys)
{
	int i;

	for (i = 0; i < sizeof(cg_ctl_map)/sizeof(cg_ctl_map[0]); i++)
		if (!strcmp(cg_ctl_map[i].subsys, subsys))
			return &cg_ctl_map[i];

	return NULL;
}

static int is_prvt_cgroup(const char *subsys)
{
	struct cg_ctl *c = find_cg_ctl(subsys);

	return (c == NULL ? 0 : c->is_prvt); 
}

static int cg_get_ctl(const char *subsys, struct cg_ctl **ctl)
{
	int ret;
	char mount_path[PATH_MAX];

	*ctl = find_cg_ctl(subsys);
	if (*ctl == NULL)
		return vzctl_err(-1, 0, "Unknown cgroup subsystem %s", subsys);

	pthread_mutex_lock(&cg_ctl_map_mtx);
	if ((*ctl)->mount_path != NULL) {
		ret = 0;
		goto out;
	}

	ret = get_mount_path(subsys, mount_path, sizeof(mount_path));
	if (ret) {
		if (ret != -1)
			vzctl_err(-1, 0, "Unable to find mount point for %s cgroup",
					subsys);
		goto out;
	}

	ret = xstrdup(&(*ctl)->mount_path, mount_path);
	if (ret)
		goto out;

	debug(DBG_CG, "cgroup %s mount point: %s ", subsys, mount_path);
out:
	pthread_mutex_unlock(&cg_ctl_map_mtx);

	return ret;
}

int write_data(const char *path, const char *data)
{
	int fd, len, w;

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return vzctl_err(-1, errno, "Can't open %s for writing", path);

	logger(3, 0, "Write %s <%s>", path, data);
	len = strlen(data);
	w = write(fd, data, len);
	if (w != len) {
		int eno = errno;
		if (w < 0)
			logger(-1, errno, "Error writing to file %s data='%s'",
					path, data);
		else
			logger(-1, 0, "Output truncated while writing to %s", path);
		close(fd);
		errno = eno;

		return -1;
	}

	if (close(fd))
		return vzctl_err(-1, errno, "Error on on close fd %s", path);

	return 0;
}

static int cg_read(const char *path, char *out, int size)
{
	int fd, r;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return vzctl_err(-errno, errno, "Can't open %s for reading", path);

	r = read(fd, out, size-1);
	close(fd);
	if (r < 0)
		return vzctl_err(-errno, errno, "Error reading from file %s", path);

	if (out[r-1] == '\n')
		out[r-1]= '\0';
	else
		out[r] = '\0';

	return 0;
}

static void get_cgroup_name(const char *ctid, struct cg_ctl *ctl,
		char *out, int size)
{

	if (cg_is_systemd(ctl->subsys))
		snprintf(out, size, "%s/" SYSTEMD_CTID_FMT".slice",
				ctl->mount_path, ctid);
	else
		snprintf(out, size, "%s/%s", ctl->mount_path, ctid);
}

static int cg_get_path(const char *ctid, const char *subsys, const char *name,
		char *out, int size)
{
	int ret;
	struct cg_ctl *ctl;
	char path[PATH_MAX];

	ret = cg_get_ctl(subsys, &ctl);
	if (ret)
		return ret;

	if (ctid == NULL || EMPTY_CTID(ctid))
		snprintf(out, size, "%s/%s", ctl->mount_path, name);
	else {
		get_cgroup_name(ctid, ctl, path, sizeof(path));
		snprintf(out, size, "%s/%s", path, name);
	}

	return 0;
}

int cg_set_param(const char *ctid, const char *subsys, const char *name, const char *data)
{
	int ret;
	char path[PATH_MAX];

	ret = cg_get_path(ctid, subsys, name, path, sizeof(path));
	if (ret)
		return ret;

	return write_data(path, data);
}

int cg_set_ul(const char *ctid, const char *subsys, const char *name,
		unsigned long value)
{
        char data[32];

        snprintf(data, sizeof(data), "%lu", value);

        return cg_set_param(ctid, subsys, name, data);
}

int cg_set_ull(const char *ctid, const char *subsys, const char *name,
		unsigned long long value)
{
        char data[32];

        snprintf(data, sizeof(data), "%llu", value);

        return cg_set_param(ctid, subsys, name, data);
}


int cg_get_param(const char *ctid, const char *subsys, const char *name, char *out, int size)
{
	char path[PATH_MAX];
	int ret;

	ret = cg_get_path(ctid, subsys, name, path, sizeof(path));
	if (ret)
		return ret;

	return cg_read(path, out, size);
}

int cg_get_ul(const char *ctid, const char *subsys, const char *name,
		unsigned long *value)
{
	int ret;
	char data[32];

	ret = cg_get_param(ctid, subsys, name, data, sizeof(data));
	if (ret)
		return ret;
	return parse_ul(data, value);
}

int cg_get_ull(const char *ctid, const char *subsys, const char *name,
		unsigned long long *value)
{
	int ret;
	char data[32];
	char *tail;

	ret = cg_get_param(ctid, subsys, name, data, sizeof(data));
	if (ret)
		return ret;

	errno = 0;
	*value = strtoull(data, (char **)&tail, 10);
	if (*tail != '\0' || errno == ERANGE)
		return -1;

	return 0;
}



static int cg_create(const char *ctid, struct cg_ctl *ctl)
{
	char path[PATH_MAX];

	get_cgroup_name(ctid, ctl, path, sizeof(path));

	logger(3, 0, "Create cgroup %s", path);
	if (mkdir(path, 0755) && errno != EEXIST)
		return vzctl_err(-1, errno, "Unable to create cgroup %s",
				path);
	return 0;
}


static int do_rmdir(const char *dir)
{
	useconds_t total = 0;
	useconds_t wait = 10000;
	const useconds_t maxwait = 500000;
	const useconds_t timeout = 30 * 1000000;

	do {
		if (rmdir(dir) == 0)
			return 0;
		if (errno != EBUSY)
			break;

		usleep(wait);
		total += wait;
		wait *= 2;
		if (wait > maxwait)
			wait = maxwait;
	} while (total < timeout);

	return vzctl_err(-1, errno, "Cannot remove dir %s", dir);
}

static int cg_destroy(const char *ctid, struct cg_ctl *ctl)
{
	char path[PATH_MAX];
	struct stat st;
	struct vzctl_str_param *it;
	LIST_HEAD(dirs);
	int ret = 0;

	if (ctl->mount_path == NULL)
		return 0;

	get_cgroup_name(ctid, ctl, path, sizeof(path));

	if (stat(path, &st) && errno == ENOENT)
		return 0;

	logger(3, 0, "Destroy cgroup %s", path);
	if (get_dir_list(&dirs, path, -1))
		return -1;

	list_for_each_prev(it, &dirs, list) {
		do_rmdir(it->str);
	}

	free_str(&dirs);
	return ret;
}

int cg_new_cgroup(const char *ctid)
{
	int ret, i;
	struct cg_ctl *ctl;

	for (i = 0; i < sizeof(cg_ctl_map)/sizeof(cg_ctl_map[0]); i++) {
		ret = cg_get_ctl(cg_ctl_map[i].subsys, &ctl);
		if (ret == -1)
			goto err;
		/* Skip non exists */
		if (ret)
			continue;

		ret = cg_create(ctid, ctl);
		if (ret)
			goto err;
	}
	return 0;
err:
	for (i = i - 1; i >= 0; i--)
		cg_destroy(ctid, &cg_ctl_map[i]);

	return ret;
}

int cg_destroy_cgroup(const char *ctid)
{
	int rc, i, ret = 0;
	struct cg_ctl *ctl;

	for (i = 0; i < sizeof(cg_ctl_map)/sizeof(cg_ctl_map[0]); i++) {
		rc = cg_get_ctl(cg_ctl_map[i].subsys, &ctl);
		if (rc)
			continue;

		ret |= cg_destroy(ctid, ctl);
	}
	return ret;
}

int cg_attach_task(const char *ctid, pid_t pid)
{
	int ret, i;

	for (i = 0; i < sizeof(cg_ctl_map)/sizeof(cg_ctl_map[0]); i++) {
		ret = cg_set_ul(ctid, cg_ctl_map[i].subsys, "tasks", pid);
		if (ret == -1)
			break;
		/* Skip non exists */
		if (ret) {
			ret = 0;
			continue;
		}
	}

	return ret;
}

/**************************************************************************/
int cg_env_set_cpuunits(const char *ctid, unsigned int cpuunits)
{
	return cg_set_ul(ctid, CG_CPU, "cpu.shares", cpuunits * 1024 / 1000);
}

int cg_env_set_cpulimit(const char *ctid, unsigned int limit1024)
{
	return cg_set_ul(ctid, CG_CPU, "cpu.rate", limit1024);
}

int cg_env_set_vcpus(const char *ctid, unsigned int vcpus)
{
	return cg_set_ul(ctid, CG_CPU, "cpu.nr_cpus", vcpus);
}

static int cg_env_set_mask(const char *ctid, const char *name,  unsigned long *cpumask, int size)
{
	char cg_name[64];
	char buf[4096];
	unsigned long *mask;

	snprintf(cg_name, sizeof(cg_name), "cpuset.%s", name);
	if (cg_get_param("", CG_CPUSET, cg_name, buf, sizeof(buf)) < 0)
		return vzctl_err(VZCTL_E_CPUMASK, 0,
				"Unable to get active %s mask", cg_name);

	mask = malloc(size * sizeof(unsigned));
	if (mask == NULL)
		return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "cg_env_set_mask");

	if (bitmap_parse(buf, mask, size)) {
		free(mask);
		return vzctl_err(VZCTL_E_CPUMASK, 0,
				"Can't parse active %s mask: %s", name, buf);
	}

	/* Autocorrect mask */
	bitmap_and(mask, cpumask, mask, size);
	bitmap_snprintf(buf, sizeof(buf), mask, size);
	free(mask);
	snprintf(cg_name, sizeof(cg_name), "cpuset.%s", name);
	if (cg_set_param(ctid, CG_CPUSET, cg_name, buf))
		return vzctl_err(VZCTL_E_CPUMASK, errno,
				"Unable to set %s", cg_name);

	return 0;
}

int cg_env_set_cpumask(const char *ctid, unsigned long *cpumask, int size)
{
	return cg_env_set_mask(ctid, "cpus", cpumask, size);
}

int cg_env_set_nodemask(const char *ctid, unsigned long *nodemask, int size)
{
	return cg_env_set_mask(ctid, "mems", nodemask, size);
}

int cg_env_set_devices(const char *ctid, const char *name, const char *data)
{
	return cg_set_param(ctid, CG_DEVICES, name, data);
}

int cg_env_set_memory(const char *ctid, const char *name, unsigned long value)
{
	return cg_set_ul(ctid, CG_MEMORY, name, value);
}

int cg_env_set_ub(const char *ctid, const char *name, unsigned long b, unsigned long l)
{
	int rc;
	char _name[STR_SIZE];

	snprintf(_name, sizeof(_name), "beancounter.%s.barrier", name);
	rc = cg_set_ul(ctid, CG_UB, _name, b);
	if (rc)
		return rc;

	snprintf(_name, sizeof(_name), "beancounter.%s.limit", name);
	return cg_set_ul(ctid, CG_UB, _name, l);
}

static int cg_env_set_io(const char *ctid, const char *name, unsigned int speed,
		unsigned int burst, unsigned int latency)
{
	int ret;
	char buf[STR_SIZE];

	snprintf(buf, sizeof(buf), CG_UB".%s.speed", name);
	ret = cg_set_ul(ctid, CG_UB, buf, speed);
	if (ret)
		return ret;

	snprintf(buf, sizeof(buf), CG_UB".%s.burst", name);
	ret = cg_set_ul(ctid, CG_UB, buf, burst);
	if (ret)
		return ret;

	snprintf(buf, sizeof(buf), CG_UB".%s.latency", name);
	ret = cg_set_ul(ctid, CG_UB, buf, latency);
	if (ret)
		return ret;

	return 0;
}

int cg_env_set_iolimit(const char *ctid, unsigned int speed,
		unsigned int burst, unsigned int latency)
{
	return cg_env_set_io(ctid, "iolimit", speed, burst, latency);
}

int cg_env_set_iopslimit(const char *ctid, unsigned int speed,
		unsigned int burst, unsigned int latency)
{
	return cg_env_set_io(ctid, "iopslimit", speed, burst, latency);
}

int cg_env_get_memory(const char *ctid, const char *name, unsigned long *value)
{
	return cg_get_ul(ctid, CG_MEMORY, name, value);
}

int cg_env_set_net_classid(const char *ctid, unsigned int classid)
{
	return cg_set_ul(ctid, CG_NET_CLS, CG_NET_CLASSID, classid);
}

static int cg_env_check_init_pid(const char *ctid, pid_t pid)
{
	int ret;
	pid_t task_pid;
	LIST_HEAD(pids);
	struct vzctl_str_param *it;

	if ((ret = cg_env_get_pids(ctid, &pids)))
		return ret;

	ret = 1;
	list_for_each(it, &pids, list) {
		if (parse_int(it->str, &task_pid))
			continue;

		if (task_pid == pid) {
			ret = 0;
			break;
		}
	}

	free_str(&pids);

	if (ret)
		logger(-1, 0, "Init pid is invalid: no such task");

	return ret;
}

int cg_env_get_init_pid(const char *ctid, pid_t *pid)
{
	int ret;

	if ((ret = read_init_pid(ctid, pid)))
		return ret;

	if ((ret = cg_env_check_init_pid(ctid, *pid))) {
		*pid = 0;
		return ret;
	}

	return 0;
}

int cg_env_get_first_pid(const char *ctid, pid_t *pid)
{
	int ret;
	char buf[4096];
	char path[PATH_MAX];
	unsigned long value;
	char *p;

	ret = cg_get_path(ctid, CG_VE, "tasks", path, sizeof(path));
	if (ret)
		return ret;

	if (stat_file(path) == 0) {
		*pid = 0;
		return 0;
	}

	ret = cg_read(path, buf, sizeof(buf));
	if (ret)
		return ret;

	p = strchr(buf, '\n');
	if (p != NULL)
		*p = '\0';

	if (*buf == '\0') {
		value = 0;
	} else {
		ret = parse_ul(buf, &value);
		if (ret)
			return vzctl_err(-1, 0, "Unable to parse pid <%s>", buf);
	}
	*pid = (pid_t)value;

	return 0;
}

int cg_env_get_pids(const char *ctid, list_head_t *list)
{
	FILE *fp;
	char path[PATH_MAX];
	char str[64];
	char *p;
	int ret = 0;

	ret = cg_get_path(ctid, CG_MEMORY, "cgroup.procs", path, sizeof(path));
	if (ret)
		return ret;

	if ((fp = fopen(path, "r")) == NULL)
		return vzctl_err(-1, errno, "Unable to open %s", path);

	while (!feof(fp)) {
		if (fgets(str, sizeof(str), fp) == NULL)
			break;

		p = strrchr(str, '\n');
		if (p != NULL)
			*p = '\0';

		if (add_str_param(list, str) == NULL) {
			free_str(list);
			ret = -1;
			break;
		}
	}

	fclose(fp);

	return ret;
}

int cg_get_legacy_veid(const char *ctid, unsigned long *value)
{
	return cg_get_ul(ctid, CG_VE, "ve.legacy_veid", value);
}

int cg_add_veip(const char *ctid, const char *ip)
{
	if (cg_set_param(ctid, CG_VE,
				is_ip6(ip) ? "ve.ip6_allow" : "ve.ip_allow", ip))
		return vzctl_err(VZCTL_E_CANT_ADDIP, errno,
				"Unable to add ip %s", ip);
	return 0;
}

int cg_del_veip(const char *ctid, const char *ip)
{
	if (cg_set_param(ctid, CG_VE,
				is_ip6(ip) ? "ve.ip6_deny" : "ve.ip_deny", ip))
		return vzctl_err(VZCTL_E_SYSTEM, errno,
				"Unable to del ip %s", ip);
	return 0;
}

static int get_veip(const char *path, list_head_t *list)
{
	FILE *fp;
	char str[64];
	char ip_str[65];
	char *p;
	int ret = 0;

	if ((fp = fopen(path, "r")) == NULL)
		return vzctl_err(-1, errno, "Unable to open %s", path);

	while (!feof(fp)) {
		if (fgets(str, sizeof(str), fp) == NULL)
			break;

		p = strrchr(str, '\n');
		if (p != NULL)
			*p = '\0';
		
		ret = get_ip_name(str, ip_str, sizeof(ip_str));
		if (ret)
			break;

		if (add_ip_param_str(list, ip_str) == NULL) {
			free_ip(list);
			ret = -1;
			break;
		}
	}

	fclose(fp);

	return ret;
}

int cg_get_veip(const char *ctid, list_head_t *list)
{
	int ret;
	char path[PATH_MAX];

	ret = cg_get_path(ctid, CG_VE, "ve.ip_list", path, sizeof(path));
	if (ret)
		return ret;

	ret = get_veip(path, list);
	if (ret)
		return ret;

	ret = cg_get_path(ctid, CG_VE, "ve.ip6_list", path, sizeof(path));
	if (ret)
		return ret;

	ret = get_veip(path, list);
	if (ret)
		return ret;

	return 0;
}

static int get_cgroup_mounts(list_head_t *head, cgroup_filter_f filter)
{
	int ret = 0;
	FILE *fp;
	char buf[512];
	char path[PATH_MAX];

	fp = fopen("/proc/cgroups", "r");
	if (fp == NULL)
		return vzctl_err(VZCTL_E_SYSTEM, errno,
				"Unable to open /proc/cgroups");

	while (fgets(buf, sizeof(buf), fp)) {
		int rc;

		if (sscanf(buf, "%511s", buf) != 1)
			continue;

		if (buf[0] == '#')
			continue;

		if (filter != NULL && filter(buf))
			continue;

		rc = get_mount_path(buf, path, sizeof(path));
		if (rc == -1) {
			ret = VZCTL_E_SYSTEM;
			break;
		} else if (rc)
			continue;

		if (find_str(head, path) != NULL)
			continue;

		if (add_str_param(head, path) == NULL) {
			ret = VZCTL_E_NOMEM;
			break;
		}
	}
	fclose(fp);

	if (ret)
		free_str(head);

	return ret;
}

static int cg_make_slaves(list_head_t *head)
{
	struct vzctl_str_param *it;

	list_for_each(it, head, list) {
		if (mount(NULL, it->str, NULL, MS_SLAVE, NULL))
			return vzctl_err(VZCTL_E_SYSTEM, errno,
					"Remounting cgroup %s as slaves failed",
					it->str);
	}

	return 0;
}

static int do_bindmount(const char *src, const char *dst, int mnt_flags)
{

	if (access(dst, F_OK) && make_dir(dst, 1))
		return vzctl_err(VZCTL_E_RESOURCE, errno,
				"Can't create %s", dst);

	if (access(src, F_OK) && make_dir(src, 1))
		return vzctl_err(VZCTL_E_RESOURCE, errno,
				"Can't create %s", src);

	logger(5, 0, "bindmount %s -> %s", src, dst);
	if (mount(src, dst, NULL, mnt_flags, NULL))
		return vzctl_err(VZCTL_E_RESOURCE, errno,
				"Can't bindmount %s -> %s", src, dst);
	return 0;
}

/* For multiple cg mountedlike 'cpu,cpuacct' create per ctl symlink PSBM-38634
 *
 * cd /sys/fs/cgroup
 * ln -s cpu,cpuacct /sys/fs/cgroup/cpuacct
 * ln -s cpu,cpuacct /sys/fs/cgroup/cpu
 *
 */
static int create_perctl_symlink(const char *root, const char *path)
{
	int ret = 0;
	char buf[STR_SIZE];
	char d[PATH_MAX];
	char cwd[PATH_MAX];
	char *p, *name;
	int last = 0;

	p = strrchr(path, '/');
	if (p == NULL)
		return 0;

	snprintf(buf, sizeof(buf), "%s", p + 1);
	p = strchr(buf, ',');
	if (p == NULL)
		return 0;

	if (getcwd(cwd, sizeof(cwd)))
		return vzctl_err(-1, errno, "Cannot getcwd");

	snprintf(d, sizeof(d), "%s/%s/..", root, path);
	if (chdir(d))
		return vzctl_err(-1, errno, "Cannot chdir %s", d);

	name = buf;
	*p = '\0'; p++;
	while (1) {
		logger(10, 0, "Create symlink %s -> %s", path, name);
		if (symlink(path, name) && errno != EEXIST) {
			ret = vzctl_err(-1, errno,
					"Cant create symlink %s -> %s",
					path, name);
			break;
		}
		if (last)
			break;

		name = p;
		p = strchr(p, ',');
		if (p != NULL) {
			*p = '\0'; p++;
		} else
			last = 1;
	}

	if (chdir(cwd))
		logger(-1, errno, "Cannot cndir %s", cwd);

	return ret;
}

static int cg_bindmount_cgroup(struct vzctl_env_handle *h, list_head_t * head)
{
	int ret;
	char s[PATH_MAX], d[PATH_MAX];
	char *ve_root = h->env_param->fs->ve_root;
	struct vzctl_str_param *it;

	snprintf(s, sizeof(s), "%s/sys", ve_root);
	if (access(s, F_OK) && make_dir(s, 1))
		return vzctl_err(VZCTL_E_CREATE_DIR, errno,
				"Can't create %s", s);
	if (mount(NULL, s, "sysfs", 0, NULL))
		return vzctl_err(VZCTL_E_RESOURCE, errno,
				"Can't pre-mount sysfs in %s", s);

        snprintf(s, sizeof(s), "%s/sys/fs/cgroup", ve_root);
	if (access(s, F_OK) && make_dir(s, 1))
		return vzctl_err(VZCTL_E_RESOURCE, errno,
				"Can't pre-mount tmpfs in %s", s);
	if (mount(NULL, s, "tmpfs", 0, NULL))
		return vzctl_err(VZCTL_E_RESOURCE, errno,
				"Can't pre-mount tmpfs in %s", s);

	list_for_each(it, head, list) {
		snprintf(d, sizeof(d), "%s%s", ve_root, it->str);
		snprintf(s, sizeof(s), "%s/%s", it->str, EID(h));
		ret = do_bindmount(s, d, MS_BIND|MS_PRIVATE);
		if (ret)
			goto err;


		ret = create_perctl_symlink(ve_root, it->str);
		if (ret)
			goto err;
		
	}

	snprintf(s, sizeof(s), "/sys/fs/cgroup/systemd/"SYSTEMD_CTID_FMT".slice",
			EID(h));
	snprintf(d, sizeof(d), "%s/sys/fs/cgroup/systemd", ve_root);
	ret = do_bindmount(s, d, MS_BIND);

err:
	if (ret) {
		list_for_each(it, head, list) {
        		snprintf(s, sizeof(s), "%s/%s",
					ve_root, it->str);
			umount(s);
		}

        	snprintf(s, sizeof(s), "%s/sys/fs/cgroup", ve_root);
		umount(s);

		snprintf(s, sizeof(s), "%s/sys", ve_root);
		umount(s);
	}

	return ret;
}

int bindmount_env_cgroup(struct vzctl_env_handle *h) 
{
	int ret;
	LIST_HEAD(head);

	ret = get_cgroup_mounts(&head, is_prvt_cgroup);
	if (ret)
		return ret;

	ret = cg_make_slaves(&head);
	if (ret)
		goto err;

	ret = cg_bindmount_cgroup(h, &head);
err:
	free_str(&head);

	return 0;
}

int cg_set_veid(const char *ctid, int veid)
{
	char path[PATH_MAX];
	char id[12];
	int ret;

	ret = cg_get_path(ctid, CG_VE, "ve.veid", path, sizeof(path));
	if (ret)
		return ret;

	if (access(path, F_OK))
		return 0;

	sprintf(id, "%d", veid);
	return write_data(path, id);
}

static int cg_set_freezer_state(const char *ctid, const char *state)
{
	int ret;
	char buf[STR_SIZE];
	int len;

	ret = cg_set_param(ctid, CG_FREEZER, "freezer.state", state);
	if (ret)
		return ret;

	len = strlen(state);
	while (1) {
		ret = cg_get_param(ctid, CG_FREEZER, "freezer.state",
				buf, sizeof(buf));
		if (ret)
			return ret;

		if (strncmp(buf, state, len) == 0)
			break;

		sleep(1);
	}

	return 0;
}

int cg_freezer_cmd(const char *ctid, int cmd)
{
	if (cmd == VZCTL_CMD_RESUME)
		return cg_set_freezer_state(ctid, "THAWED");
	else if (cmd == VZCTL_CMD_FREEZE)
		return cg_set_freezer_state(ctid, "FROZEN");

	return vzctl_err(-1, 0, "Unsupported freezer command %d", cmd);
}
