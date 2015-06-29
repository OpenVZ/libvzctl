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

#include <unistd.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <linux/vzcalluser.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <dirent.h>

#include "env.h"
#include "util.h"
#include "logger.h"
#include "vzerror.h"
#include "vzsyscalls.h"
#include "vz.h"
#include "cpu.h"
#include "bitmap.h"

static long __clk_tck = -1;

static inline int fairsched_chwt(unsigned int id, unsigned wght)
{
	return syscall(__NR_fairsched_chwt, id, wght);
}

static inline int fairsched_rate(unsigned int id, int op, unsigned rate)
{
	return syscall(__NR_fairsched_rate, id, op, rate);
}

static inline int fairsched_vcpus(unsigned int id, unsigned vcpus)
{
	int ret;

	ret = syscall(__NR_fairsched_vcpus, id, vcpus);
	if (ret && errno == ENOSYS)
		ret = 0;
	return ret;
}

static int env_set_cpulimit(struct vzctl_env_handle *h, unsigned int cpulim1024)
{
	int op;

	op = cpulim1024 != 0 ? FAIRSCHED_SET_RATE : FAIRSCHED_DROP_RATE;
	logger(0, 0, "Setting CPU limit: %0.1f%%", 100.0 *cpulim1024 /1024);
	if (fairsched_rate(h->veid, op, cpulim1024) < 0)
		return vzctl_err(VZCTL_E_CPULIMIT, errno,
			"Cannot set %d as cpulimit value", cpulim1024);
	return 0;
}

static int env_set_cpuweight(struct vzctl_env_handle *h, unsigned int cpuweight)
{
	if (fairsched_chwt(h->veid, cpuweight))
		return vzctl_err(VZCTL_E_CPUWEIGHT, errno,
			"Cannot set %d as cpuweight value", cpuweight);
	return 0;
}

static int env_set_cpuunits(struct vzctl_env_handle *h, unsigned int cpuunits)
{
	int cpuweight;

	if (cpuunits < MINCPUUNITS || cpuunits > MAXCPUUNITS) {
		return vzctl_err(VZCTL_E_INVAL, 0,
			"Invalid value for cpuunits: %d allowed range is %d-%d",
			cpuunits, MINCPUUNITS, MAXCPUUNITS);
	}
	cpuweight = MAXCPUUNITS / cpuunits;
	logger(0, 0, "Setting CPU units: %d", cpuunits);
	if (fairsched_chwt(h->veid, cpuweight))
		return vzctl_err(VZCTL_E_CPUWEIGHT, errno,
			"Cannot set %d as cpuuniit value", cpuunits);
	return 0;
}

/** Change number of CPUs available in the running Container.
 *
 * @param veid		Container id
 * @param vcpu		number of cpu
 */
static int env_set_vcpus(struct vzctl_env_handle *h, unsigned int vcpus)
{
	logger(0, 0, "Setting CPUs: %d", vcpus);
	if (fairsched_vcpus(h->veid, vcpus))
		return vzctl_err(VZCTL_E_VCPU, errno,
			"Cannot set %d as vcpu value", vcpus);
	return 0;
}

int env_set_cpumask(struct vzctl_env_handle *h, struct vzctl_cpumask *cpumask)
{
	int ret;
	char buf[1024] = "";

	if (cpumask == NULL)
		return 0;

	bitmap_snprintf(buf, sizeof(buf), cpumask->mask, sizeof(cpumask->mask));
	logger(1, 0, "Set cpumask: %s", buf);

	ret = syscall(__NR_fairsched_cpumask, h->veid,
			sizeof(cpumask->mask), cpumask->mask);
	if (ret) {
		if (errno == ENOENT)
			logger(-1, 0, "Unable to set cpumask: the Container is not running");
		else
			logger(-1, errno, "Unable to set cpumask ret=%d", ret);
		return VZCTL_E_CPUMASK;
	}
	return 0;
}

int env_set_nodemask(struct vzctl_env_handle *h, struct vzctl_nodemask *nodemask)
{
	int ret;
	char buf[1024] = "";

	if (nodemask == NULL)
		return 0;

	bitmap_snprintf(buf, sizeof(buf), nodemask->mask, sizeof(nodemask->mask));
	logger(1, 0, "Set nodemask: %s", buf);

	ret = syscall(__NR_fairsched_nodemask, h->veid,
			sizeof(struct vzctl_nodemask), nodemask->mask);
	if (ret) {
		if (errno == ENOENT)
			logger(-1, 0, "Unable to set nodemask: the Container is not running");
		else
			logger(-1, errno, "Unable to set nodemask ret=%d", ret);
		return VZCTL_E_NODEMASK;
	}
	return 0;
}

int vzctl2_set_cpumask(struct vzctl_env_handle *h, const char *str)
{
	int ret;
	struct vzctl_cpumask *mask = NULL;

	ret = parse_cpumask(str, &mask);
	if (ret)
		return ret;

	ret = env_set_cpumask(h, mask);

	free(mask);

	return ret;
}

int vzctl2_set_nodemask(struct vzctl_env_handle *h, const char *str)
{
	int ret;
	struct vzctl_nodemask *mask = NULL;

	ret = parse_nodemask(str, &mask);
	if (ret)
		return ret;

	ret = env_set_nodemask(h, mask);

	free(mask);

	return ret;
}

int apply_cpu_param(struct vzctl_env_handle *h, struct vzctl_env_param *env, int flags)
{
	struct vzctl_cpu_param *cpu = env->cpu;
	int ret = 0;

	if (cpu->limit_res == NULL &&
			cpu->units == NULL &&
			cpu->weight == NULL &&
			cpu->vcpus == NULL &&
			cpu->cpumask == NULL)
	{
		return 0;
	}
	if (cpu->limit_res != NULL) {
		if ((ret = env_set_cpulimit(h, cpu->limit1024)))
			return ret;
	}
	if (cpu->vcpus != NULL) {
		if ((ret = env_set_vcpus(h, *cpu->vcpus)))
			return ret;
	}

	if (cpu->units != NULL) {
		if ((ret = env_set_cpuunits(h, *cpu->units)))
			return ret;
	} else if (cpu->weight != NULL) {
		if ((ret = env_set_cpuweight(h, *cpu->weight)))
			return ret;
	}

	if (cpu->nodemask != NULL || cpu->cpumask != NULL) {
		if ((ret = vzctl2_env_set_node(h, cpu->nodemask, cpu->cpumask)))
			return ret;
	}

	return 0;
}

static long get_clk_tck()
{
	if (__clk_tck != -1)
		return __clk_tck;
	__clk_tck = sysconf(_SC_CLK_TCK);
	return __clk_tck;
}

int vzctl2_env_cpustat(struct vzctl_env_handle *h, struct vzctl_cpustat *vzctl_cpustat, int size)
{
	int ret;
	struct vz_cpu_stat cpustat;
	struct vzctl_cpustatctl cpustatctl;
	struct vzctl_cpustat tmp;

	cpustatctl.veid = h->veid;
	cpustatctl.cpustat = &cpustat;
	if ((ret = ioctl(get_vzctlfd(), VZCTL_GET_CPU_STAT, &cpustatctl)))
		return vzctl_err(VZCTL_E_CPUSTAT, errno,
				"Unable to get cpu stat");
	tmp.loadavg[0] = (float) cpustat.avenrun[0].val_int +
					(0.01 * cpustat.avenrun[0].val_frac);
	tmp.loadavg[1] = (float) cpustat.avenrun[1].val_int +
					(0.01 * cpustat.avenrun[1].val_frac);
	tmp.loadavg[2] = (float) cpustat.avenrun[2].val_int +
					(0.01 * cpustat.avenrun[2].val_frac);
	tmp.uptime =  (float) cpustat.uptime_jif / get_clk_tck();
	tmp.user =  (float)cpustat.user_jif / get_clk_tck();
	tmp.nice =  (float)cpustat.nice_jif / get_clk_tck();
	tmp.system = (float)cpustat.system_jif / get_clk_tck();
	if (cpustat.uptime_clk == 0 || cpustat.uptime_jif == 0)
		tmp.idle = 0;
	else
		tmp.idle = ((float)cpustat.idle_clk /
			(cpustat.uptime_clk / cpustat.uptime_jif)) / get_clk_tck();

	memcpy(vzctl_cpustat, &tmp, size);

	return 0;
}

static int get_cpu_max_freq(unsigned long long *freq)
{
#define PROC_CPUINFO_MAX_FREQ  "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq"

	FILE *fp;
	int n;

	if ((fp = fopen(PROC_CPUINFO_MAX_FREQ, "r")) == NULL)
		return -1;

	n = fscanf(fp, "%llu", freq);

	fclose(fp);

	return n == 1 ? 0 : -1;
}

int vzctl2_get_cpuinfo(struct vzctl_cpuinfo *info)
{
	FILE *fp;
	char str[128];
	int ncpu = 0;
	unsigned long long max_freq = 0;

	if ((fp = fopen("/proc/cpuinfo", "r")) == NULL)
		return vzctl_err(VZCTL_E_CPUINFO, errno, "Cannot open /proc/cpuinfo");
	while (fgets(str, sizeof(str), fp)) {
		float val;
		int n;
		if (!strncmp(str, "processor", 9))
			ncpu++;
		n = sscanf(str, "cpu MHz%*[^:]: %f", &val);
		if (n == 1)
			max_freq = val * 1000;
	}
	fclose(fp);

	if (max_freq == 0)
		return vzctl_err(VZCTL_E_CPUINFO, 0,
				"Unable to get the CPU frequency from /proc/cpuinfo");
	if (ncpu == 0)
		ncpu = 1;

	info->ncpu = ncpu;
	info->freq = ncpu * max_freq;
	if (get_cpu_max_freq(&max_freq) == 0)
		info->freq = ncpu * max_freq;

	return 0;
}

int vzctl_parse_cpulimit(struct vzctl_cpu_param *param, struct vzctl_cpulimit_param *cpu)
{
	int ret;
	struct vzctl_cpuinfo info;
	int type = cpu->type;

	if (type != VZCTL_CPULIMIT_MHZ &&
			type != VZCTL_CPULIMIT_PCT &&
			type != VZCTL_CPULIMIT_PCT_TO_MHZ)
		return vzctl_err(VZCTL_E_INVAL, 0, "Incorrect vzctl_cpulimit_param.type %d",
				type);

	ret = vzctl2_get_cpuinfo(&info);
	if (ret)
		return ret;

	if (param->limit_res == NULL) {
		param->limit_res = xmalloc(sizeof(struct vzctl_cpulimit_param));
		if (param->limit_res == NULL)
			return VZCTL_E_NOMEM;
	}

	if (type == VZCTL_CPULIMIT_PCT_TO_MHZ)
	{
		type = VZCTL_CPULIMIT_MHZ;
		cpu->limit = info.freq * cpu->limit / (100 * 1000 * info.ncpu);
	}

	if (type == VZCTL_CPULIMIT_MHZ) {
		if (cpu->limit * 1000 > info.freq)
			logger(0, 0, "Warning: the specified CPU frequency %lu"
					" is higher the total %llu",
					cpu->limit, info.freq/1000);

		param->limit1024 = 1024.0 * cpu->limit * 1000 * info.ncpu / info.freq;
		param->limit_res->limit = cpu->limit;
		param->limit_res->type = VZCTL_CPULIMIT_MHZ;

	} else if (type == VZCTL_CPULIMIT_PCT) {
		if (cpu->limit > info.ncpu * 100)
			logger(0, 0, "Warning: the specified CPU limit %lu"
					" is higher the total %d",
					cpu->limit , info.ncpu * 100);

		param->limit1024 = cpu->limit * 1024 / 100;
		param->limit_res->limit = cpu->limit;
		param->limit_res->type = VZCTL_CPULIMIT_PCT;
	}

	return 0;
}

int parse_cpulimit(struct vzctl_cpu_param *param, const char *str, int def_in_mhz)
{
	char *tail;
	struct vzctl_cpulimit_param cpu;

	errno = 0;
	cpu.limit = strtoul(str, (char **)&tail, 10);
	if (errno == ERANGE || cpu.limit > INT_MAX)
		return VZCTL_E_INVAL;

	if (def_in_mhz || !strcasecmp(tail, "m") || !strcasecmp(tail, "mhz"))
		cpu.type = VZCTL_CPULIMIT_MHZ;
	else if (!strcmp(tail, "%") || (*tail == '\0'))
		cpu.type = VZCTL_CPULIMIT_PCT;
	else
		return VZCTL_E_INVAL;

	return vzctl_parse_cpulimit(param, &cpu);
}

struct vzctl_cpu_param *alloc_cpu_param()
{
	return calloc(1, sizeof(struct vzctl_cpu_param));
}

void free_cpu_param(struct vzctl_cpu_param *cpu)
{
	free(cpu->limit_res);
	free(cpu->weight);
	free(cpu->units);
	free(cpu->vcpus);
	free(cpu->cpumask);
	free(cpu->nodemask);
	free(cpu);
}

char *cpumask2str(struct vzctl_cpumask *cpumask)
{
	char buf[1024] = "";

	if (cpumask == NULL)
		return NULL;

	if (cpumask->auto_assigment)
		return strdup("auto");

	if (!bitmap_all_bit_set(cpumask->mask, sizeof(cpumask->mask)))
		bitmap_snprintf(buf, sizeof(buf), cpumask->mask, sizeof(cpumask->mask));

	return strdup(buf);
}

char *nodemask2str(struct vzctl_nodemask *nodemask)
{
	char buf[1024] = "";

	if (nodemask == NULL)
		return NULL;

	if (!bitmap_all_bit_set(nodemask->mask, sizeof(nodemask->mask)))
		bitmap_snprintf(buf, sizeof(buf), nodemask->mask, sizeof(nodemask->mask));

	return strdup(buf);
}

int parse_cpumask(const char *str, struct vzctl_cpumask **cpumask)
{
	int ret = 0;

	if (str == NULL)
		return VZCTL_E_INVAL;

	if (*cpumask == NULL) {
		*cpumask = calloc(1, sizeof(struct vzctl_cpumask));
		if (*cpumask == NULL)
			return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "parse_cpumask");
	}

	if (!strcmp(str, "auto")) {
		(*cpumask)->auto_assigment = 1;
	} else {
		ret = bitmap_parse(str, (*cpumask)->mask, sizeof((*cpumask)->mask));
		if (ret) {
			free(*cpumask);
			*cpumask = NULL;
		}
	}

	return ret;
}

int parse_nodemask(const char *str, struct vzctl_nodemask **nodemask)
{
	int ret;

	if (str == NULL)
		return VZCTL_E_INVAL;

	if (*nodemask == NULL) {
		*nodemask = calloc(1, sizeof(struct vzctl_nodemask));
		if (*nodemask == NULL)
			return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "parse_nodemask");
	}

	ret = bitmap_parse(str, (*nodemask)->mask, sizeof((*nodemask)->mask));
	if (ret) {
		free(*nodemask);
		*nodemask = NULL;
	}

	return ret;
}

static int numa_node_to_cpu(int nid, unsigned long *cpumask, int size)
{
	DIR *d;
	struct dirent *de;
	char path[64];
	char *endp;
	int nmaskbits = size * 8;

	sprintf(path, "/sys/devices/system/node/node%d", nid);
	d = opendir(path);
	if (!d)
		return vzctl_err(-1, errno, "NUMA: Failed to open %s", path);

	while ((de = readdir(d)) != NULL) {
		int cpu;

		if (strncmp(de->d_name, "cpu", 3))
			continue;
		cpu = strtoul(de->d_name + 3, &endp, 10);
		if (!*endp && cpu >= 0 && cpu < nmaskbits)
			bitmap_set_bit(cpu, cpumask);
	}
	closedir(d);
	return 0;
}

int get_node_cpumask(struct vzctl_nodemask *nodemask, struct vzctl_cpumask *cpumask)
{
	int n;

	bzero(cpumask->mask, sizeof(cpumask->mask));
	for (n = 0; n < sizeof(nodemask->mask) * 8; n++) {
		if (!test_bit(n, nodemask->mask))
			continue;

		if (numa_node_to_cpu(n, cpumask->mask, sizeof(cpumask->mask)))
			continue;
	}
	return 0;
}

#define SYS_CPU_ONLINE	"/sys/devices/system/cpu/online"
int get_online_cpumask(struct vzctl_cpumask *cpumask)
{
	FILE *fp;
	char buf[4096];
	char *p;
	int ret = -1;

	fp = fopen(SYS_CPU_ONLINE, "r");
	if (!fp)
		return vzctl_err(-1, errno, "Failed to open " SYS_CPU_ONLINE);

	if (!fgets(buf, sizeof(buf), fp)) {
		ret = vzctl_err(-1, errno, "Failed to read from " SYS_CPU_ONLINE);
		goto out;
	}

	p = strchr(buf, '\n');
	if (p != NULL)
		*p = '\0';

	ret = bitmap_parse(buf, cpumask->mask, sizeof(cpumask->mask));
	if (ret)
		vzctl_err(-1, 0, "Failed to parse online cpumask '%s'", buf);
out:
	fclose(fp);

	return ret;
}
