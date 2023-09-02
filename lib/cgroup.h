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

#ifndef __CGROUP_H__
#define __CGROUP_H__

#define CG_CPU		"cpu"
#define CG_CPUSET	"cpuset"
#define CG_DEVICES	"devices"
#define CG_MEMORY	"memory"
#define CG_NET_CLS	"net_cls"
#define CG_VE		"ve"
#define CG_UB		"beancounter"
#define CG_BLKIO	"blkio"
#define CG_FREEZER	"freezer"
#define CG_PERF_EVENT	"perf_event"
#define CG_HUGETLB	"hugetlb"
#define CG_PIDS		"pids"
#define CG_RDMA		"rdma"
#define CG_UNIFIED	"unified"

#define CG_MEM_LIMIT	"memory.limit_in_bytes"
#define CG_MEM_USAGE	"memory.usage_in_bytes"
#define CG_SWAP_LIMIT	"memory.memsw.limit_in_bytes"
#define CG_SWAP_USAGE	"memory.memsw.usage_in_bytes"
#define CG_KMEM_LIMIT	"memory.kmem.limit_in_bytes"
#define CG_KMEM_USAGE	"memory.kmem.usage_in_bytes"

#define CGV2_MEM_MAX	"memory.max"
#define CGV2_MEM_CURR	"memory.current"
#define CGV2_SWAP_MAX	"memory.swap.max"
#define CGV2_SWAP_CURR	"memory.swap.current"

#define PAGE_COUNTER_MAX ((unsigned long)LONG_MAX)

#define CG_NET_CLASSID	"net_cls.classid"

/* For x86-64 kernels */
#define PID_MAX_LIMIT		(4 * 1024 * 1024)
#define PIDS_MAX		(PID_MAX_LIMIT + 1ULL)

struct vzctl_env_handle;

int init_cgroups(void);
void fini_cgroups(void);
int is_cgroup_v2(void);

const char* cg_get_memory_subsys();
const char* cg_get_freezer_subsys();
const char* cg_get_cpuset_subsys();
const char* cg_get_pids_subsys();
const char* cg_get_blkio_subsys();

const char *cg_get_slice_name(void);
int cg_get_path(const char *ctid, const char *subsys, const char *name,
		char *out, int size);
int write_data(const char *path, const char *data);
int cg_get_cgroup_env_param(const char *ctid, char *out, int size);
int cg_new_cgroup(const char *ctid);
int cg_destroy_cgroup(const char *ctid, int release);
int cg_enable_pseudosuper(const char *ctid);
int cg_pseudosuper_open(const char *ctid, int *fd);
int cg_disable_pseudosuper(const int pseudosuper_fd);
int cg_attach_task(const char *ctid, pid_t pid, char *cg_subsys_except);
int cg_set_param(const char *ctid, const char *subsys, const char *name, const char *data);
int cg_get_param(const char *ctid, const char *subsys, const char *name, char *out, int size);
int cg_get_ul(const char *ctid, const char *subsys, const char *name,
		unsigned long *value);
int cg_set_ul(const char *ctid, const char *subsys, const char *name,
                unsigned long value);
int cg_set_ull(const char *ctid, const char *subsys, const char *name,
		unsigned long long value);
int cg_get_ull(const char *ctid, const char *subsys, const char *name,
		unsigned long long *value);
int cg_env_set_cpuunits(const char *ctid, unsigned int cpuunits);
int cg_env_set_cpulimit(const char *ctid, float limit);
int cg_env_get_cpulimit(const char *ctid, float *limit);
int cg_env_set_vcpus(const char *ctid, unsigned int vcpus);
int cg_env_set_cpumask(const char *ctid, unsigned long *cpumask, int size);
int cg_env_set_nodemask(const char *ctid, unsigned long *nodemask, int size);
int cg_env_set_devices(const char *ctid, const char *name, const char *data);
int cg_env_set_memory(const char *ctid, const char *name, unsigned long value);
int cg_env_get_memory(const char *ctid, const char *name, unsigned long *value);
int cgv2_env_set_memory(const char *ctid, const char *name, unsigned long value);
int cgv2_env_get_memory(const char *ctid, const char *name, unsigned long *value);
int cgv2_env_set_unified(const char *ctid, const char *name, unsigned long value);
int cg_env_set_ub(const char *ctid, const char *name, unsigned long b, unsigned long l);
int cg_set_disk_iolimit(const char *ctid, dev_t dev, unsigned int limit);
int cg_set_disk_iopslimit(const char *ctid, dev_t dev, unsigned int limit);
int cg_env_set_iolimit(const char *ctid, unsigned int speed,
		unsigned int burst, unsigned int latency);
int cg_env_set_iopslimit(const char *ctid, unsigned int speed,
		unsigned int burst, unsigned int latency);
int cg_env_set_net_classid(const char *ctid, unsigned int classid);
int cg_env_get_init_pid(const char *ctid, pid_t *pid);
int cg_env_get_ve_state(const char *ctid);
int cg_env_get_pids(const char *ctid, list_head_t *list);
int cg_get_legacy_veid(const char *ctid, unsigned long *value);
int bindmount_env_cgroup(struct vzctl_env_handle *h);
int cg_set_veid(const char *ctid, int veid);
int cg_freezer_cmd(const char *ctid, int cmd, int rec);
int cg_read_freezer_state(const char *ctid, char *out, int size);
int cg_is_supported(const char *subsys);
#endif
