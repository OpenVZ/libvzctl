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

#ifndef _CPU_H_
#define _CPU_H_

/** Data structure for cpu parameters.
 */
struct vzctl_cpu_param {
	float limit;	/**< CPU usage for the VE, in percent. */
	struct vzctl_cpulimit_param *limit_res;
	unsigned long *weight;
	unsigned long *units;	/**< CPU weight for the VE, in units. */
	unsigned long *vcpus;	/**< number of CPUs available in the running VE*/
	unsigned long *burst_cpulimit;
	unsigned long *burst_cpu_avg_usage;
	struct vzctl_cpumask *cpumask;
	struct vzctl_nodemask *nodemask;
};

struct vzctl_env_handle;
struct vzctl_env_param;
int vzctl_parse_cpulimit(struct vzctl_cpu_param *param, struct vzctl_cpulimit_param *cpu);
int parse_cpulimit(struct vzctl_cpu_param *param, const char *str, int def_in_mhz);
int parse_cpumask(const char *str, struct vzctl_cpumask **cpumask);
int parse_nodemask(const char *str, struct vzctl_nodemask **nodemask);
int env_set_cpumask(struct vzctl_env_handle *h, struct vzctl_cpumask *cpumask);
int env_set_nodemask(struct vzctl_env_handle *h, struct vzctl_nodemask *nodemask);
char *cpumask2str(struct vzctl_cpumask *cpumask);
char *nodemask2str(struct vzctl_nodemask *nodemask);
int get_node_cpumask(struct vzctl_nodemask *nodemask, struct vzctl_cpumask *cpumask);
int get_online_cpumask(struct vzctl_cpumask *cpumask);
struct vzctl_cpu_param *alloc_cpu_param();
void free_cpu_param(struct vzctl_cpu_param *cpu);

#endif /* _CPU_H_ */
