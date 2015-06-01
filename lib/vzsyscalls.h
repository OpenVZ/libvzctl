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

#ifndef _VZSYSCALLS_H_
#define _VZSYSCALLS_H_

#include <sys/syscall.h>

#ifdef __ia64__
#define __NR_fairsched_vcpus	1499
#define __NR_fairsched_chwt	1502
#define __NR_fairsched_rate	1504
#define __NR_setluid		1506
#define __NR_setublimit		1507
#define __NR_ioprio_set		1274
#elif __x86_64__
#define __NR_fairsched_vcpus	499
#define __NR_setluid		501
#define __NR_setublimit		502
#define __NR_fairsched_chwt	506
#define __NR_fairsched_rate	508
#define __NR_ioprio_set		251
#define __NR_fairsched_cpumask  498
#define __NR_fairsched_nodemask 497
#elif __powerpc__
#define __NR_fairsched_chwt	402
#define __NR_fairsched_rate	404
#define __NR_fairsched_vcpus	405
#define __NR_setluid		411
#define __NR_setublimit		412
#define __NR_ioprio_set		273
#elif defined(__i386__) || defined(__sparc__)
#define __NR_fairsched_chwt	502
#define __NR_fairsched_rate	504
#define __NR_fairsched_vcpus	505
#define __NR_setluid		511
#define __NR_setublimit		512
#define __NR_fairsched_cpumask  506
#define __NR_fairsched_nodemask 507
#ifdef __sparc__
#define __NR_ioprio_set		196
#else
#define __NR_ioprio_set		289
#endif
#else
#error "no syscall for this arch"
#endif

#define FAIRSCHED_SET_RATE	0
#define FAIRSCHED_DROP_RATE	1
#define FAIRSCHED_GET_RATE	2

#endif
