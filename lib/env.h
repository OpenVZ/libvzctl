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

#ifndef	_ENV_H_
#define _ENV_H_

#include <limits.h>

#include "vzctl.h"
#include "vztypes.h"
#include "dist.h"
#include "fs.h"
#include "cpu.h"
#include "res.h"
#include "veth.h"
#include "net.h"
#include "cap.h"
#include "res.h"
#include "vzfeatures.h"
#include "io.h"
#include "bindmount.h"
#include "vzenv.h"

/** Shutdown timeout.
 */
#define MAX_SHTD_TM		60
#define MIN_NUMIPTENT		16
/* default cpu units values */
#define LHTCPUUNITS		250
#define UNLCPUUNITS		1000
#define HNCPUUNITS		1000

/** Maximum High Availability priority value */
#define MAXHAPRIO		UINT_MAX

#define EID(h)		(h->ctid)
#define IS_OLD_EID(a)	(strlen(a) < 11)

/* internal  flags */
enum {
	VZCTL_CONF_PARAM        = 0x20000,
	VZCTL_CONF_QUIET        = 0x40000,
};

struct vzctl_opts {
	int wait;
	int onboot;
	int resetub;
	int skip_app;
	char *dumpdir;
	char *lockdir;
	char *config;
	unsigned long *bootorder;
	int apply_iponly;
	int ha_enable;
	unsigned long *ha_prio;
	int setmode;
	int autostop;
};

struct vzctl_name_param {
	char *name;
};

struct vzctl_misc_param {
	list_head_t userpw;
	list_head_t nameserver;
	list_head_t searchdomain;
	list_head_t ve_env;
	char *hostname;
	char *description;
	char *description_eq;
	int ve_type;
	char *ve_type_custom;
	char *uuid;
	int start_disabled;
	int autocompact;
};

struct vzctl_dq_param {
	int enable;                             /**< quota enable yes/no. */
	struct vzctl_2UL_res *diskspace;        /**< disk block limit. */
	struct vzctl_2UL_res *diskinodes;       /**< disk inodes limit. */
	unsigned long *exptime;                 /**< quot aexpiration time. */
	unsigned long *ugidlimit;               /**< userqroup quota limit. */
	int skipquotacheck;
	int journaled_quota;
};


struct vzctl_dev_param;
struct vzctl_meminfo_param;

struct vzctl_env_param {
	struct vzctl_opts *opts;
	struct vzctl_tmpl_param *tmpl;
	struct vzctl_features_param *features;
	struct vzctl_fs_param *fs;
	struct vzctl_dq_param *dq;
	struct vzctl_cpu_param *cpu;
	struct vzctl_res_param *res;
	struct vzctl_veth_param *veth;
	struct vzctl_net_param *net;
	struct vzctl_netdev_param *netdev;
	struct vzctl_cap_param *cap;
	struct vzctl_name_param *name;
	struct vzctl_dev_param *dev;
	struct vzctl_io_param *io;
	struct vzctl_meminfo_param *meminfo;
	struct vzctl_misc_param *misc;
	struct vzctl_env_disk *disk;
	struct vzctl_bindmount_param *bindmount;
/* virtuozzo specific */
	struct vzctl_vz_env_param *vz;
};

struct vzctl_config;

struct vzctl_runtime_ctx {
	int state;
	pid_t pid;
	int wait_p[2];
	int err_p[2];
};

struct vzctl_env_handle {
	ctid_t ctid;
	int veid;
	struct vzctl_config *conf;
	struct vzctl_env_param *env_param;
	struct vzctl_dist_actions *dist_actions;
	struct vzctl_runtime_ctx *ctx;
};

struct start_param {
	struct vzctl_env_handle *h;
	int *init_p;
	int *status_p;
	int pseudosuper_fd;
	pid_t pid;
	vzctl_env_create_FN fn;
	void *data;
};

 struct vzctl_cpt_param;

struct vzctl_env_handle *vzctl_alloc_env_handle(unsigned int id);
struct vzctl_env_param *vzctl2_get_env_param(struct vzctl_env_handle *h);
int vzctl2_env_start(struct vzctl_env_handle *h, int flags);
int vzctl2_env_restore(struct vzctl_env_handle *h, struct vzctl_cpt_param *param, int flags);
int env_start_conf(struct vzctl_env_handle *h, int flags, vzctl_env_create_FN fn, void *data);
int vzctl2_env_stop(struct vzctl_env_handle *h, stop_mode_e stop_mode, int flags);
int is_env_run(struct vzctl_env_handle *h);
int vzctl_chroot(const char *root);
int vzctl_setluid(struct vzctl_env_handle *h);
int vzctl_env_create_ioctl(unsigned veid, int flags);

int set_personality32(void);
int real_env_stop(int stop_mode);
int pre_setup_env(struct start_param *param);
int exec_init(struct start_param *param);
int wait_env_state(struct vzctl_env_handle *h, int state, unsigned int timeout);
int get_cid_uuid_pair(const char *ctid, const char *uuid,
		ctid_t ctid_out, ctid_t uuid_out);
int enter_net_ns(struct vzctl_env_handle *h, pid_t *ct_pid);
int run_stop_script(struct vzctl_env_handle *h);
#endif /* _ENV_H_ */
