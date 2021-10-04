/*
 *  Copyright (c) 2000-2017, Parallels International GmbH
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

#ifndef __LIBVZCTL_H__
#define __LIBVZCTL_H__

#ifndef VZ_DEPRECATED
#define VZ_DEPRECATED __attribute__ ((deprecated))
#endif

#define VZ_DIR			"/etc/vz/"
#define VZ_GLOBAL_CFG		VZ_DIR "vz.conf"
#define VZ_ENV_CONF_DIR		VZ_DIR "conf/"
#define VZ_ENV_CONF_LOCK_DIR	"/var/vz/"
#define VZ_SAMPLE_CONF_PATTERN	"ve-%s.conf-sample"
#define VZ_ENV_CONF_SAMPLE	VZ_ENV_CONF_DIR VZ_SAMPLE_CONF_PATTERN
#define VZCTL_VE_ROOTHDD_DIR	"root.hdd"

#define VZCTL_PARAM_ON		1
#define VZCTL_PARAM_OFF		2
#define VZCTL_PARAM_FORCE_REPAIR	3

#define VZCTL_LAYOUT_3  3
#define VZCTL_LAYOUT_4  4
#define VZCTL_LAYOUT_5  5

#define VZCTL_CPUUNITS_MAX     500000
#define VZCTL_CPUUNITS_MIN     8
#define VZCTL_CPUUNITS_DEFAULT 1000

#define VZCTL_ENV_SNAPSHOT_NAME_PARAM  "VZCTL_ENV_SNAPSHOT_NAME_PARAM"
#define VZCTL_ENV_SNAPSHOT_DESC_PARAM  "VZCTL_ENV_SNAPSHOT_DESC_PARAM"

#define CTID_SIZE	38
typedef char ctid_t[CTID_SIZE];
#define EMPTY_CTID(a)	(a == NULL || (a[0]) == '\0')
#define SET_CTID(a, b)						\
	do {							\
		if ((b) != NULL) {				\
			strncpy((a), (b), sizeof(ctid_t));	\
			(a[sizeof(ctid_t) - 1]) = '\0';		\
		} else						\
			(a[0]) = '\0';				\
	} while (0);

#define CMP_CTID(a, b)	strcmp((a), (b))

struct vzctl_ids {
	unsigned int size;
	ctid_t *ids;
};
typedef struct vzctl_ids vzctl_ids_t;

/** Stop modes.
 */
typedef enum {
	M_HALT,		/**< stop by halt. */
	M_REBOOT,	/**< stop by reboot. */
	M_KILL,		/**< stop by SIGTERM. */
	M_KILL_FORCE,
} stop_mode_e;

enum {
	VZ_T_I386 =	(1<<0),
	VZ_T_X86_64 =	(1<<1),
	VZ_T_IA64 =	(1<<2),
	VZ_T_NPTL =	(1<<3),
	VZ_T_SYSFS =	(1<<4),
	VZ_T_SLM =	(1<<5),
	VZ_T_ZDTM =	(1<<6),
	VZ_T_VZFS_COWDIR = (1<<7),
	VZ_T_VZFS_HASHDIR = (1<<8),
	VZ_T_VZFS_MFILES = (1<<9),
	VZ_T_VZFS3 =	(1<<10),
	VZ_T_VZFS4 =	(1<<11),
	VZ_T_NFS =	(1<<12),
	VZ_T_VZFS0 = (1<<13),
	VZ_T_SIMFS = VZ_T_VZFS0,
	VZ_T_EXT4 = (1<<14),
};

enum {
	VZ_FEATURE_SYSFS	= (1ULL << 0),
	VZ_FEATURE_NFS		= (1ULL << 1),
	VZ_FEATURE_DEF_PERMS	= (1ULL << 2),
	VZ_FEATURE_SIT		= (1ULL << 3),
	VZ_FEATURE_IPIP		= (1ULL << 4),
	VZ_FEATURE_PPP		= (1ULL << 5),
	VZ_FEATURE_IPGRE	= (1ULL << 6),
	VZ_FEATURE_BRIDGE	= (1ULL << 7),
	VZ_FEATURE_NFSD		= (1ULL << 8),
	VZ_FEATURE_TIME		= (1ULL << 9),
};

struct vzctl_feature_param {
	unsigned long long on;
	unsigned long long off;
};

enum {
	VZCTL_SKIP_NONE         = 0x00000,
	VZCTL_SKIP_SETUP        = 0x00001,
	VZCTL_SKIP_CONFIGURE    = 0x00002,
	VZCTL_SKIP_ACTION_SCRIPT= 0x00004,
	VZCTL_SKIP_LOCK         = 0x00008,
	VZCTL_FAST              = 0x00010,
	VZCTL_SKIP_ARPDETECT    = 0x00020,
	VZCTL_WAIT              = 0x00040,
	VZCTL_FORCE             = 0x00080,
	VZCTL_SAVE              = 0x00100,
	VZCTL_RESTORE           = 0x00200,
	VZCTL_SKIP_UMOUNT	= 0x00400,
	VZCTL_SKIP_FSCK		= 0x00800,
	VZCTL_SKIP_MOUNT	= 0x01000,
	VZCTL_APPLY_CONF	= 0x02000,
	VZCTL_SKIP_HA_REG	= 0x04000,
	VZCTL_FORCE_REPAIR	= 0x08000,
	VZCTL_ENV_START_REPAIR	= 0x10000,
};

enum {
	VZ_REG_FORCE		= 0x01, /* force reg: skip owner check */
	VZ_REG_SKIP_OWNER	= 0x02,	/* Skip .owner update on register */
	VZ_REG_SKIP_CLUSTER	= 0x04, /* Skip cluster related operation */
	VZ_REG_RENEW		= 0x08, /* renew registration */
	VZ_UNREG_PRESERVE	= 0x10, /* remove only VEID.conf preserve all
					   data under VE_PRIVATE */
	VZ_REG_SKIP_HA_CLUSTER  = 0x20, /* compatibility: alias for VZ_REG_SKIP_CLUSTER */
	VZ_REG_START            = 0x40, /* Start CT after registration */
	VZ_REG_RENEW_NETIF_IFNAME	= 0x80, /* Renew host_ifname */
	VZ_REG_RENEW_NETIF_MAC	= 0x100, /* Renew host_mac */
};

/* Global internal flags for vzctl2_set_flags  */
enum {
	VZCTL_FLAG_DONT_SEND_EVT = 0x01, /* Do not send vzevent in any case */
	VZCTL_FLAG_DONT_USE_WRAP = 0x02, 
	VZCTL_FLAG_WRAP		 = 0x04,
};

enum {
	VZCTL_CPT_UNFREEZE_ON_DUMP      = 0x1,
	VZCTL_CPT_KEEP_PAGES            = 0x2,
	VZCTL_CPT_STOP_TRACKER		= 0x4,
	VZCTL_CPT_CREATE_DEVMAP		= 0x8,
};

enum vzctl_config_flags {
	VZCTL_CONF_SKIP_GLOBAL          = 0x01, /**< Skip global VZ config processing */
	VZCTL_CONF_BASE_SET             = 0x02, /**< Parse limited set of parameters:
						  VE_PRIVATE, VE_ROOT */
	VZCTL_CONF_SKIP_NON_EXISTS      = 0x04,
	VZCTL_CONF_SKIP_PRIVATE		= 0x08, /**< skip parse CT private parameters
						  IP_ADDRESS, OSTEMPLATE. VE_PRIVATE, ... */
	VZCTL_CONF_USE_RELATIVE_PATH	= 0x10,
	VZCTL_CONF_SKIP_PARAM_ERRORS	= 0x20,
	VZCTL_CONF_SKIP_PARSE		= 0x40,
	VZCTL_CONF_RUNTIME_PARAM	= 0x80,
	VZCTL_CONF_LOAD_DISK_INFO	= 0x100,
	VZCTL_CONF_UNREGISTERED		= 0x200,
};

/** Exec modes.
 */
typedef enum {
        MODE_EXEC,              /**< use exec syscall. */
        MODE_BASH,              /**< exec bash, and put command on stdin. */
        MODE_EXECFN,            /**< exec function. */
        MODE_BASH_NOSTDIN,      /**< exec bash & close stdin. */
	MODE_TTY,
} exec_mode_e;

struct vzctl_exec_handle {
	int pid;
	int exited;
	int comm[2];
};

/* Netfilter:
 *    "disabled"   -- no iptables in CT allowed
 *    "stateless"  -- all but conntracks and NAT (filter, mangle) are allowed
 *    "stateful"   -- all but NAT is allowed
 *    "full"       -- all netfilter functionality is allowed
 */
enum {
	VZCTL_NF_DISABLED = 1,
	VZCTL_NF_STATELESS,
	VZCTL_NF_STATEFUL,
	VZCTL_NF_FULL,
};

typedef enum {
	VZCTL_AUTOSTART_NONE	= -1,
	VZCTL_AUTOSTART_OFF	= 0,
	VZCTL_AUTOSTART_ON 	= 1,
	VZCTL_AUTOSTART_AUTO	= 2,
} autostart_mode_t;

#define VZCTL_VETH_CONFIGURE_ALL        0x01
#define VZCTL_VETH_CONFIGURE_NONE       0x02

enum vzctl_veth_nettype {
	VZCTL_NETTYPE_BRIDGE	= 1,
	VZCTL_NETTYPE_VNET	= 2,
};

enum vzctl_veth_vport_type {
	VZCTl_VPORTTYPE_NONE	= 0,
	VZCTL_VPORTTYPE_OVS	= 1,
};

struct vzctl_veth_dev_param {
	const char *mac;		/**< device MAC address. */
	const char *dev_name;		/**< device name. */
	const char *mac_ve;		/**< device MAC address in VE. */
	const char *dev_name_ve;	/**< device name in VE. */
	const char *gw;                 /**< gateway ip */
	const char *network;		/**< connect virtual interface to
					  virtual network or bridge.
					  (depends on nettype) */
	int dhcp;                       /**< DHCP4 2 - on 1 - off. */
	int allow_mac_spoof;
	int mac_renew;
	int dhcp6;                      /**< DHCP6 2 - on 1 - off. */
	const char *gw6;                 /**< gateway ip6 */
	int ip_apply_mode;              /***< 1 - set 0 - add */
	int configure_mode;
	int allow_ip_spoof;
	int nettype;
	int vporttype;			/* vzctl_veth_vport_type */
};

struct vzctl_rate_param {
	const char *dev;
	int net_class;
	int rate;
};


#define VZCTL_TRANSITION_MIGRATING	"migrating"
#define VZCTL_TRANSITION_RESTORING	"restoring"

struct vzctl_env_status {
#define ENV_STATUS_EXISTS	0x01
#define ENV_STATUS_MOUNTED	0x02
#define ENV_STATUS_RUNNING	0x04
#define ENV_STATUS_SUSPENDED	0x08
#define ENV_STATUS_CPT_SUSPENDED 0x10
#define ENV_STATUS_CPT_UNDUMPED	0x20
#define ENV_STATUS_MOUNTED_FAST	0x40
#define ENV_STATUS_ALL		0xff
/* flags */
#define ENV_SKIP_OWNER		0x100
	int mask;
	char transition[256];
};
typedef struct vzctl_env_status vzctl_env_status_t;

struct vzctl_2UL_res {
	unsigned long b;        /* barrier */
	unsigned long l;        /* limit */
};

enum vzctl_cpulimit_type {
	VZCTL_CPULIMIT_PCT,
	VZCTL_CPULIMIT_MHZ,
	VZCTL_CPULIMIT_PCT_TO_MHZ, /* Limit in % convert to Mhz */
};

struct vzctl_cpulimit_param {
	unsigned long limit;
	int type;
};

struct vzctl_cpustat {
	float loadavg[3];       /* average number of jobs in the run
				   queue over the last 1, 5 and 15 minutes */
	float uptime;           /* time in sec VE has been up */
	float user;	/* user time in sec */
	float nice;	/* nice time in sec */
	float system;	/* system time in sec */
	float idle;
};

struct vzctl_iostat {
	unsigned long long read;
	unsigned long long write;
	unsigned long long read_reqs;
	unsigned long long write_reqs;
};

#define TC_MAX_CLASSES	16
struct vzctl_tc_netstat {
	unsigned long long incoming[TC_MAX_CLASSES];
	unsigned long long outgoing[TC_MAX_CLASSES];
	unsigned int incoming_pkt[TC_MAX_CLASSES];
	unsigned int outgoing_pkt[TC_MAX_CLASSES];
};

struct vzctl_netstat {
	unsigned long long incoming;
	unsigned long long outgoing;
	unsigned long long incoming_pkt;
	unsigned long long outgoing_pkt;
};

enum {
	VZCTL_ENV_CREATED = 1,
	VZCTL_ENV_REGISTERED = 2,
	VZCTL_ENV_UNREGISTERED = 3,
	VZCTL_ENV_DELETED = 4,
	VZCTL_ENV_CONFIG_CHANGED = 5,
	VZCTL_ENV_STARTED = 6,
	VZCTL_ENV_STOPPED = 7,
	VZCTL_ENV_SUSPENDED = 8,
	VZCTL_NET_CLASSES_CONFIG_CHANGED = 9,
	VZCTL_NET_SHAPING_CONFIG_CHANGED = 10,
	VZCTL_ENV_NET_CONFIG_CHANGED = 11,
	VZCTL_ENV_UMOUNT = 12,
	VZCTL_ENV_CONFIGURED = 13,
};

#define VZCTL_SET_USERPASSWD_CRYPTED	0x1

typedef enum {
        VZCTL_ENV_TYPE_REGULAR = 1,
        VZCTL_ENV_TYPE_TEMPORARY = 2,
        VZCTL_ENV_TYPE_TEMPLATE = 3,
        VZCTL_ENV_TYPE_CUSTOM = 4,

	VZCTL_ENV_TYPE_MAX = VZCTL_ENV_TYPE_TEMPLATE,
} vzctl_env_type;

typedef enum {
        VZCTL_SET_NONE = 0,
        VZCTL_SET_RESTART,
        VZCTL_SET_IGNORE,
        VZCTL_SET_MODE_MAX = VZCTL_SET_IGNORE,
} vzctl_setmode_t;

enum {
	VZCTL_DISK_DETACH       = 0x1,
	VZCTL_DISK_SKIP_CREATE  = 0x2,
	VZCTL_DISK_SKIP_CONFIGURE = 0x4,
	VZCTL_DISK_RECREATE	= 0x8,
};

struct vzctl_state_evt {
	unsigned int type;
	ctid_t ctid;
	unsigned int state;
	unsigned long long dev;
};


struct vzctl_mount_param {
	char device[64];
	int ro;
	char *guid;
	int unused1;
	char *target;
	int unused;
	char *mount_data;
	char *component_name;
	int flags;
	int fsck; /* 0 - default. 1 - VZCTL_PARAM_ON,
		     2 - VZCTL_PARAM_OFF, 3 - VZCTL_PARAM_FORCE_REPAIR */
	char dummy[32];
};

struct vzctl_create_image_param {
	int mode;
	unsigned long size;
	char *enc_keyid;
};

struct vzctl_cpuinfo {
	int ncpu;
	unsigned long long freq;
};

struct vzctl_disk_param {
	char uuid[39];
	int enabled;
	unsigned long size;
	char *path;
	char *mnt;
	int user_quota;
	int offline_resize;
	int autocompact;
	char *storage_url;
	int use_device;
	char *enc_keyid;
	char *mnt_opts;
	int dummy[32];
};

struct vzctl_disk_stats {
	char device[64];
	unsigned long long total; // in kilobytes
	unsigned long long free; // in kilobytes
	unsigned long long inodes;
	unsigned long long ifree;
	struct vzctl_iostat io;
	char part[64];
};

struct vzctl_meminfo {
	unsigned long long total;
	unsigned long long free;
	unsigned long long cached;
	unsigned long long swap_in;
	unsigned long long swap_out;
	unsigned long long rss;
};

#define VZCTL_SNAPSHOT_SKIP_DUMP	0x01
#define VZCTL_SNAPSHOT_SKIP_RESUME	0x02
struct vzctl_snapshot_param {
	char *guid;
	char *name;
	char *desc;
	int flags;
};

struct vzctl_snap_holder {
	int n;
	int *fds;
};

struct vzctl_tsnapshot_param {
	char *component_name;
	char *snap_dir;
	char *cbt_uuid;
	int dummy[32];
};

struct vzctl_switch_snapshot_param {
	char *guid;
	int flags;
};

struct vzctl_reg_param {
	ctid_t ctid;
	const char *uuid;
	const char *name;
	int dummy[32];
};

#define VZCTL_MAX_NCPU        4096
struct vzctl_cpumask
{
	unsigned long mask[VZCTL_MAX_NCPU / (8 * sizeof(unsigned long))];
	int auto_assigment;
};

#define VZCTL_MAX_NNODE       4096
struct vzctl_nodemask
{
	unsigned long mask[VZCTL_MAX_NNODE / (8 * sizeof(unsigned long))];
};

struct vzctl_snapshot_data {
	int current;
	char *guid;
	char *parent_guid;
	char *name;
	char *date;
	char *desc;
};

struct vzctl_snapshot_tree {
	struct vzctl_snapshot_data **snapshots;
	int nsnapshots;
};


#define VZCTL_CMD_CHKPNT              1
#define VZCTL_CMD_SUSPEND             2
#define VZCTL_CMD_FREEZE              VZCTL_CMD_SUSPEND
#define VZCTL_CMD_DUMP                3
#define VZCTL_CMD_RESTORE             4
#define VZCTL_CMD_UNDUMP              5

#define VZCTL_CMD_KILL                10
#define VZCTL_CMD_RESUME              11
#define VZCTL_CMD_DUMP_LEAVE_FROZEN	13

enum {
	VZCTL_MEMINFO_NONE	= 1,
	VZCTL_MEMINFO_PAGES	= 2,
};

struct vzctl_cpt_param {
	char *dumpfile;
	unsigned int ctx;
	unsigned int cpu_flags;
	int cmd;
	int flags;
	int rst_fd;
};

enum {
	VZCTL_ROOT_DISK_SKIP	= 1,
	VZCTL_ROOT_DISK_BLANK	= 2,
};

enum {
	VZCTL_GET_PLOOP_ARGS_EXTERNAL	= 1,
};

struct vzctl_env_create_param {
	ctid_t ctid;
	const char *uuid;
	char *config;
	char *ostmpl;
	char *ve_private;
	char *ve_root;
	char *name;
	int layout;
	union {
		int no_root_disk;
		int root_disk;
	};
	char *enc_keyid;
	int dummy[32];
};

struct vzctl_reinstall_param {
	int skipbackup;
	int resetpwdb;
	int skipscripts;
	char *reinstall_scripts;
	char *reinstall_opts;
	char *ostemplate;
	void *pad[32];
};

enum {
	VZCTL_MEM_GUARANTEE_AUTO = 0,
	VZCTL_MEM_GUARANTEE_PCT,
	VZCTL_MEM_GUARANTEE_BYTES,
};

struct vzctl_mem_guarantee {
	int type;
	unsigned long value;
	int dummy[32];
};

enum {
	VZCTL_AUTOSTOP_SHUTDOWN	= 1,
	VZCTL_AUTOSTOP_SUSPEND
};

enum {
	VZCTL_ENC_REENCRYPT	= 0x01,
	VZCTL_ENC_WIPE		= 0x02,
};

struct vzctl_net_info {
	int if_up;
	char *if_ips;
};

struct vzctl_compact_param {
	int defrag;
};

struct vzctl_console {
	int ntty;
};

typedef int (* execFn)(void *data);

/* Internal data representattion */
typedef struct vzctl_env_handle vzctl_env_handle;
typedef vzctl_env_handle *vzctl_env_handle_ptr;

typedef struct vzctl_env_param vzctl_env_param;
typedef vzctl_env_param *vzctl_env_param_ptr;

typedef struct vzctl_ip_param *vzctl_ip_iterator;
typedef struct vzctl_veth_dev *vzctl_veth_dev_iterator;

typedef struct vzctl_rate *vzctl_rate_iterator;
typedef struct vzctl_str_param *vzctl_str_iterator;


typedef struct vzctl_disk *vzctl_disk_iterator;
typedef struct vzevt_handle_s vzevt_handle_t;
typedef void cleanup_handler_t;


#ifndef _USE_DLOPEN_
#ifdef __cplusplus
extern "C" {
#endif

/** Build path to VE configuration file
 *
 * @param ctid          VEID
 * @param buf           storage buffer
 * @param len           buffer size
 * @return              exit code of snprintf()
 */
int vzctl2_get_env_conf_path(const ctid_t ctid, char *buf, int len);

/** Build path to global VZ configuration file
 *
 * @param buf           storage buffer
 * @param len           buffer size
 * @return              exit code of snprintf()
 */
int vzctl2_get_global_conf_path(char *buf, int len);


/** Allocate structure to collect ids from vzctl_get_env_ids()
 *
 * @return		NULL on error
 */
vzctl_ids_t *vzctl2_alloc_env_ids(void);

/** Free data allocated by the vzctl2_alloc_env_ids(int()
 */
void vzctl2_free_env_ids(vzctl_ids_t *ids);

/** Get VE ids by state.
 * This function fill VE ids with specified state into vzctl_ids structure.
 * Structure automatically expanded if needed.
 *
 * @param ids		allocated by vz_alloc_env_ids() structure
 * @param mask		supported values ENV_STATUS_EXISTS, ENV_STATUS_RUNNING
 * @return:		>= 0 number of VE in ids array.
 *			<  0 error
*/
int vzctl2_get_env_ids_by_state(vzctl_ids_t *veids, unsigned int mask);


/** Get CT status
 *
 * @param ctid		VEID
 * @param status	status data
 * @param mask		status filter (ENV_STATUS_ALL for all statuses)
 */
int vzctl2_get_env_status(const ctid_t ctid, vzctl_env_status_t *status, int mask);
int vzctl2_get_env_status_info(struct vzctl_env_handle *h, vzctl_env_status_t *status, int mask);

/** Initialize internal data
 * open /dev/vzctl file descriptor it needed for most libvzctl functions
 *
 * @return		0 on success
 */
int vzctl2_lib_init(void);
void vzctl2_lib_close(void);
/** Get vz service status
 * @return  1 - running
 *	    0 - stopped
 *	   -1 - error
 */
int vzctl2_vz_status(void);

/** Register VE
 * - symlynk created /vz/conf/VEID.conf -> VE_PRIVATE/ve.conf
 * - VEID="id" variable stored to the VE_PRIVATE/ve.conf
 * - created VE_PRIVATE/.owner
 * - created VE_PRIVATE/.ve_layout -> 4
 * - created VE_PRIVATE/.cluster_service_name in case CLUSTER_MODE==shared
 *
 * @param path		VE private data root
 * @param param		struct vzctl_reg_param
 * @param flags
 * @return		ctid on -1 in case error
 */
int vzctl2_env_register(const char *path, struct vzctl_reg_param *param, int flags);


/** Unregister VE
 * @param path		VE private data root
 * @param ctid		assigned id
 * @param flags
 * @return		0 on sucess
 */
int vzctl2_env_unregister(const char *path, const ctid_t ctid, int flags);
int vzctl2_env_unreg(struct vzctl_env_handle *h, int flags);


/* Lock Container
 * For layout == 4 create lock file under VE_PRIVATE/.lck
 * and lock with old locking schema under LOCKDIR/VEID.lck
 * @return:     > 0 lock file descriptor
 *              -1 locking error
 *              -2 VE locked
 */
int vzctl2_env_lock(struct vzctl_env_handle *h, const char *status);

/** Unlock Container.
 *
 * @param ctid		id.
 * @param lckfd         lock file descriptor
 */
void vzctl2_env_unlock(struct vzctl_env_handle *h, int lckfd);

/* get Container io statisctics
 * @return		0 on success
 */
int vzctl2_get_env_iostat(const ctid_t ctid, struct vzctl_iostat *stat, int size);

int vzctl2_get_env_meminfo(const ctid_t ctid, struct vzctl_meminfo *meminfo, int size);
int vzctl2_get_env_total_meminfo(unsigned long *limit_bytes, unsigned long *usage_bytes);
void vzctl2_release_net_info(struct vzctl_net_info *info);
int vzctl2_get_net_info(struct vzctl_env_handle *h, const char *ifname,
		struct vzctl_net_info **info);

/** Get Container cpu statisctics
 * @return		0 on success
 */
int vzctl2_env_cpustat(struct vzctl_env_handle *h, struct vzctl_cpustat *cpustat,
		int size);

int vzctl2_get_env_tc_netstat(struct vzctl_env_handle *h,
		struct vzctl_tc_netstat *stat, int v6);

int vzctl2_get_env_netstat(const ctid_t ctid, const char *dev,
		struct vzctl_netstat *stat, int size);

/** Set Container I/O priority
 * @return		0 on success
 */
int vzctl2_set_ioprio(struct vzctl_env_handle *h, int prio);

/** Set Container I/O limit
 * @return		0 on success
 */
int vzctl2_set_iolimit(struct vzctl_env_handle *h, unsigned int limit);
int vzctl2_get_iolimit(struct vzctl_env_handle *h, unsigned int *limit);
int vzctl2_set_iopslimit(struct vzctl_env_handle *h, unsigned int limit);
int vzctl2_get_iopslimit(struct vzctl_env_handle *h, unsigned int *limit);
int vzctl2_clear_ve_netstat(struct vzctl_env_handle *h);
int vzctl2_clear_all_ve_netstat(void);

vzctl_env_handle_ptr vzctl2_alloc_env_handle();
vzctl_env_handle_ptr vzctl2_env_open(const char *ctid, int flags, int *err);
vzctl_env_handle_ptr vzctl2_env_open_conf(const ctid_t, const char *fname, int flags, int *err);
void vzctl2_env_close(vzctl_env_handle_ptr h);
int vzctl2_apply_param(vzctl_env_handle_ptr h, vzctl_env_param_ptr param, int flags);
int vzctl2_env_save(vzctl_env_handle_ptr h);
int vzctl2_env_save_conf(vzctl_env_handle_ptr h, const char *fname);

vzctl_env_param_ptr vzctl2_alloc_env_param();
void vzctl2_free_env_param(vzctl_env_param_ptr env);

vzctl_env_param_ptr vzctl2_get_env_param(vzctl_env_handle_ptr h);

int vzctl2_env_set_ub_resource(vzctl_env_param_ptr env, int id, struct vzctl_2UL_res *res);
int vzctl2_env_get_ub_resource(vzctl_env_param_ptr env, int id, struct vzctl_2UL_res *res);

int vzctl2_env_set_ramsize(vzctl_env_param_ptr env, unsigned long ramsize);
int vzctl2_env_get_ramsize(vzctl_env_param_ptr env, unsigned long *ramsize);
int vzctl2_env_set_memguarantee(vzctl_env_param_ptr env,
		struct vzctl_mem_guarantee *meemguarantee);
int vzctl2_env_get_memguarantee(vzctl_env_param_ptr env,
		struct vzctl_mem_guarantee *meemguarantee);

int vzctl2_env_set_diskspace(vzctl_env_param_ptr env, struct vzctl_2UL_res *res);
int vzctl2_env_get_diskspace(vzctl_env_param_ptr env, struct vzctl_2UL_res *res);

int vzctl2_env_set_diskinodes(vzctl_env_param_ptr env, struct vzctl_2UL_res *res);
int vzctl2_env_get_diskinodes(vzctl_env_param_ptr env, struct vzctl_2UL_res *res);

int vzctl2_env_set_quotaugidlimit(vzctl_env_param_ptr env, unsigned long limits);
int vzctl2_env_get_quotaugidlimit(vzctl_env_param_ptr env, unsigned long *limits);

int vzctl2_env_set_cap(vzctl_env_handle_ptr h, vzctl_env_param_ptr env, unsigned long capmask);
int vzctl2_env_get_cap(vzctl_env_param_ptr env, unsigned long *capmask);

int vzctl2_env_set_cpulimit(vzctl_env_param_ptr env, struct vzctl_cpulimit_param *param);
int vzctl2_env_get_cpulimit(vzctl_env_param_ptr env, struct vzctl_cpulimit_param *param);

int vzctl2_env_set_cpuunits(vzctl_env_param_ptr env, unsigned long units);
int vzctl2_env_get_cpuunits(vzctl_env_param_ptr env, unsigned long *units);

int vzctl2_env_set_cpu_count(vzctl_env_param_ptr env, unsigned long num);
int vzctl2_env_get_cpu_count(vzctl_env_param_ptr env, unsigned long *num);

int vzctl2_env_set_iolimit(vzctl_env_param_ptr env, unsigned int limit);
int vzctl2_env_get_iolimit(vzctl_env_param_ptr env, unsigned int *limit);

int vzctl2_env_set_iopslimit(vzctl_env_param_ptr env, unsigned int limit);
int vzctl2_env_get_iopslimit(vzctl_env_param_ptr env, unsigned int *limit);

int vzctl2_env_set_ioprio(vzctl_env_param_ptr env, int prio);
int vzctl2_env_get_ioprio(vzctl_env_param_ptr env, int *prio);

int vzctl2_env_get_name(vzctl_env_handle_ptr h, const char **name);

int vzctl2_set_name(vzctl_env_handle_ptr h, const char *name);
int vzctl2_get_name(vzctl_env_handle_ptr h, const char **name);

int vzctl2_env_get_description(vzctl_env_param_ptr env, const char **desc);
int vzctl2_env_set_description(vzctl_env_param_ptr env, const char *desc);

int vzctl2_env_get_hostname(vzctl_env_param_ptr env, const char **name);
int vzctl2_env_set_hostname(vzctl_env_param_ptr env, const char *name);

int vzctl2_env_get_ve_private_path(vzctl_env_param_ptr env, const char **path);
int vzctl2_env_get_ve_private_orig_path(vzctl_env_param_ptr env, const char **path);
int vzctl2_env_get_ve_root_path(vzctl_env_param_ptr env, const char **path);
int vzctl2_env_get_ve_root_orig_path(vzctl_env_param_ptr env, const char **path);

int vzctl2_env_get_ostemplate(vzctl_env_param_ptr env, const char **name);
int vzctl2_env_set_ostemplate(struct vzctl_env_param *env, const char *name);
int vzctl2_env_get_apptemplates(vzctl_env_param_ptr env, const char **names);

int vzctl2_env_set_autostart(vzctl_env_param_ptr env, int mode);
int vzctl2_env_get_autostart(vzctl_env_param_ptr env, int *mode);
int vzctl2_env_set_autostop(vzctl_env_param_ptr env, int mode);
int vzctl2_env_get_autostop(vzctl_env_param_ptr env, int *mode);

int vzctl2_env_get_ipstr(vzctl_ip_iterator it, char *buf, int len);

int vzctl2_env_add_ipaddress(vzctl_env_param_ptr env, const char *ipstr);
int vzctl2_env_del_ipaddress(vzctl_env_param_ptr env, const char *ipstr);
vzctl_ip_iterator vzctl2_env_get_ipaddress(vzctl_env_param_ptr env, vzctl_ip_iterator it);

int vzctl2_env_get_veth_param(vzctl_veth_dev_iterator itdev, struct vzctl_veth_dev_param *dev, int size);
int vzctl2_env_set_veth_param(struct vzctl_veth_dev *dev, struct vzctl_veth_dev_param *param, int size);
vzctl_veth_dev_iterator vzctl2_create_veth_dev(struct vzctl_veth_dev_param *dev, int size);
void vzctl2_free_veth_dev(vzctl_veth_dev_iterator dev);
int vzctl2_env_add_veth_ipaddress(vzctl_veth_dev_iterator dev, const char *ipstr);
int vzctl2_env_del_veth_ipaddress(vzctl_veth_dev_iterator dev, const char *ipstr);
vzctl_ip_iterator vzctl2_env_get_veth_ipaddress(vzctl_veth_dev_iterator itdev,
							vzctl_ip_iterator itip);
int vzctl2_env_add_veth(vzctl_env_param_ptr env, vzctl_veth_dev_iterator itdev);
int vzctl2_env_del_veth(vzctl_env_param_ptr env, const char *ifname);
vzctl_veth_dev_iterator vzctl2_env_get_veth(vzctl_env_param_ptr env, vzctl_veth_dev_iterator it);

int vzctl2_env_get_rate_param(vzctl_rate_iterator itrate, struct vzctl_rate_param *rate);
vzctl_rate_iterator vzctl2_create_rate(struct vzctl_rate_param *rate);
int vzctl2_env_add_rate(vzctl_env_param_ptr env, vzctl_rate_iterator itrate);
vzctl_rate_iterator vzctl2_env_get_rate(vzctl_env_param_ptr env, vzctl_rate_iterator it);
int vzctl2_env_set_ratebound(vzctl_env_param_ptr env, int ratebound);
int vzctl2_env_get_ratebound(vzctl_env_param_ptr env, int *ratebound);

const char *vzctl2_env_get_str_param(vzctl_str_iterator it);
int vzctl2_env_add_nameserver(vzctl_env_param_ptr env, const char *server);
vzctl_str_iterator vzctl2_env_get_nameserver(vzctl_env_param_ptr env, vzctl_str_iterator it);
int vzctl2_env_add_searchdomain(vzctl_env_param_ptr env, const char *domain);
vzctl_str_iterator vzctl2_env_get_searchdomain(vzctl_env_param_ptr env, vzctl_str_iterator it);
int vzctl2_env_get_param_bool(struct vzctl_env_handle *h, const char *name);

int vzctl2_env_set_type(struct vzctl_env_param *env, vzctl_env_type type);
int vzctl2_env_get_type(struct vzctl_env_param *env, vzctl_env_type *type);

const char *vzctl2_env_get_ctid(struct vzctl_env_handle *h);
int vzctl2_env_get_veid(struct vzctl_env_handle *h);
int vzctl2_env_set_uuid(struct vzctl_env_param *env, const char *uuid);
int vzctl2_env_get_uuid(struct vzctl_env_param *env, const char **uuid);
int vzctl2_env_set_cpumask(struct vzctl_env_param *env, const char *str);
int vzctl2_env_get_cpumask(struct vzctl_env_param *env, char *buf, int buflen);
int vzctl2_env_set_nodemask_ex(struct vzctl_env_param *env,
		struct vzctl_cpumask *cpumask, struct vzctl_nodemask *nodemask);
int vzctl2_env_set_nodemask(struct vzctl_env_param *env, const char *str);
int vzctl2_env_get_nodemask(struct vzctl_env_param *env, char *buf, int buflen);
int vzctl2_env_get_layout(struct vzctl_env_param *env, int *layout);
int vzctl2_env_set_layout(struct vzctl_env_param *env, int layout, int flags);
int vzctl2_env_set_apply_iponly(struct vzctl_env_param *env, int enable);
int vzctl2_env_get_apply_iponly(struct vzctl_env_param *env, int *enable);

int vzctl2_env_get_ha_enable(vzctl_env_param_ptr env, int *enable);
int vzctl2_env_set_ha_enable(vzctl_env_param_ptr env, int enable);
int vzctl2_env_get_ha_prio(vzctl_env_param_ptr env, unsigned long *prio);
int vzctl2_env_set_ha_prio(vzctl_env_param_ptr env, unsigned long prio);

int vzctl2_env_set_meminfo(vzctl_env_param_ptr env, int mode, unsigned long val);

int vzctl2_env_add_device(vzctl_env_param_ptr env, const char *dev);
int vzctl2_env_del_device(vzctl_env_param_ptr env, const char *dev);
int vzctl2_env_add_devnodes(vzctl_env_param_ptr env, const char *dev);
int vzctl2_env_del_devnodes(vzctl_env_param_ptr env, const char *dev);
int vzctl2_env_add_pcidev(vzctl_env_param_ptr env, const char *dev);
int vzctl2_env_del_pcidev(vzctl_env_param_ptr env, const char *dev);
int vzctl2_env_set_features(vzctl_env_param_ptr env, struct vzctl_feature_param *param);
int vzctl2_env_get_features(vzctl_env_param_ptr env, struct vzctl_feature_param *param);
int vzctl2_env_set_netfilter(struct vzctl_env_param *env, unsigned mode);
int vzctl2_env_get_netfilter(struct vzctl_env_param *env, unsigned *mode);
int vzctl2_env_get_autocompact(vzctl_env_param_ptr env, int *enable);
int vzctl2_env_set_autocompact(vzctl_env_param_ptr env, int enable);
int vzctl2_env_get_bootorder(struct vzctl_env_param *env, unsigned long *bootorder);
int vzctl2_env_set_bootorder(struct vzctl_env_param *env, unsigned long bootorder);
int vzctl2_env_get_disabled(struct vzctl_env_param *env, int *disabled);

int vzctl2_get_config_fname(const char *param_conf, char *config, int len);
int vzctl2_get_config_full_fname(const char *param_conf, char *config, int len);
int vzctl2_add_env_param_by_name(struct vzctl_env_param *env, const char *name, const char *str);
int vzctl2_add_env_param_by_id(struct vzctl_env_param *env, unsigned id, const char *str);
int vzctl2_del_param_by_id(struct vzctl_env_handle *h, int id);
int vzctl2_del_param_by_name(struct vzctl_env_handle *h, const char *name);
int vzctl2_merge_env_param(struct vzctl_env_handle *h, struct vzctl_env_param *env);


/* get parameter by name NAME=value
*/
int vzctl2_env_get_param(vzctl_env_handle_ptr h, const char *name, const char **res);
int vzctl2_env_set_param(struct vzctl_env_handle *h, const char *name, const char *str);

/* Create user (if not exists) and set password in the Container
 *
 */
int vzctl2_env_set_userpasswd(struct vzctl_env_handle *h, const char *user,
		const char *passwd, int flags);
/* Authenticate the user in a the container
 * @param h		Container handle
 * @param user		User name
 * @param password	User password
 * @param gid		if >= 0 user checked to be a member of group gid.
 * @param type		0 - system, 1 - pleskadmin
 * @return		VZCTL_E_AUTH on auth failure, 0 on success
 */
int vzctl2_env_auth(struct vzctl_env_handle *h, const char *user, const char *passwd,
		int gid, int type);

/* Get & lock next free Container id
 * @param dst		check for /dst/$VEID
 */
int vzctl2_get_free_envid(unsigned int *newid, const char *dst,
		const char *unused);


/***************** Container's uptime *******************************/

/** Resets the Container uptime counter (start date and counter itself).
 *
 * @param h		handle to Container
 */
int vzctl2_env_reset_uptime(vzctl_env_handle_ptr h);

/** Returns the Container uptime in seconds since some datetime and this
 *  datetime (in seconds since the Epoch)
 *
 * @param h		A handle to Container
 * @param uptime	[out] A pointer to the integer that receives uptime
 * @param start_time	[out] A pointer to the integer that receives start
 *                      datetime
 */
int vzctl2_env_get_uptime(vzctl_env_handle_ptr h, unsigned long long *uptime,
		unsigned long long *start_time);

/** Sets the Container uptime in seconds since some datetime and this
 *  datetime (in seconds since the Epoch)
 *
 * @param h		A handle to Container
 * @param uptime	The uptime value (in seconds)
 * @param start_time	The uptime start date (in seconds since the Epoch)
 */
int vzctl2_env_set_uptime(vzctl_env_handle_ptr h, unsigned long long uptime,
		unsigned long long start_time);

/** Updates the Container uptime counter on filesystem on base of run-time
 *  uptime.
 *
 * @param h		handle to Container
 */
int vzctl2_env_sync_uptime(vzctl_env_handle_ptr h);

int vzctl2_get_cpuinfo(struct vzctl_cpuinfo *info);

int vzctl2_check_owner(const char *ve_private);

int vzctl2_get_envid_by_name(const char *name, ctid_t ctid);

int vzctl2_env_layout_version(const char *path);

int vzctl2_env_is_mounted(struct vzctl_env_handle *h);

/***************** Cancelation *******************************/
void vzctl2_cancel_last_operation(void);

/***************** Logging/Error *******************************/
int vzctl2_init_log(const char *progname);
int vzctl2_set_log_file(const char *file);
int vzctl2_set_log_level(int level);
int vzctl2_set_log_enable(int enable);
int vzctl2_set_log_verbose(int verbose);
int vzctl2_get_log_verbose(void);
int vzctl2_get_log_quiet(void);
int vzctl2_set_log_quiet(int quiet);
const char *vzctl2_get_log_progname();
const char *vzctl2_get_last_error(void);
void vzctl2_set_ctx(const ctid_t ctid);
int vzctl2_set_log_file(const char *file);
int vzctl2_get_log_fd(void);
void vzctl2_log(int level, int err_no, const char *format, ...)
	__attribute__ ((__format__ (__printf__, 3, 4)));

/****************** Actions ************************************/
int vzctl2_env_create(struct vzctl_env_param *env, struct vzctl_env_create_param *param,
		int flags);
int vzctl2_env_reinstall(struct vzctl_env_handle *h,
		struct vzctl_reinstall_param *param);
int vzctl2_env_start(struct vzctl_env_handle *h, int flags);
int vzctl2_env_pause(struct vzctl_env_handle *h, int flags);
int vzctl2_env_restart(struct vzctl_env_handle *h, int flags);
int vzctl2_env_stop(struct vzctl_env_handle *h, stop_mode_e stop_mode, int flags);
int vzctl2_env_mount(struct vzctl_env_handle *h, int flags);
int vzctl2_env_umount(struct vzctl_env_handle *h, int flags);
int vzctl2_env_convert_layout(struct vzctl_env_handle *h, int new_layout);
int vzctl2_env_destroy(struct vzctl_env_handle *h, int flags);

/***************** Event ***************************************/
int vzctl2_register_evt(vzevt_handle_t **h);
void vzctl2_unregister_evt(vzevt_handle_t *h);
int vzctl2_get_state_evt(vzevt_handle_t *h, struct vzctl_state_evt *evt, int size);
int vzctl2_send_state_evt(const ctid_t ctid, int state);
int vzctl2_get_evt_fd(vzevt_handle_t *h);

/*************** snapshot manipulation **************************/
int vzctl2_mount_disk_snapshot(const char *path, struct vzctl_mount_param *param);
int vzctl2_mount_snap(struct vzctl_env_handle *h, const char *mnt, const char *guid,
			const char *component_name);
int vzctl2_umount_disk_snapshot(const char *path, const char *guid, const char *component_name);
int vzctl2_umount_snapshot(struct vzctl_env_handle *h, const char *guid, const char *component_name);
int vzctl2_delete_snapshot(struct vzctl_env_handle *h, const char *guid);
void vzctl2_env_drop_cbt(struct vzctl_env_handle *h);
int vzctl2_merge_snapshot(struct vzctl_env_handle *h, const char *guid);
int vzctl2_umount_image_by_dev(const char *dev);
int vzctl2_create_snapshot(struct vzctl_env_handle *h, const char *guid);
int vzctl2_delete_disk_snapshot(const char *path, const char *guid);
int vzctl2_merge_disk_snapshot(const char *path, const char *guid);
int vzctl2_create_disk_snapshot(const char *path, const char *guid);
int vzctl2_switch_disk_snapshot(const char *path, const char *guid, const char *guid_old, int flags);
int vzctl2_env_create_snapshot(struct vzctl_env_handle *h, struct vzctl_snapshot_param *param);
int vzctl2_env_delete_tsnapshot(struct vzctl_env_handle *h, const char *guid,
		 struct vzctl_snap_holder *holder);
int vzctl2_env_create_disk_snapshot(struct vzctl_env_handle *h, const char *guid);
int vzctl2_env_create_temporary_snapshot(struct vzctl_env_handle *h,
		const char *guid, struct vzctl_tsnapshot_param *tparam,
		struct vzctl_snap_holder *holder);
void vzctl2_release_snap_holder(struct vzctl_snap_holder *holder);
int vzctl2_env_switch_snapshot(struct vzctl_env_handle *h,
		struct vzctl_switch_snapshot_param *param);
int vzctl2_env_delete_snapshot(struct vzctl_env_handle *h, const char *guid);
int vzctl2_env_mount_snapshot(struct vzctl_env_handle *h, const char *mnt, const char *guid);
int vzctl2_env_umount_snapshot(struct vzctl_env_handle *h, const char *guid);
struct vzctl_snapshot_tree *vzctl2_open_snapshot_tree(const char *fname, int *err);
void vzctl2_close_snapshot_tree(struct vzctl_snapshot_tree *tree);
int vzctl2_find_snapshot_by_guid(struct vzctl_snapshot_tree *tree, const char *guid);


/*************** disk manipulation ******************************/
int vzctl2_mount_disk_image(const char *path, struct vzctl_mount_param *param);
int vzctl2_mount_image(const char *ve_private, struct vzctl_mount_param *param);
int vzctl2_umount_disk_image(const char *path);
int vzctl2_umount_image(const char *ve_private);
int vzctl2_create_disk_image(const char *path, struct vzctl_create_image_param *param);
int vzctl2_create_root_image(const char *ve_private, struct vzctl_create_image_param *param);
int vzctl2_create_image(const char *ve_private, struct vzctl_create_image_param *param);
int vzctl2_convert_image(const char *ve_private, int mode);
int vzctl2_resize_disk_image(const char *path, unsigned long long newsize, int offline);
int vzctl2_resize_image(const char *ve_private, unsigned long long newsize, int offline);
int vzctl2_env_resize_disk(struct vzctl_env_handle *h, const char *uuid,
		unsigned long size, int offline);
int vzctl2_env_encrypt_disk(struct vzctl_env_handle *h, const char *uuid,
		const char *keyid, int flags);

int vzctl2_env_get_disk_param(vzctl_disk_iterator it, struct vzctl_disk_param *out, int size);
vzctl_disk_iterator vzctl2_env_get_disk(struct vzctl_env_param *env, vzctl_disk_iterator it);
int vzctl2_env_add_disk(struct vzctl_env_handle *h, struct vzctl_disk_param *param, int flags);
int vzctl2_env_attach_disk(struct vzctl_env_handle *h, struct vzctl_disk_param *param);
int vzctl2_env_del_disk(struct vzctl_env_handle *h, const char *uuid, int flags);
int vzctl2_env_detach_disk(struct vzctl_env_handle *h, const char *guid);
int vzctl2_env_set_disk(struct vzctl_env_handle *h, struct vzctl_disk_param *param);
int vzctl2_get_disk_stats(const char *path, struct vzctl_disk_stats *stats,
		int size);
int vzctl2_env_get_disk_stats(struct vzctl_env_handle *h, const char *uuid,
	struct vzctl_disk_stats *stats, int size);
int vzctl2_get_disk_usage(const char *path, unsigned long long *out);
int vzctl2_get_ploop_dev(const char *path, char *dev, int len);
int vzctl2_get_ploop_dev_by_mnt(const char *mnt, char *out, int len);
int vzctl2_get_ploop_dev2(const char *path, char *dev, int dlen, char *part,
		int plen);
int vzctl2_get_top_image_fname(char *ve_private, char *out, int len);
int vzctl2_is_image_mounted(const char *path);
int vzctl2_get_mount_opts(const char *mnt_opts, int user_quota, char *out, int size);
int vzctl2_get_criu_arg(struct vzctl_env_handle *h, int op, char *out, int size);

/***************** CPT *********************************/
int vzctl2_env_remove_dump(struct vzctl_env_handle *h);
int vzctl2_env_chkpnt(struct vzctl_env_handle *h, int cmd, struct vzctl_cpt_param *param, int flags);
int vzctl2_env_restore(struct vzctl_env_handle *h, struct vzctl_cpt_param *param, int flags);

/**************** Exec *********************************/
/** Execute command inside CT.
 *
 * @param h             CT handle.
 * @param exec_mode     execution mode (MODE_EXEC, MODE_BASH).
 * @param arg           argv array.
 * @param envp          command environment array.
 * @param std_i         read command from buffer stdin point to.
 * @param timeout       execution timeout, 0 - unlimited.
 * @param flags
 * @return              0 on success.
 */
int vzctl2_env_exec(struct vzctl_env_handle *h, exec_mode_e exec_mode,
                char *const argv[], char *const envp[], char *std_in, int timeout, int flags);
/** Execute function inside VE.
 * All file descriptors are closed.
 *
 * @param h		CT handle.
 * @param fn            function pointer
 * @param data          function argument
 * @param timeout       execution timeout, 0 - unlimited.
 * @param flags
 * @return              0 on success.
 */
int vzctl2_env_exec_fn2(struct vzctl_env_handle *h, execFn fn, void *data, int timeout, int flags);
int vzctl2_env_exec_fn3(ctid_t ctid, execFn fn, void *data, int *data_fd, int flags);

/** Execute function inside VE in no wait mode.
 * Enter into VE and run user defined function. All file descriptiors
 * except of the data_fd are closed. User defined function executed in
 * separate process with SIGCHILD handler set to SIG_IGN (wait() not needed)).
 *
 * @param h		CT handle
 * @param fn		function pointer.
 * @param data		function argument.
 * @param data_fd	Array of file descriptors terminated by -1,
			these fds will not closed on VE enter.
 * @param timeout	execution timeout, 0 - unlimited.
 * @param flags
 * @param *err		error code.
 * @return		-1 on errr or process id.
 */
int vzctl2_env_exec_fn_async(struct vzctl_env_handle *h, execFn fn,
		void *data, int *data_fd, int timeout, int flags, int *err);
void vzctl2_release_exec_handle(struct vzctl_exec_handle *exec);
int vzctl2_env_execve(struct vzctl_env_handle *h, char *const argv[], char *const envp[],
                int stdfd[3], exec_mode_e mode, struct vzctl_exec_handle **exec);
struct termios;
struct winsize;
int vzctl2_env_exec_pty(struct vzctl_env_handle *h, char *const argv[], char *const envp[],
		int fds[2], struct termios *tios, struct winsize *ws,
		struct vzctl_exec_handle **exec);
int vzctl2_env_exec_wait(int pid, int *retcode);
void vzctl2_env_exec_terminate(struct vzctl_exec_handle *exec);
int vzctl2_env_exec_set_winsize(struct vzctl_exec_handle *exec,
		struct winsize *ws);

int vzctl2_env_waitpid(struct vzctl_exec_handle *exec, int nohang, int *status);
int vzctl2_env_enter(struct vzctl_env_handle *h);
int vzctl2_enter_mnt_ns(struct vzctl_env_handle *h);
int vzctl2_env_exec_action_script(struct vzctl_env_handle *h, const char *name,
		char *const env[], int timeout, int flags);

/*******************************************************/
int vzctl2_lock(const char *lockfile, int mode, unsigned int timeout);
void vzctl2_unlock(int fd, const char *lockfile);
int vzctl2_env_lock_prvt(const ctid_t ctid, const char *prvt, const char *status);
void vzctl2_env_unlock_prvt(const ctid_t ctid, int lckfd, const char *prvt);
int vzctl2_env_set_node(struct vzctl_env_handle *h, struct vzctl_nodemask *nodemask,
		struct vzctl_cpumask *cpumask);
unsigned long vzctl2_check_tech(unsigned long mask);
unsigned long long vzctl2_name2tech(const char *name);
const char *vzctl2_tech2name(unsigned long long id);
int vzctl2_fstype2layout(unsigned long fstype);
const char *vzctl2_layout2fstype(int layout);
int vzctl2_get_veformat(const char *ve_private);
int vzctl2_get_vzfs_ver(const char *ve_private);
const char *vzctl2_veformat2fs(int format);
char **vzctl2_get_storage(void);
int vzctl2_is_ve_private(const char *root);
char **vzctl2_scan_private(void);
int vzctl2_convertstr(const char *src, char *dst, int dst_size);
int vzctl2_is_env_name_valid(const char *name);
int vzctl2_is_networkid_valid(char const *name);
int vzctl2_parse_ctid(const char *in, ctid_t out);
void vzctl2_generate_ctid(ctid_t ctid);
int vzctl2_get_normalized_guid(const char *str, char *buf, int len);
int vzctl2_get_normalized_uuid(const char *str, char *buf, int len);
int vzctl2_set_tc_param(struct vzctl_env_handle *h, struct vzctl_env_param *env,
		int flags);
int vzctl2_env_set_setmode(struct vzctl_env_param *env, vzctl_setmode_t mode);
int vzctl2_env_set_cidata_fname(struct vzctl_env_param *env, const char *fname);
int vzctl2_set_limits(struct vzctl_env_handle *h, int release);
int vzctl2_get_def_ostemplate_name(char *out, int size);
int vzctl2_bitmap_parse(const char *str, unsigned long *maskp, int size);
int vzctl2_prepare_root_image(const char *dst, const char *ostemplate,
		struct vzctl_create_image_param *param);
const char *vzctl2_get_version();

/************** Depricated *****************************/
struct vzctl_config *vzctl2_conf_open(const char *fname, int flags, int *err);
int vzctl2_conf_get_param(const struct vzctl_config *conf, const char *name, const char **res);
int vzctl2_conf_set_param(struct vzctl_config *conf, const char *name, const char *str);
int vzctl2_conf_save(struct vzctl_config *conf, const char *fname);
void vzctl2_conf_close(struct vzctl_config *conf);
int vzctl2_create_env_private(const char *ve_private, int layout);
unsigned int vzctl2_get_flags(void);
void vzctl2_set_flags(unsigned int flags);
void vzctl2_register_running_state(const char *ve_private);
void vzctl2_unregister_running_state(const char *ve_private);
int vzctl2_env_set_ve_private_path(vzctl_env_param_ptr env, const char *path);
int vzctl2_env_set_ve_root_path(struct vzctl_env_param *env, const char *ve_root);
int vzctl2_get_vzctlfd(void);
int vzctl2_unescapestr_eq(char *src, char *dst, int size);
/* Compatibiity: mount root disk snapshot */
int vzctl2_mount_snapshot(struct vzctl_env_handle *h, struct vzctl_mount_param *param);
int vzctl2_env_create_tsnapshot(struct vzctl_env_handle *h, const char *guid,
		struct vzctl_tsnapshot_param *tsnap, struct vzctl_snap_holder *holder);
int vzctl2_env_compact(struct vzctl_env_handle *h,
		struct vzctl_compact_param *param, int size);
int vzctl2_console_start(struct vzctl_env_handle *h, struct vzctl_console *con);
VZ_DEPRECATED int vzctl2_set_vzlimits(const char *name);
#ifdef __cplusplus
}
#endif
#endif // _USE_DLOPEN_
#endif /* __VZCTL_H__ */
