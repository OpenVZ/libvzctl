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

#ifndef	_VZTYPES_H_
#define	_VZTYPES_H_

#define VZCTLDEV		"/dev/vzctl"
#define GLOBAL_CFG		VZ_DIR "vz.conf"
#define DIST_DIR		DISTCONFDIR
#define ENV_NAME_DIR		VZ_DIR "names/"
#define VZCTL_SCRIPT_DIR	SCRIPTDIR"/"
#define VZCTL_ENV_SAMPLE	VZ_ENV_CONF_DIR "ve-%s.conf-sample"

#define PROC_VZ			"/proc/vz"

#define DEF_DUMPDIR		"/vz/tmp"
#define DEF_DUMPFILE		"Dump.%s"

#define VZFIFO_FILE		"/.vzfifo"

#define LOCALE_UTF8		"UTF-8"

#define VZCTL_VE_CONF		"ve.conf"
#define VZCTL_VE_LAYOUT		".ve.layout"
#define VZCTL_VE_FS_DIR		"/fs"
#define VZCTL_VE_SCRIPTS_DIR	"/scripts"
#define VZCTL_VE_DUMP_DIR	"/dump"
#define VZCTL_VE_DUMP_FILE	"Dump"
#define VZCTL_VE_OWNER		".owner"
#define VZCTL_VE_ROOTHDD_DIR	"root.hdd"
#define VZCTL_VE_CLUSTER_SERVICE_NAME	".cluster_service_name"
#define VZCTL_VE_RUN_DIR	"/var/run/ve"

#define VZCTL_SCRIPT_D_DIR	SCRIPTDDIR"/"
#define VZCTL_START		"vz-start"
#define VZCTL_STOP		"vz-stop"
#define VZCTL_SETRATE		"vz-setrate"
#define VZCTL_CREATE_PRVT	"vz-create_prvt"
#define VZCTL_PCI_CONFIGURE	"vz-pci_configure"
#define VZCTL_NETNS_DEV_ADD	"vz-netns_dev_add"
#define VZCTL_NETNS_DEV_DEL	"vz-netns_dev_del"
#define VZCTL_ANNOUNCE_IPS	"vz-announce_ips"
#define VZCTL_REINSTALL_SCRIPT  "vps.reinstall"
#define VZCTL_CONFIGURE_SCRIPT  "vps.configure"

#define VZCTL_CUSTOM_SCRIPT_DIR	"/etc/vz/reinstall.d"

#define VZCTL_EXEC_WRAP_BIN	PKGLIBDIR "/exec_wrap"
#define VZCTL_ACTION_WRAP_BIN	PKGLIBDIR "/action_wrap"
#define VZCTL_START_PREFIX	"start"
#define VZCTL_STOP_PREFIX	"stop"
#define VZCTL_PRE_MOUNT_PREFIX	"premount"
#define VZCTL_MOUNT_PREFIX	"mount"
#define VZCTL_UMOUNT_PREFIX	"umount"
#define VZCTL_POST_UMOUNT_PREFIX	"postumount"

#define VZPKGINFO		"/usr/bin/vzpkginfo"
#define VZPKGADD		"/usr/sbin/vzpkgadd"
#define VZPKG			"/usr/sbin/vzpkg"

#define QUOTA_U			"/aquota.user"
#define QUOTA_G			"/aquota.group"

#define LIST_DELIMITERS		"\t ,"

#define BINDMOUNT_DIR		".bindmount"

#define VZCTL_VEID_MAX		2147483644

#define STR_SIZE	512
#define STR_MAX		4096
#define PATH_LEN	4096

#define VZCTL_ADD_PARAM	0
#define VZCTL_DEL_PARAM	1
#define VZCTL_DELALL	3

#define VZCTL_SCRIPT_EXEC_TIMEOUT	600

/* Default enviroment variable PATH */
#define	DEF_PATH	"/usr/local/sbin:/usr/local/bin:" \
			"/bin:/sbin:/usr/bin:/usr/sbin:"
#define	ENV_PATH	"PATH=" DEF_PATH

#define MAX_ARGS	255

#define ADD	0
#define DEL	1

#define STR_UNLIMITED	"unlimited"

#define SYSTEMD_CTID_FMT	"%s"
#define SYSTEMD_CTID_SCOPE_FMT	SYSTEMD_CTID_FMT

#define NETNS_RUN_DIR   "/var/run/netns"

#define VE_IP_ADD	1
#define VE_IP_DEL	2

#define VE_USE_MAJOR	010     /* Test MAJOR supplied in rule */
#define VE_USE_MINOR	030     /* Test MINOR supplied in rule */


/* VE states */
enum {
	VZCTL_STATE_STARTING = 1,
	VZCTL_STATE_RUNNING,
	VZCTL_STATE_STOPPED,
	VZCTL_STATE_STOPPING,
	VZCTL_STATE_RESTORING,
	VZCTL_STATE_CHECKPOINTING,
};

enum {
	VZCTL_IP_ADD_CMD,
	VZCTL_IP_DEL_CMD,
};

enum {
	VZCTL_ACTION_MOUNT,
	VZCTL_ACTION_UMOUNT,
	VZCTL_ACTION_PRE_MOUNT,
	VZCTL_ACTION_POST_UMOUNT,
};

enum {
	VZCTL_JQUOTA_MODE = 1,
	VZCTL_QUOTA_MODE,
};

enum {elf_none, elf_32, elf_64};

struct vzctl_env_handle;
struct start_param;
typedef int (*vzctl_env_create_FN)(struct vzctl_env_handle *h, struct start_param *param);

#endif /* _VZTYPES_H_ */
