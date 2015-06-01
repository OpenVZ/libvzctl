/*
 *  Copyright (C) 2000-2015 Parallels IP Holdings GmbH
 *
 * This file is part of OpenVZ. OpenVZ is free software; you can redistribute
 * it and/or modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * Our contact details: Parallels IP Holdings GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>

#include <libvzctl.h>
#include "logger.h"
#include "vzctl_param.h"
#include "vzerror.h"
#include "create.h"
#include "config.h"
#include "vz.h"
#include "env_config.h"
#include "image.h"
#include "exec.h"
#include "cpt.h"
#include "snapshot.h"

#include "vztypes.h"

#define P_OSTEMPLATE            0xffff00
#define P_PKGSET                0xffff01
#define P_PKGVER                0xffff02
#define P_FORCE			0xffff03
#define P_WAIT			0xffff04
#define P_SKIP_VE_SETUP		0xffff05
#define P_SAVE			0xffff07
#define P_RESETUB		0xffff08
#define P_CLASSID		0xffff10
#define P_BR_CPU_AVG_USAGE	0xffff0a
#define P_BR_CPULIMIT		0xffff0b
#define P_SKIP_ARPDETECT	0xffff0c
#define P_OLD_LAYOUT		0xffff0d
#define P_NEW_LAYOUT		0xffff0e
#define P_SNAPSHOT_GUID		0xffff0f
#define P_TARGET		0xffff10


typedef int (*action)(unsigned int id, int argc, char **argv, int flags);
struct cmd_struct {
	const char *cmd;
	action f;
};

#define ST_CREATE		"creating"
#define ST_DESTROY		"destroying"
#define ST_MOUNT		"mounting"
#define ST_UMOUNT		"unmounting"
#define ST_START		"starting"
#define ST_SET			"setting"
#define ST_STOP			"stopping"
#define ST_RESTART		"restarting"
#define ST_QUOTA_INIT		"initializing-quota"
#define ST_RECOVER		"recovering"
#define ST_REINSTALL		"reinstalling"
#define ST_RESUME		"resuming"
#define ST_RESTORE		"restoring"
#define ST_UPDATING		"updating"
#define ST_SUSPEND		"suspending"

char *_proc_title;
int _proc_title_len;

void version()
{
	fprintf(stdout, "vzctl version " "\n");
}

void usage()
{
	version();
	fprintf(stdout, "Copyright (C) 2000-2008 Parallels.\n");
	fprintf(stdout, "This program may be distributed under the terms of the GNU GPL License.\n\n");
	fprintf(stdout, "Usage: vzctl [options] <command> <veid> [parameters]\n"
"vzctl destroy | mount | umount | stop | status | enter <veid>\n"
"vzctl create <veid> {--ostemplate <name>] [--config <name>]\n"
"   [--private <path>] [--root <path>] [--ipadd <addr>] | [--hostname <name>]\n"
"vzctl start <veid> [--force] [--wait]\n"
"vzctl exec | exec2 <veid> <command> [arg ...]\n"
"vzctl runscript <veid> <script>\n"
"vzctl chkpnt <veid> [--dumpfile <name>]\n"
"vzctl restore <veid> [--dumpfile <name>]\n"
"vzctl set <veid> [--save] [--setmode restart|ignore]\n"
"   [--ipadd <addr>] [--ipdel <addr>|all] [--hostname <name>]\n"
"   [--nameserver <addr>] [--searchdomain <name>] [--onboot yes|no]\n"
"   [--userpasswd <user>:<passwd>] [--cpuunits <N>] [--cpulimit <N>] [--cpus <N>]\n"
"   [--diskspace <soft>[:<hard>]] [--diskinodes <soft>[:<hard>]]\n"
"   [--quotatime <N>] [--quotaugidlimit <N>]\n"
"   [--noatime yes|no] [--capability <name>:on|off ...]\n"
"   [--devices b|c:major:minor|all:r|w|rw]\n"
"   [--devnodes device:r|w|rw|none]\n"
"   [--netif_add <ifname[,mac,host_ifname,host_mac]]>] [--netif_del <ifname>]\n"
"   [--applyconfig <name>] [--applyconfig_map <name>]\n"
"   [--features <name:on|off>] [--name <vename>]\n"
"   [--ioprio <N>]\n");


	fprintf(stdout, "   [--iptables <name>] [--disabled <yes|no>]\n");
	fprintf(stdout, "   [UBC parameters]\n"
"UBC parameters (N - items, P - pages, B - bytes):\n"
"Two numbers divided by colon means barrier:limit.\n"
"In case the limit is not given it is set to the same value as the barrier.\n"
"   --numproc N[:N]	--numtcpsock N[:N]	--numothersock N[:N]\n"
"   --vmguarpages P[:P]	--kmemsize B[:B]	--tcpsndbuf B[:B]\n"
"   --tcprcvbuf B[:B]	--othersockbuf B[:B]	--dgramrcvbuf B[:B]\n"
"   --oomguarpages P[:P]	--lockedpages P[:P]	--privvmpages P[:P]\n"
"   --shmpages P[:P]	--numfile N[:N]		--numflock N[:N]\n"
"   --numpty N[:N]	--numsiginfo N[:N]	--dcachesize N[:N]\n"
"   --numiptent N[:N]	--physpages P[:P]	--avnumproc N[:N]\n");
}


static int yesno2id(const char *str)
{
	if (str == NULL)
		return -1;
	if (!strcmp(str, "yes"))
		return VZCTL_PARAM_ON;
	else if (!strcmp(str, "no"))
		return VZCTL_PARAM_OFF;
	return -1;
}

static int parse_int(const char *str, int *val)
{
	char *tail;

	errno = 0;
	*val = (int)strtol(str, (char **)&tail, 10);
	if (*tail != '\0' || errno == ERANGE)
		return 1;
	return 0;
}

static int check_argv_tail(int argc, char **argv)
{
	if (optind < argc) {
		printf("non-option ARGV-elements: ");
		while (optind < argc)
			printf ("%s ", argv[optind++]);
		printf("\n");
		return VZCTL_E_INVAL_PARAMETER_SYNTAX;
	}
	return 0;
}

static int parse_create_opt(struct vzctl_env_param *param, int argc,
		char **argv)
{
	int ret, c;
	struct option options[] = {
		{"ostemplate",  required_argument, NULL, VZCTL_PARAM_OSTEMPLATE},
		{"pkgver",      required_argument, NULL, P_PKGVER},
		{"pkgset",      required_argument, NULL, P_PKGSET},
		{"config",      required_argument, NULL, VZCTL_PARAM_CONFIG},
		{"private",     required_argument, NULL, VZCTL_PARAM_VE_PRIVATE},
		{"root",        required_argument, NULL, VZCTL_PARAM_VE_ROOT},
		{"ipadd",       required_argument, NULL, VZCTL_PARAM_IP_ADDRESS},
		{"hostname",    required_argument, NULL, VZCTL_PARAM_HOSTNAME},
		{"name",	required_argument, NULL, VZCTL_PARAM_NAME},
		{"description",	required_argument, NULL, VZCTL_PARAM_DESCRIPTION},

		{"old_layout", no_argument, NULL, P_OLD_LAYOUT},
		{"new_layout", no_argument, NULL, P_NEW_LAYOUT},
		{ NULL, 0, NULL, 0 }
	};

	while (1) {
		int option_index = -1;

		c = getopt_long(argc, argv, "", options, &option_index);
		if (c == -1)
			break;
		if (c == '?')
			return VZCTL_E_INVAL;
		switch (c) {
		case P_PKGSET:
		case P_PKGVER:
			continue;
		}

		if ((ret = vzctl2_add_env_param_by_id(param, c, optarg))) {
			if (option_index < 0)
				vzctl2_log(-1, 0, "Bad parameter for -%c: %s",
					c, optarg);
			else
				vzctl2_log(-1, 0, "Bad parameter for --%s: %s",
					options[option_index].name, optarg);
			return ret;
		}

	}
	if (optind < argc) {
		printf ("non-option ARGV-elements: ");
		while (optind < argc)
			printf ("%s ", argv[optind++]);
		printf ("\n");
		return VZCTL_E_INVAL;
	}
	return 0;
}

static int create(unsigned id, int argc, char **argv, int flags)
{
	int ret = -1;
	struct vzctl_env_param *param = NULL;

	if ((param = vzctl2_alloc_env_param(id)) == NULL)
                return VZCTL_E_NOMEM;

	if ((ret = parse_create_opt(param, argc, argv)))
		return ret;

//	ret = vzctl_env_create(id, param, flags);

	vzctl2_free_env_param(param);

	return ret;
}

static int destroy(unsigned int id, int argc, char **argv, int flags)
{
	int ret;
	struct vzctl_env_handle *h;

	if (!(h = vzctl2_env_open(id, flags, &ret)))
		return ret;
	ret = vzctl2_env_destroy(h, flags);
	vzctl2_env_close(h);

	return ret;
}

static int parse_start_opt(int argc, char **argv, int *flags)
{
	int ret, c;
	struct option options[] = {
		{"force",	no_argument, NULL, P_FORCE},
		{"skip_ve_setup",no_argument, NULL, P_SKIP_VE_SETUP},
		{"wait",	no_argument, NULL, P_WAIT},
		{ NULL, 0, NULL, 0 }

	};

	while (1) {
		int option_index = -1;

		c = getopt_long(argc, argv, "", options, &option_index);
		if (c == -1)
			break;
		if (c == '?')
			return VZCTL_E_INVAL;
		switch (c) {
		case P_FORCE:
			*flags |= VZCTL_FORCE;
			break;
		case P_WAIT:
			*flags |= VZCTL_WAIT;
			break;
		case P_SKIP_VE_SETUP:
			*flags |= VZCTL_SKIP_SETUP;
			break;
		}

	}
	ret = check_argv_tail(argc, argv);
	return ret;
}

static int start(unsigned int id, int argc, char **argv, int flags)
{
	int ret;
	struct vzctl_env_handle *h;

	if ((ret = parse_start_opt(argc, argv, &flags)))
		return ret;
	if (!(h = vzctl2_env_open(id, flags, &ret)))
		return ret;
	ret = vzctl2_env_start(h, flags);
	vzctl2_env_close(h);

	return ret;
}

static int parse_stop_opt(int argc, char **argv, int *flags)
{
	int ret, c;
	struct option options[] = {
		{"fast",	no_argument, NULL, VZCTL_PARAM_FAST},
		{ NULL, 0, NULL, 0 }

	};

	while (1) {
		int option_index = -1;

		c = getopt_long(argc, argv, "", options, &option_index);
		if (c == -1)
			break;
		if (c == '?')
			return VZCTL_E_INVAL;
		switch (c) {
		case VZCTL_PARAM_FAST:
			*flags |= VZCTL_FAST;
			break;
		}
	}
	ret = check_argv_tail(argc, argv);
	return ret;
}

static int stop(unsigned id, int argc, char **argv, int flags)
{
	int ret;
	struct vzctl_env_handle *h;

	if ((ret = parse_stop_opt(argc, argv, &flags)))
		return ret;
	if (!(h = vzctl2_env_open(id, flags, &ret)))
		return ret;
	ret = vzctl2_env_stop(h, flags & VZCTL_FAST ? M_KILL: M_HALT, flags);
	vzctl2_env_close(h);

	return ret;
}

static int parse_mount_opt(int argc, char **argv, struct vzctl_mount_param *param)
{
	int ret, c;
	struct option options[] = {
		{"uuid", required_argument, NULL, 'u'},
		{ NULL, 0, NULL, 0 }
	};

	while (1) {
		int option_index = -1;

		c = getopt_long(argc, argv, "u:rPm:", options, &option_index);
		if (c == -1)
			break;
		if (c == '?')
			return VZCTL_E_INVAL;
		switch (c) {
		case 'u':
			param->guid = optarg;
			break;
		case 'r':
			param->ro = 1;
			break;
		case 'P':
			param->mount_by_parent_guid = 1;
			break;
		case 'm':
			param->target = optarg;
			break;
		}
	}
	ret = check_argv_tail(argc, argv);
	return ret;
}

static int mount(unsigned id, int argc, char **argv, int flags)
{
	int ret;
	struct vzctl_env_handle *h;
	struct vzctl_mount_param param = {};

	if (!(h = vzctl2_env_open(id, flags, &ret)))
		return ret;
	if ((ret = parse_mount_opt(argc, argv, &param)))
		return ret;

	ret = vzctl2_env_mount(h, 0);
	vzctl2_env_close(h);

	return ret;
}

static int umount(unsigned id, int argc, char **argv, int flags)
{
	int ret;
	struct vzctl_env_handle *h;

	if (!(h = vzctl2_env_open(id, flags, &ret)))
		return ret;
	ret = vzctl2_env_umount(h, flags);
	vzctl2_env_close(h);

	return ret;
}

static int parse_snapshot_opt(int argc, char **argv,char **guid)
{
	int ret, c;
	struct option options[] = {
		{"uuid", required_argument, NULL, 'u'},
			{"id", required_argument, NULL, 'u'},
		{ NULL, 0, NULL, 0 }
	};

	while (1) {
		int option_index = -1;

		c = getopt_long(argc, argv, "u:rPm:", options, &option_index);
		if (c == -1)
			break;
		if (c == '?')
			return VZCTL_E_INVAL;
		switch (c) {
		case 'u':
			*guid = optarg;
			break;
		}
	}
	ret = check_argv_tail(argc, argv);
	return ret;
}

static int snapshot(unsigned id, int argc, char **argv, int flags)
{
	int ret;
	struct vzctl_env_handle *h;
	struct vzctl_snapshot_param param = {};

	if (!(h = vzctl2_env_open(id, flags, &ret)))
		return ret;

	ret = vzctl2_env_create_snapshot(h, &param);
	vzctl2_env_close(h);

	return ret;
}

static int snapshot_switch(unsigned id, int argc, char **argv, int flags)
{
	int ret;
	struct vzctl_env_handle *h;
	struct vzctl_switch_snapshot_param param = {};

	if ((ret = parse_snapshot_opt(argc, argv, &param->guid)))
		return ret;

	if (!(h = vzctl2_env_open(id, flags, &ret)))
		return ret;

	ret = vzctl2_env_switch_snapshot(h, &param);
	vzctl2_env_close(h);

	return ret;
}

static int snapshot_delete(unsigned id, int argc, char **argv, int flags)
{
	int ret;
	struct vzctl_env_handle *h;
	const char *guid = NULL;

	if ((ret = parse_snapshot_opt(argc, argv, &guid)))
		return ret;

	if (!(h = vzctl2_env_open(id, flags, &ret)))
		return ret;

	ret = vzctl2_env_delete_snapshot(h, guid);
	vzctl2_env_close(h);

	return ret;
}

static int parse_snapshot_mount_opt(int argc, char **argv, struct vzctl_mount_param *param)
{
	int ret, c;
	struct option options[] = {
		{"id",  required_argument, NULL, P_SNAPSHOT_GUID},
			{"uuid", required_argument, NULL, P_SNAPSHOT_GUID},
		{"target", required_argument, NULL, P_TARGET},
		{ NULL, 0, NULL, 0 }
	};

	while (1) {
		int option_index = -1;

		c = getopt_long(argc, argv, "", options, &option_index);
		if (c == -1)
			break;
		if (c == '?')
			return VZCTL_E_INVAL;
		switch (c) {
		case P_SNAPSHOT_GUID:
			param->guid = optarg;
			break;
		case P_TARGET:
			param->target = optarg;
			break;
		}
	}
	ret = check_argv_tail(argc, argv);
	return ret;
}

static int snapshot_mount(unsigned id, int argc, char **argv, int flags)
{
	int ret;
	struct vzctl_env_handle *h;
	struct vzctl_mount_param param = {};

	if ((ret = parse_snapshot_mount_opt(argc, argv, &param)))
		return ret;

	if (!(h = vzctl2_env_open(id, flags, &ret)))
		return ret;
	ret = vzctl2_env_mount_snapshot(h, param.target, param.guid);
	vzctl2_env_close(h);

	return ret;
}

static int parse_snapshot_umount_opt(int argc, char **argv, const char **guid)
{
	int ret, c;
	struct option options[] = {
		{"id",  required_argument, NULL, P_SNAPSHOT_GUID},
			{"uuid", required_argument, NULL, P_SNAPSHOT_GUID},
		{ NULL, 0, NULL, 0 }
	};

	while (1) {
		int option_index = -1;

		c = getopt_long(argc, argv, "", options, &option_index);
		if (c == -1)
			break;
		if (c == '?')
			return VZCTL_E_INVAL;
		switch (c) {
		case P_SNAPSHOT_GUID:
			*guid = optarg;
			break;
		}
	}
	ret = check_argv_tail(argc, argv);
	return ret;
}

static int snapshot_umount(unsigned id, int argc, char **argv, int flags)
{
	int ret;
	struct vzctl_env_handle *h;
	const char *guid;

	if ((ret = parse_snapshot_umount_opt(argc, argv, &guid)))
		return ret;

	if (!(h = vzctl2_env_open(id, flags, &ret)))
		return ret;

	ret = vzctl2_env_umount_snapshot(h, guid);
	vzctl2_env_close(h);

	return ret;
}

static int runscript(unsigned id, int argc, char **argv, int flags)
{
	int ret;
	struct vzctl_env_handle *h;

	if (argc != 2) {
		vzctl2_log(-1, 0, "Invalid number of arguments");
		return -1;
	}
	if (!(h = vzctl2_env_open(id, flags, &ret)))
		return ret;

	ret = vzctl2_wrap_env_exec_script(id, h->env_param->fs->ve_root, NULL, NULL, argv[1], 0, 0);
	vzctl2_env_close(h);

	return ret;
}

static int exec(unsigned id, int argc, char **argv, int flags)
{
	int ret;
	struct vzctl_env_handle *h;

	if (argc < 2) {
		vzctl2_log(-1, 0, "Invalid number of arguments");
		return -1;
	}
	argv++; argc--;
	if (!(h = vzctl2_env_open(id, flags, &ret)))
		return ret;

	ret = vzctl2_env_exec(h, MODE_EXEC, argv, NULL, NULL, 0, 0);
	vzctl2_env_close(h);

	return ret;
}

static int enter(unsigned id, int argc, char **argv, int flags)
{
	int ret;
	struct vzctl_env_handle *h;

	h = vzctl2_env_open(id, flags, &ret);
	if (h == NULL)
		return ret;

	ret = vzctl2_env_enter(h);

	vzctl2_env_close(h);

	return ret;
}

static int find_arg(char **arg, const char *str)
{
	char **p;

	for (p = arg; *p != NULL; p++)
		if (!strcmp(*p, str))
			return 1;
	return 0;
}

static int parse_set_opt(struct vzctl_env_param *env,
		int argc, char **argv, int *flags)
{
	int ret, c;
	struct option options[] = {
		/* Flags */
		{"save",	no_argument, NULL, P_SAVE},
		{"reset_ub",	no_argument, NULL, P_RESETUB},
		{"onboot",	required_argument, NULL, VZCTL_PARAM_ONBOOT},

		{"root",        required_argument, NULL, VZCTL_PARAM_VE_ROOT},
		{"private",	required_argument, NULL, VZCTL_PARAM_VE_PRIVATE},
		/* License */
		{"classid",	required_argument, NULL, P_CLASSID},
		/* Network */
		{"ipadd",	required_argument, NULL, VZCTL_PARAM_IP_ADDRESS},
		{"ip",		required_argument, NULL, VZCTL_PARAM_IP_ADDRESS},
		{"ipdel",	required_argument, NULL, VZCTL_PARAM_IPDEL},
		{"skip_arpdetect",no_argument, NULL, P_SKIP_ARPDETECT},
		/* Disk quota parameters */
		{"diskspace",	required_argument, NULL, VZCTL_PARAM_DISKSPACE},
		{"diskinodes",	required_argument, NULL, VZCTL_PARAM_DISKINODES},
		{"quotatime",	required_argument, NULL, VZCTL_PARAM_QUOTATIME},
		{"quotaugidlimit",required_argument,NULL,VZCTL_PARAM_QUOTAUGIDLIMIT},
		{"journalled_quota",    required_argument, NULL, VZCTL_PARAM_JOURNALED_QUOTA},
			{"jquota",      required_argument, NULL, VZCTL_PARAM_JOURNALED_QUOTA},

		/* SLM */
		{"slmmemorylimit",required_argument,NULL, VZCTL_PARAM_SLMMEMORYLIMIT},
		{"slmmode",	required_argument,NULL,	VZCTL_PARAM_SLMMODE},
		/* Host parameters */
		{"nameserver",	required_argument, NULL, VZCTL_PARAM_NAMESERVER},
		{"searchdomain",required_argument, NULL, VZCTL_PARAM_SEARCHDOMAIN},
		{"hostname",	required_argument, NULL, VZCTL_PARAM_HOSTNAME},
#if 0
		{"description",	required_argument, NULL, VZCTL_PARAM_DESCRIPTION},
		{"name",	required_argument, NULL, VZCTL_PARAM_NAME},
		{"userpasswd",	required_argument, NULL, VZCTL_PARAM_USERPW},
		/* Mount */
		{"noatime",	required_argument, NULL, VZCTL_PARAM_NOATIME},
#endif
		/* Shaping */
		{"rate",	required_argument, NULL, VZCTL_PARAM_RATE},
		{"ratebound",	required_argument, NULL, VZCTL_PARAM_RATEBOUND},
		/* User beancounter parameters */
		{"kmemsize",	required_argument, NULL, VZCTL_PARAM_KMEMSIZE},
		{"lockedpages",	required_argument, NULL, VZCTL_PARAM_LOCKEDPAGES},
		{"privvmpages",	required_argument, NULL, VZCTL_PARAM_PRIVVMPAGES},
		{"shmpages",	required_argument, NULL, VZCTL_PARAM_SHMPAGES},
		{"numproc",	required_argument, NULL, VZCTL_PARAM_NUMPROC},
		{"physpages",	required_argument, NULL, VZCTL_PARAM_PHYSPAGES},
		{"vmguarpages",	required_argument, NULL, VZCTL_PARAM_VMGUARPAGES},
		{"oomguarpages",required_argument, NULL, VZCTL_PARAM_OOMGUARPAGES},
		{"numtcpsock",	required_argument, NULL, VZCTL_PARAM_NUMTCPSOCK},
		{"numflock",	required_argument, NULL, VZCTL_PARAM_NUMFLOCK},
		{"numpty",	required_argument, NULL, VZCTL_PARAM_NUMPTY},
		{"numsiginfo",	required_argument, NULL, VZCTL_PARAM_NUMSIGINFO},
		{"tcpsndbuf",	required_argument, NULL, VZCTL_PARAM_TCPSNDBUF},
			{"tcpsendbuf",	required_argument, NULL, VZCTL_PARAM_TCPSNDBUF},
		{"tcprcvbuf",	required_argument, NULL, VZCTL_PARAM_TCPRCVBUF},
		{"othersockbuf",required_argument, NULL, VZCTL_PARAM_OTHERSOCKBUF},
		{"dgramrcvbuf",	required_argument, NULL, VZCTL_PARAM_DGRAMRCVBUF},
		{"numothersock",required_argument, NULL, VZCTL_PARAM_NUMOTHERSOCK},
		{"numfile",	required_argument, NULL, VZCTL_PARAM_NUMFILE},
		{"dcachesize",	required_argument, NULL, VZCTL_PARAM_DCACHESIZE},
			{"dcache", required_argument, NULL, VZCTL_PARAM_DCACHESIZE},
		{"numiptent",	required_argument, NULL, VZCTL_PARAM_NUMIPTENT},
			{"iptentries", required_argument, NULL, VZCTL_PARAM_NUMIPTENT},
		{"avnumproc",	required_argument, NULL, VZCTL_PARAM_AVNUMPROC},
		{"swappages",	required_argument, NULL, VZCTL_PARAM_SWAPPAGES},
		{"vm_overcommit",	required_argument, NULL, VZCTL_PARAM_VM_OVERCOMMIT},
#if 0
		/* old UBC */
		{"totvmpages",	required_argument, NULL, VZCTL_PARAM_TOTVMPAGES},
		{"ipcshmpages",	required_argument, NULL, VZCTL_PARAM_IPCSHMPAGES},
		{"anonshpages", required_argument, NULL, VZCTL_PARAM_ANONSHPAGES},
		{"rsspages",	required_argument, NULL, VZCTL_PARAM_RSSPAGES},
		{"oomguar",	required_argument, NULL, VZCTL_PARAM_OOMGUAR},
		{"numsock",	required_argument, NULL, VZCTL_PARAM_NUMSOCK},
		{"unixsockbuf",	required_argument, NULL, VZCTL_PARAM_UNIXSOCKBUF},
		{"sockrcvbuf",	required_argument, NULL, VZCTL_PARAM_SOCKRCVBUF},
		{"numunixsock",	required_argument, NULL, VZCTL_PARAM_NUMUNIXSOCK},
#endif
		/* CPU */
		{"cpuweight",	required_argument, NULL, VZCTL_PARAM_CPUWEIGHT},
		{"cpulimit",	required_argument, NULL, VZCTL_PARAM_CPULIMIT},
		{"cpuunits",	required_argument, NULL, VZCTL_PARAM_CPUUNITS},
		{"burst_cpu_avg_usage",	required_argument, NULL, VZCTL_PARAM_BURST_CPU_AVG_USAGE},
		{"burst_cpulimit", required_argument, NULL, VZCTL_PARAM_BURST_CPULIMIT},
		/* Capability */
		{"capability",	required_argument, NULL, VZCTL_PARAM_CAP},
		/* Devices */
		{"devices",	required_argument, NULL, VZCTL_PARAM_DEVICES},
		{"devnodes",	required_argument, NULL, VZCTL_PARAM_DEVNODES},

#if 0
		{"applyconfig", required_argument, NULL, VZCTL_PARAM_APPCONF},
		{"applyconfig_map", required_argument, NULL, VZCTL_PARAM_APPCONF_MAP},
		{"config_customized", required_argument, NULL, VZCTL_PARAM_CONFIG_CUSTOMIZE},
		{"origin_sample", required_argument, NULL, VZCTL_PARAM_CONFIG_SAMPLE},
#endif
		/* Iptablae */
		{"iptables",	required_argument, NULL, VZCTL_PARAM_IPTABLES},
		{"netdev_add",	required_argument, NULL, VZCTL_PARAM_NETDEV},
		{"netdev_del",	required_argument, NULL, VZCTL_PARAM_NETDEV_DEL},


		{"setmode",	required_argument, NULL, VZCTL_PARAM_SETMODE},
#if 0
		{"disabled",	required_argument, NULL, VZCTL_PARAM_DISABLED},
		/*	bindmount	*/
		{"bindmount_add",required_argument, NULL, VZCTL_PARAM_BINDMOUNT_ADD},
		{"bindmount_del",required_argument, NULL, VZCTL_PARAM_BINDMOUNT_DEL},

#endif

		{"meminfo",	required_argument, NULL, VZCTL_PARAM_MEMINFO},
		/* VETH */
		{"netif_add",	required_argument, NULL, VZCTL_PARAM_NETIF_ADD},
		{"netif_del",	required_argument, NULL, VZCTL_PARAM_NETIF_DEL},
//		{"netif_mac_renew",no_argument, NULL, VZCTL_PARAM_NETIF_MAC_RENEW},
		{"ifname",	required_argument, NULL, VZCTL_PARAM_NETIF_IFNAME},
		{"mac",		required_argument, NULL, VZCTL_PARAM_NETIF_MAC},
		{"host_mac",	required_argument, NULL, VZCTL_PARAM_NETIF_HOST_MAC},
		{"host_ifname",	required_argument, NULL, VZCTL_PARAM_NETIF_HOST_IFNAME},
		{"gateway",	required_argument, NULL, VZCTL_PARAM_NETIF_GW},
			{"gw",		required_argument, NULL, VZCTL_PARAM_NETIF_GW},
		{"gateway6",	required_argument, NULL, VZCTL_PARAM_NETIF_GW6},
			{"gw6",		required_argument, NULL, VZCTL_PARAM_NETIF_GW6},
		{"network",	required_argument, NULL, VZCTL_PARAM_NETIF_NETWORK},
		{"dhcp",	required_argument, NULL, VZCTL_PARAM_NETIF_DHCP},
		{"dhcp6",	required_argument, NULL, VZCTL_PARAM_NETIF_DHCP6},
		{"mac_filter",	required_argument, NULL, VZCTL_PARAM_NETIF_MAC_FILTER},

		{"features",	required_argument, NULL, VZCTL_PARAM_FEATURES},
		/* ioprio */
		{"ioprio",	required_argument, NULL, VZCTL_PARAM_IOPRIO},

		{ NULL, 0, NULL, 0 }
	};
	struct vzctl_veth_dev_param veth_param;
	struct vzctl_veth_dev *veth = NULL;
	int ifname = 0;


	ifname = find_arg(argv, "--ifname");
	bzero(&veth_param, sizeof(veth_param));

	if (ifname)
		veth = vzctl2_create_veth_dev(NULL, 0);
	while (1) {
		int option_index = -1;

		c = getopt_long(argc, argv, "", options, &option_index);
		if (c == -1)
			break;
		if (c == '?')
			return VZCTL_E_INVAL;
		switch (c) {
		case VZCTL_PARAM_SETMODE:
			if (!strcmp("restart", optarg))
				env->opts->setmode = VZCTL_SET_RESTART;
			else if (!!strcmp("ignore", optarg))
				env->opts->setmode = VZCTL_SET_IGNORE;
			else {
				fprintf(stderr, "invalid arg for --setmode\n");
				return VZCTL_E_INVAL;
			}
			continue;
		case P_SAVE:
			*flags |= VZCTL_SAVE;
			continue;
		case P_SKIP_ARPDETECT:
			*flags |= VZCTL_SKIP_ARPDETECT;
			continue;
		case VZCTL_PARAM_IP_ADDRESS:
			if (veth != NULL)
				vzctl2_env_add_veth_ipaddress(veth, optarg);
			else
				vzctl2_env_add_ipaddress(env, optarg);
			continue;
		case VZCTL_PARAM_IPDEL:
			if (veth != NULL) {
				if (!strcmp(optarg, "all"))
					veth_param.ip_apply_mode = 1;
				else
					vzctl2_env_del_veth_ipaddress(veth, optarg);
			} else
				vzctl2_env_del_ipaddress(env, optarg);
			continue;
		case VZCTL_PARAM_NETIF_DHCP:
			if ((veth_param.dhcp = yesno2id(optarg)) == -1) {
				fprintf(stderr, "invalid arg for --dhcp\n");
				return VZCTL_E_INVAL;
			}
			continue;
		case VZCTL_PARAM_NETIF_DHCP6:
			if ((veth_param.dhcp6 = yesno2id(optarg)) == -1) {
				fprintf(stderr, "invalid arg for --dhcp6\n");
				return VZCTL_E_INVAL;
			}
			continue;
		case VZCTL_PARAM_NETIF_NETWORK:
			veth_param.network = strdup(optarg);
			continue;
		case VZCTL_PARAM_NETIF_ADD:
			if (veth == NULL) {
				veth = vzctl2_create_veth_dev(NULL, 0);
				veth_param.dev_name_ve = strdup(optarg);
			}
			continue;
		case VZCTL_PARAM_NETIF_GW:
			veth_param.gw = strdup(optarg);
			continue;
		case VZCTL_PARAM_NETIF_GW6:
			veth_param.gw6 = strdup(optarg);
			continue;
		case VZCTL_PARAM_NETIF_IFNAME:
			veth_param.dev_name_ve = strdup(optarg);
			continue;
		case VZCTL_PARAM_NETIF_DEL:
			vzctl2_env_del_veth(env, optarg);
			continue;
		default:
			break;
		}

		if ((ret = vzctl2_add_env_param_by_id(env, c, optarg))) {
			if (option_index < 0)
				vzctl2_log(-1, 0, "Bad parameter for -%c: %s",
					c, optarg);
			else
				vzctl2_log(-1, 0, "Bad parameter for --%s: %s",
					options[option_index].name, optarg);
			return ret;
		}
	}
	if (veth != NULL) {
		vzctl2_env_set_veth_param(veth, &veth_param, sizeof(veth_param));
		vzctl2_env_add_veth(env, veth);
	}
	ret = check_argv_tail(argc, argv);
	return ret;
}

static int set(unsigned id, int argc, char **argv, int flags)
{
	int ret;
	struct vzctl_env_handle *h = NULL;
	struct vzctl_env_param *param = NULL;

	if ((param = vzctl2_alloc_env_param(id)) == NULL)
                return VZCTL_E_NOMEM;

	if ((h = vzctl2_env_open(id, flags, &ret)) == NULL)
		goto err;
	if ((ret = parse_set_opt(param, argc, argv,  &flags)))
		goto err;
	ret = vzctl2_apply_param(h, param, flags);

err:
	vzctl2_env_close(h);
	vzctl2_free_env_param(param);

	return ret;
}

static int parse_register_opt(int argc, char **argv, int *flags)
{
	int ret, c;
	struct option options[] = {
		{"skip_cluster", no_argument, NULL, VZCTL_PARAM_SKIP_CLUSTER},
		{"force",       no_argument, NULL, VZCTL_PARAM_FORCE},
		{"renew",       no_argument, NULL, VZCTL_PARAM_RENEW},
		{"start",       no_argument, NULL, VZCTL_PARAM_REG_START},
		{ NULL, 0, NULL, 0 }
	};

	while (1) {
		int option_index = -1;

		c = getopt_long(argc, argv, "", options, &option_index);
		if (c == -1)
			break;
		if (c == '?')
			return VZCTL_E_INVAL;
		switch (c) {
		case VZCTL_PARAM_SKIP_CLUSTER :
			*flags |= VZ_REG_SKIP_CLUSTER;
			break;
		case VZCTL_PARAM_FORCE        :
			*flags |= VZ_REG_FORCE;
			break;
		case VZCTL_PARAM_RENEW        :
			*flags |= VZ_REG_RENEW;
			break;
		case VZCTL_PARAM_REG_START:
			*flags |= VZ_REG_START;
			break;
		}
        }
	ret = check_argv_tail(argc, argv);
	return ret;
}

static int env_register(int argc, char **argv, int flags)
{
	int ret;
	unsigned id;
	char *ve_private;

	if (argc < 2) {
		fprintf(stderr, "Usage: vzctl register <path> <ctid>\n");
		return VZCTL_E_INVAL;
	}

	ve_private = argv[0];
	if (parse_int(argv[1], &id)) {
		fprintf(stderr, "Invalid VE ID %s\n", *argv);
		return VZCTL_E_INVAL;
	}

	argv++; argc--;

	ret = parse_register_opt(argc, argv, &flags);
	if (ret)
		return ret;

	return vzctl2_env_register(ve_private, id, flags);
}

static int parse_cpt_opt(struct option *options, int argc, char **argv, struct vzctl_cpt_param *param)
{
	int ret, c;

	while (1) {
		int option_index = -1;

		c = getopt_long(argc, argv, "", options, &option_index);
		if (c == -1)
			break;
		if (c == '?')
			return VZCTL_E_INVAL;
		switch (c){
		case VZCTL_PARAM_DUMPFILE     :
			param->dumpfile = strdup(optarg);
			break;
		case VZCTL_PARAM_CPTCONTEXT   :
			param->ctx = strtoul(optarg, NULL, 16);
			break;
		case VZCTL_PARAM_CPU_FLAGS    :
			param->cpu_flags = strtoul(optarg, NULL, 0);
			break;
		case VZCTL_PARAM_KILL:
			param->cmd = VZCTL_CMD_KILL;
			break;
		case VZCTL_PARAM_UNDUMP:
			param->cmd = VZCTL_CMD_UNDUMP;
			break;
		case VZCTL_PARAM_DUMP:
			param->cmd = VZCTL_CMD_DUMP;
			break;
		case VZCTL_PARAM_RESUME:
			param->cmd = VZCTL_CMD_RESUME;
			break;
		case VZCTL_PARAM_SUSPEND:
			param->cmd = VZCTL_CMD_SUSPEND;
			break;
		case VZCTL_PARAM_SKIP_ARPDETECT:
			param->flags = VZCTL_SKIP_ARPDETECT;
			break;
		case VZCTL_PARAM_KEEP_PAGES:
			param->flags = VZCTL_CPT_KEEP_PAGES;
			break;
		case VZCTL_PARAM_UNFREEZE:
			param->flags = VZCTL_CPT_UNFREEZE_ON_DUMP;
			break;
		default         :
			ret = VZCTL_E_INVAL;
			break;
		}
	}

	ret = check_argv_tail(argc, argv);
	return ret;
}

static int suspend(unsigned id, int argc, char **argv, int flags)
{
	struct vzctl_cpt_param param = {};
	struct vzctl_env_handle *h = NULL;
	int ret;
	struct option options[] = {
		/*      sub commands    */
		{"dump",        no_argument, NULL, VZCTL_PARAM_DUMP},
		{"suspend",     no_argument, NULL, VZCTL_PARAM_SUSPEND},
		{"resume",      no_argument, NULL, VZCTL_PARAM_RESUME},
		{"kill",        no_argument, NULL, VZCTL_PARAM_KILL},
		/*      flags           */
		{"flags",       required_argument, NULL, VZCTL_PARAM_CPU_FLAGS},
		{"context",     required_argument, NULL, VZCTL_PARAM_CPTCONTEXT},
		{"dumpfile",    required_argument, NULL, VZCTL_PARAM_DUMPFILE},
		{"skip_arpdetect", no_argument, NULL, VZCTL_PARAM_SKIP_ARPDETECT},
		{"keep_pages",  no_argument, NULL, VZCTL_PARAM_KEEP_PAGES},
		{"unfreeze",    no_argument, NULL, VZCTL_PARAM_UNFREEZE},
		{ NULL, 0, NULL, 0 }
	};


	if ((ret = parse_cpt_opt(options, argc, argv, &param)))
		return ret;

	if ((h = vzctl2_env_open(id, flags, &ret)) == NULL)
		return ret;

	return vzctl2_env_chkpnt(h, param.cmd ? param.cmd : VZCTL_CMD_CHKPNT, &param, flags);
}

static int resume(unsigned id, int argc, char **argv, int flags)
{
	struct vzctl_cpt_param param = {};
	struct vzctl_env_handle *h = NULL;
	int ret;
	struct option options[] =
	{
		/*      sub commands    */
		{"undump",      no_argument, NULL, VZCTL_PARAM_UNDUMP},
		{"kill",        no_argument, NULL, VZCTL_PARAM_KILL},
		{"resume",      no_argument, NULL, VZCTL_PARAM_RESUME},
		/*      flags           */
		{"dumpfile",    required_argument, NULL, VZCTL_PARAM_DUMPFILE},
		{"flags",       required_argument, NULL, VZCTL_PARAM_CPU_FLAGS},
		{"context",     required_argument, NULL, VZCTL_PARAM_CPTCONTEXT},
		{"skip_arpdetect",      no_argument, NULL, VZCTL_PARAM_SKIP_ARPDETECT},
		{ NULL, 0, NULL, 0 }
	};

	if ((ret = parse_cpt_opt(options, argc, argv, &param)))
		return ret;


	if ((h = vzctl2_env_open(id, flags, &ret)) == NULL)
		return ret;

	if (param.cmd == 0)
		param.cmd = VZCTL_CMD_RESTORE;

	return vzctl2_env_restore(h, &param, flags);
}

static int env_unregister(unsigned id, int argc, char **argv, int flags)
{
	return vzctl2_env_unregister(NULL, id, flags);
}

int status(unsigned id, int argc, char **argv, int flags)
{
	vzctl_env_status_t status;

	vzctl2_get_env_status(id, &status, ENV_STATUS_ALL);

	printf("VEID %d %s %s %s", id,
			status.mask & ENV_STATUS_EXISTS ? "exist" : "deleted",
			status.mask & ENV_STATUS_MOUNTED ? "mounted" : "unmounted",
			status.mask & ENV_STATUS_RUNNING ? "running" : "down");
	if (status.mask & ENV_STATUS_SUSPENDED)
		printf(" suspended");
	printf("\n");
	return 0;
}

int main(int argc, char *argv[], char *envp[])
{
	int unsigned veid;
	int verbose = 0;
	int verbose_tmp;
	int verbose_custom = 0;
	int quiet = 0;
	int flags = 0;
	int ret, i;
	const char *opt;
	action action = NULL;
	struct cmd_struct cmds[] = {
		{"set", set},
		{"create", create},
		{"start", start},
		{"stop", stop},
//		{"restart", restart},
		{"destroy", destroy},
		{"mount", mount},
		{"umount", umount},
		{"snapshot", snapshot},
		{"snapshot-switch", snapshot_switch},
		{"snapshot-delete", snapshot_delete},
		{"snapshot-mount", snapshot_mount},
		{"snapshot-umount", snapshot_umount},
//		{"exec3", exec},
//		{"exec2", exec},
		{"exec", exec},
		{"runscript", runscript},
		{"enter", enter},
		{"status", status},
		{"suspend", suspend},
		{"resume", resume},
//		{"quotaon", quotaon},
//		{"quotaoff", quotaoff},
//		{"quotainit", quotainit},
		{"register", env_register},
		{"unregister", env_unregister},
		{NULL, NULL},
	};

	_proc_title = argv[0];
	_proc_title_len = envp[0] - argv[0];
	ret = VZCTL_E_INVAL;
	argc--; argv++;
	vzctl2_init_log("vzctl");
	while (argc > 1) {
		opt = *argv;
		if (!strcmp(opt, "--verbose")) {
			if (argc > 2 &&
			    !parse_int(argv[1], &verbose_tmp))
			{
				verbose += verbose_tmp;
				argc--; argv++;
			} else {
				verbose++;
			}
			verbose_custom = 1;
		} else if (!strncmp(opt, "--verbose=", 10)) {
			if (parse_int(opt + 10, &verbose_tmp)) {
				fprintf(stderr, "Invalid value for"
					" --verbose\n");
				exit(VZCTL_E_INVAL);
			}
			verbose += verbose_tmp;
			vzctl2_set_log_verbose(verbose);
			verbose_custom = 1;
		} else if (!strcmp(opt, "--debug")) {
			verbose = DBG_CFG;
			vzctl2_set_log_verbose(verbose);
			verbose_custom = 1;
		} else if (!strcmp(opt, "--quiet"))
			quiet = 1;
		else if (!strcmp(opt, "--version")) {
			version();
			exit(0);
		} else if (!strcmp(opt, "--skiplock"))
			flags = VZCTL_SKIP_LOCK;
		else
			break;
		argc--; argv++;
	}
	if (argc == 0)	{
		usage();
		exit(VZCTL_E_INVAL);
	}

	for (i = 0; cmds[i].cmd && argc; i++) {
		if (!strcmp(*argv, cmds[i].cmd)) {
			action = cmds[i].f;
			argc--; argv++;
			break;
		}
	}
	if (action == NULL) {
		fprintf(stderr, "Bad command: %s\n", *argv);
		return VZCTL_E_INVAL;
	}

	if (action == env_register)
		return env_register(argc, argv, flags);

	if (argc < 1) {
		fprintf(stderr, "VE id is not given\n");
		return VZCTL_E_INVAL;
	}
	if (parse_int(*argv, &veid)) {
		char name[STR_SIZE];

		if (vzctl2_get_envid_by_name(name, &veid) < 0)
		{
			fprintf(stderr, "Invalid VE ID %s\n", *argv);
			return VZCTL_E_INVAL;
		}
	}
	if (verbose_custom)
		vzctl2_set_log_verbose(verbose);
	if ((ret = vzctl2_lib_init()))
		return ret;
	vzctl2_set_log_quiet(quiet);
	vzctl2_set_ctx(veid);
	ret = action(veid, argc, argv, flags);

	return ret;
}
