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

#ifndef _VZERROR_H_
#define _VZERROR_H_

/* vzctl error codes */
//*****************************************
#define VZCTL_E_OK			0
#define VZCTL_E_SETUBC			1
#define VZCTL_E_SETFSHD			2
#define VZCTL_E_SYSTEM			3
#define VZCTL_E_NOMEM			4
#define VZCTL_E_BAD_KERNEL		5
#define VZCTL_E_RESOURCE		6
#define VZCTL_E_ENVCREATE		7
#define VZCTL_E_EXEC			8
#define VZCTL_E_LOCKED			9
#define VZCTL_E_NOCONFIG		10
#define VZCTL_E_NOSCRIPT		11
#define VZCTL_E_NO_LICENSE		12
#define VZCTL_E_CAP			13
#define VZCTL_E_NOVE_CONFIG		14
#define VZCTL_E_EXEC_TIMEOUT		15
#define VZCTL_E_CHKPNT			16
#define VZCTL_E_RESTORE			17
#define VZCTL_E_SETLUID			18

#define VZCTL_E_UNKNOWN_PARM		19
#define VZCTL_E_INVAL_PARAMETER_SYNTAX	20
#define VZCTL_E_INVAL			21
#define VZCTL_E_VE_ROOT_NOTSET		22
#define VZCTL_E_VE_PRIVATE_NOTSET	23
#define VZCTL_E_VE_TMPL_NOTSET		24
#define VZCTL_E_RATE_NOTSET		25
#define VZCTL_E_TOTALRATE_NOTSET	26
#define VZCTL_E_NOT_ENOUGH_PARAMS	27
#define VZCTL_E_NOT_ENOUGH_UBC_PARAMS	28
#define VZCTL_E_VE_PKGSET_NOTSET	29
#define VZCTL_E_VE_BANDWIDTH_NOTSET	30
#define VZCTL_E_ENV_NOT_RUN		31
#define VZCTL_E_ENV_RUN			32
#define VZCTL_E_ENV_STOP			33
#define VZCTL_E_CANT_ADDIP		34
#define VZCTL_E_VALIDATE		35
#define VZCTL_E_OVERCOMMIT		36

#define VZCTL_E_SKIP_ACTION		39

#define VZCTL_E_FS_NOT_MOUNTED		40
#define VZCTL_E_FS_MOUNTED		41
#define VZCTL_E_NO_PRVT			42
#define VZCTL_E_FS_PRVT_AREA_EXIST	44
#define VZCTL_E_FS_NO_DISK_SPACE	46
#define VZCTL_E_BAD_TMPL		47
#define VZCTL_E_FS_NEW_VE_PRVT		48
#define VZCTL_E_FS_MPOINTCREAT		49
#define VZCTL_E_MOUNT			50
#define VZCTL_E_UMOUNT			51
#define VZCTL_E_FS_DEL_PRVT		52
#define VZCTL_E_UNK_MOUNT_TYPE		53
#define VZCTL_E_CREATE_DIR		54
#define VZCTL_E_NOTENOUGH_QUOTA_LIMITS	55

#define VZCTL_E_DQ_ON			60
#define VZCTL_E_DQ_INIT			61
#define VZCTL_E_DQ_SET			62
#define VZCTL_E_DISKSPACE_NOT_SET	63
#define VZCTL_E_DISKINODES_NOT_SET	64
#define VZCTL_E_SET_USER_QUOTA		65
#define VZCTL_E_DQ_OFF			66
#define VZCTL_E_DQ_UGID_NOTINIT		67
#define VZCTL_E_GET_QUOTA_USAGE		68

#define VZCTL_E_BADHOSTNAME		70
#define VZCTL_E_BADIP			71
#define VZCTL_E_BADDNSSRV		72
#define VZCTL_E_BADDNSSEARCH		73
#define VZCTL_E_CHANGEPASS		74
#define VZCTL_E_VE_LCKDIR_NOTSET	77
#define VZCTL_E_IP_INUSE		78
#define VZCTL_E_ACTIONSCRIPT		79
#define VZCTL_E_SET_RATE		80
#define VZCTL_E_SET_ACCOUNT		81
#define VZCTL_E_CP_CONFIG		82
#define VZCTL_E_INVALID_CONFIG		85
#define VZCTL_E_SET_DEVICES		86
#define VZCTL_E_INSTALL_APPS		87
#define VZCTL_E_START_SHARED_BASE	88

#define VZCTL_E_PKGSET_NOT_FOUND	91
#define VZCTL_E_RECOVER			92
#define VZCTL_E_GET_APPS		93
#define VZCTL_E_REINSTALL		94

#define VZCTL_E_APP_CONFIG		100
#define VZCTL_E_CUSTOM_CONFIGURE	102
#define VZCTL_E_IPREDIRECT		103
#define VZCTL_E_NETDEV			104
#define VZCTL_E_ENV_START_DISABLED	105
#define VZCTL_E_SET_IPTABLES		106

#define VZCTL_E_NO_DISTR_CONF		107
#define VZCTL_E_NO_DISTR_ACTION_SCRIPT	108

#define VZCTL_E_CUSTOM_REINSTALL	128
#define VZCTL_E_SLMLIMIT_NOT_SET	129
#define VZCTL_E_SLM			130
#define VZCTL_E_UNSUP_TECH		131
#define VZCTL_E_SLM_DISABLED		132
#define VZCTL_E_WAIT_FAILED		133
#define VZCTL_E_SET_PERSONALITY		134
#define VZCTL_E_SET_MEMINFO		135
#define VZCTL_E_VETH			136
#define VZCTL_E_SET_NAME		137
#define VZCTL_E_NO_INITTAB		138
#define VZCTL_E_CONF_SAVE		139
#define VZCTL_E_REGISTER		140
#define VZCTL_E_ENV_MANAGE_DISABLED	141
#define VZCTL_E_UNREGISTER		142
#define VZCTL_E_SET_OSRELEASE		144
#define VZCTL_E_GET_OSRELEASE		145
#define VZCTL_E_CPUMASK			146
#define VZCTL_E_SET_PCI			147
#define VZCTL_E_NODEMASK		149

#define VZCTL_E_CREATE_IMAGE            151
#define VZCTL_E_MOUNT_IMAGE             152
#define VZCTL_E_UMOUNT_IMAGE            153
#define VZCTL_E_RESIZE_IMAGE            154
#define VZCTL_E_CONVERT_IMAGE           155
#define VZCTL_E_CREATE_SNAPSHOT         156
#define VZCTL_E_MERGE_SNAPSHOT          157
#define VZCTL_E_DELETE_SNAPSHOT         158
#define VZCTL_E_SWITCH_SNAPSHOT         159
#define VZCTL_E_MOUNT_SNAPSHOT          160
#define VZCTL_E_UMOUNT_SNAPSHOT         161
#define VZCTL_E_PARSE_DD                162
#define VZCTL_E_ADD_IMAGE		163
#define VZCTL_E_DEL_IMAGE		164
#define VZCTL_E_DISK_CONFIGURE		165
#define VZCTL_E_INODE_CONVERSION	168
#define VZCTL_E_USAGE_CONVERSION	169
#define VZCTL_E_CPUPOOLS                170

#define VZCTL_E_PIPE			200
#define VZCTL_E_FORK			201
#define VZCTl_E_FOPEN			202
#define VZCTL_E_UNKNOWN_PARAM		203
#define VZCTL_E_INVAL_SKIP		204
#define VZCTL_E_LONG_TRUNC		205
#define VZCTL_E_CONFIG			206
#define VZCTL_E_LOCK			207
#define VZCTL_E_CHROOT			208
#define VZCTL_E_WAIT			209
#define VZCTL_E_SET_IO			210
#define VZCTL_E_NO_PARAM		211
#define VZCTL_E_ENV_LAYOUT		212
#define VZCTL_E_TIMEOUT			213
#define VZCTL_E_DQ_STAT			214
#define VZCTL_E_CPULIMIT		215
#define VZCTL_E_CPUWEIGHT		216
#define VZCTL_E_VCPU			217
#define VZCTL_E_CPUSTAT			218
#define VZCTL_E_PORT_REDIR		219
#define VZCTL_E_READ_DISTACTION		220
#define VZCTL_E_CACHE_NOT_FOUND		221
#define VZCTL_E_CPUINFO			222
#define VZCTL_E_AUTH			224
#define VZCTL_E_AUTH_GUID		225
#define VZCTL_E_VCMM			226
#define VZCTL_E_SYSFS_PERM		227
#define VZCTL_E_ENCRYPT			228
#define VZCTL_E_NOT_INITIALIZED		229
#define VZCTL_E_AUTH_PSASHADOW		230
#define VZCTL_E_UMOUNT_BUSY		231

#define debug(level, fmt, args...)      logger(level, 0, fmt, ##args)

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif
#endif /* _VZ_ERROR_H_ */

