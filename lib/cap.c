/*
 *  Copyright (c) 2000-2017, Parallels International GmbH
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
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <string.h>
#include <sys/prctl.h>

#include "env.h"
#include "cap.h"
#include "vzerror.h"
#include "logger.h"
#include "vzfeatures.h"

#ifndef _LINUX_CAPABILITY_VERSION_1
# define _LINUX_CAPABILITY_VERSION_1  0x19980330
#endif
#ifndef _LINUX_CAPABILITY_VERSION_2
# define _LINUX_CAPABILITY_VERSION_2  0x20071026
#endif
#ifndef _LINUX_CAPABILITY_VERSION_3
# define _LINUX_CAPABILITY_VERSION_3  0x20080522
#endif

#ifndef CAP_AUDIT_WRITE
#define CAP_AUDIT_WRITE 29
#endif
#ifndef CAP_VE_ADMIN
#define CAP_VE_ADMIN    30
#endif
#ifndef CAP_SETFCAP
#define CAP_SETFCAP     31
#endif

/* From /usr/include/linux/prctl.h */
#ifndef PR_CAPBSET_DROP
# define PR_CAPBSET_DROP 24
#endif


#define CAPDEFAULTMASK					\
	(CAP_TO_MASK(CAP_CHOWN)				| \
	CAP_TO_MASK(CAP_DAC_OVERRIDE)			| \
	CAP_TO_MASK(CAP_DAC_READ_SEARCH)		| \
	CAP_TO_MASK(CAP_FOWNER)				| \
	CAP_TO_MASK(CAP_FSETID)				| \
	CAP_TO_MASK(CAP_KILL)				| \
	CAP_TO_MASK(CAP_SETGID)				| \
	CAP_TO_MASK(CAP_SETUID)				| \
	CAP_TO_MASK(CAP_LINUX_IMMUTABLE)		| \
	CAP_TO_MASK(CAP_NET_BIND_SERVICE)		| \
	CAP_TO_MASK(CAP_NET_BROADCAST)			| \
	CAP_TO_MASK(CAP_NET_RAW)			| \
	CAP_TO_MASK(CAP_IPC_LOCK)			| \
	CAP_TO_MASK(CAP_IPC_OWNER)			| \
	CAP_TO_MASK(CAP_SYS_CHROOT)			| \
	CAP_TO_MASK(CAP_SYS_PTRACE)			| \
	CAP_TO_MASK(CAP_SYS_BOOT)			| \
	CAP_TO_MASK(CAP_SYS_NICE)			| \
	CAP_TO_MASK(CAP_SYS_RESOURCE)			| \
	CAP_TO_MASK(CAP_SYS_TTY_CONFIG)			| \
	CAP_TO_MASK(CAP_MKNOD)				| \
	CAP_TO_MASK(CAP_LEASE)				| \
	CAP_TO_MASK(CAP_VE_ADMIN)			| \
	CAP_TO_MASK(CAP_SETPCAP)			| \
	CAP_TO_MASK(CAP_SETFCAP)			| \
	CAP_TO_MASK(CAP_AUDIT_WRITE))

#define CAPDEFAULTMASK_UPSTREAM				\
	CAPDEFAULTMASK					| \
	CAP_TO_MASK(CAP_SYS_ADMIN)			| \
	CAP_TO_MASK(CAP_NET_ADMIN)


static char *cap_names[] = {
"CHOWN",		/*	0	*/
"DAC_OVERRIDE",		/*	1	*/
"DAC_READ_SEARCH",	/*	2	*/
"FOWNER",		/*	3	*/
"FSETID",		/*	4	*/
"KILL",			/*	5	*/
"SETGID",		/*	6	*/
"SETUID",		/*	7	*/
"SETPCAP",		/*	8	*/
"LINUX_IMMUTABLE",	/*	9	*/
"NET_BIND_SERVICE",	/*	10	*/
"NET_BROADCAST",	/*	11	*/
"NET_ADMIN",		/*	12	*/
"NET_RAW",		/*	13	*/
"IPC_LOCK",		/*	14	*/
"IPC_OWNER",		/*	15	*/
"SYS_MODULE",		/*	16	*/
"SYS_RAWIO",		/*	17	*/
"SYS_CHROOT",		/*	18	*/
"SYS_PTRACE",		/*	19	*/
"SYS_PACCT",		/*	20	*/
"SYS_ADMIN",		/*	21	*/
"SYS_BOOT",		/*	22	*/
"SYS_NICE",		/*	23	*/
"SYS_RESOURCE",		/*	24	*/
"SYS_TIME",		/*	25	*/
"SYS_TTY_CONFIG",	/*	26	*/
"MKNOD",		/*	27	*/
"LEASE",		/*	28	*/
"AUDIT_WRITE",		/*	29	*/
"VE_ADMIN",		/*	30	*/
"SETFCAP",		/*	31	*/
};

/** Add capability name to capability mask.
 *
 * @param name		capability name.
 * @param mask		capability mask.
 * @return		0 on success.
 */
int get_cap_mask(char *name, unsigned long *mask)
{
	unsigned int i;

	for (i = 0; i < sizeof(cap_names) / sizeof(*cap_names); i++) {
		if (!strcasecmp(name, cap_names[i])) {
			cap_raise(*mask, i);
			return 0;
		}
	}
	return -1;
}

/** merge capabilities and return in string format.
 *
 * @param new		capability mask.
 * @param buf		capabilities in string format.
 * @return		filled buffer.
 */
void build_cap_str(struct vzctl_cap_param *new, char *buf, int len)
{
	unsigned int i;
	int r;
	char *sp, *ep;

	*buf = '\0';
	sp = buf;
	ep = buf + len;
	for (i = 0; i < sizeof(cap_names) / sizeof(*cap_names); i++) {
		int op = 0;

		if (CAP_TO_MASK(i) & new->on)
			op = 1;
		else if (CAP_TO_MASK(i) & new->off)
			op = 2;
		else
			continue;
		r = snprintf(sp, ep - sp,  "%s:%s ", cap_names[i],
			op == 1 ? "on" : "off");
		if (r < 0 || sp + r >= ep)
			break;
		sp += r;
	}
}

static cap_t make_cap_mask(cap_t def, cap_t on, cap_t off)
{
	return (def | on) & ~off;
}

unsigned long vzctl2_get_default_capmask(void)
{
	return CAPDEFAULTMASK & 0xffffffff;
}

int parse_cap(struct vzctl_cap_param *cap, const char *str, int replace)
{
	int len, ret = 0;
	char *p, *token;
	char cap_nm[128];
	unsigned long *mask;
	char *tmp = strdup(str);
	char *savedptr;

	if (replace) {
		cap->on = 0;
		cap->off = 0;
	}

	if ((token = strtok_r(tmp, LIST_DELIMITERS, &savedptr)) == NULL)
		return 0;
	do {
		if ((p = strrchr(token, ':')) == NULL) {
			logger(-1, 0, "Invalid syntaxes in %s:"
					" capname:on|off", token);
			ret = VZCTL_E_INVAL;
			break;
		}
		if (!strcmp(p + 1, "off"))
			mask = &cap->off;
		else if (!strcmp(p + 1, "on"))
			mask = &cap->on;
		else {
			logger(-1, 0, "Invalid syntaxes in %s:"
					" capname:on|off", token);
			ret = VZCTL_E_INVAL;
			break;
		}
		len = p - token;
		if (len >= sizeof(cap_nm))
			len = sizeof(cap_nm) - 1;
		strncpy(cap_nm, token, len);
		cap_nm[len] = 0;
		if (get_cap_mask(cap_nm, mask)) {
			logger(-1, 0, "Capability %s is unknown", cap_nm);
			ret = VZCTL_E_INVAL;
			break;
		}
	} while ((token = strtok_r(NULL, LIST_DELIMITERS, &savedptr)));
	free(tmp);
	return ret;
}

int vzctl2_env_set_cap(vzctl_env_handle_ptr h, vzctl_env_param_ptr env, unsigned long capmask)
{
	struct vzctl_cap_param *cap = env->cap;
	unsigned long old_capmask;

	old_capmask = make_cap_mask(CAPDEFAULTMASK, h->env_param->cap->on, h->env_param->cap->off);

	cap->on = capmask & ~old_capmask;
	cap->off = old_capmask & ~capmask;

	return 0;
}

int vzctl2_env_get_cap(vzctl_env_param_ptr env, unsigned long *capmask)
{
	struct vzctl_cap_param *cap = env->cap;

	*capmask = make_cap_mask(CAPDEFAULTMASK, cap->on, cap->off);

	return 0;
}
