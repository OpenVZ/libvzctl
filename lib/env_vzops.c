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
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "vzerror.h"
#include "logger.h"
#include "vztypes.h"
#include "util.h"

static int __vzctlfd = -1;

void vzctl_close(void)
{
	if (__vzctlfd != -1)
		close(__vzctlfd);
}

int vzctl_open(void)
{
	if (__vzctlfd != -1)
		return 0;

	__vzctlfd = open(VZCTLDEV, O_RDWR);
	if (__vzctlfd == -1)
		return vzctl_err(VZCTL_E_BAD_KERNEL, errno,
				"unable to open " VZCTLDEV);

	return 0;
}

int get_vzctlfd(void)
{
	if (__vzctlfd == -1)
		vzctl_open();

	return __vzctlfd;
}

int vzctl2_get_vzctlfd(void)
{
	return get_vzctlfd();
}

/** Change root to specified directory
 *
 * @param		Container root
 * @return		0 on success
 */
int vzctl_chroot(const char *root)
{
	int i;
	sigset_t sigset;
	struct sigaction act;

	if (check_var(root, "CT root is not set"))
		return VZCTL_E_VE_ROOT_NOTSET;

        if (chdir(root))
                return vzctl_err(VZCTL_E_CHROOT, errno,
				"unable to change dir to %s", root);
	if (chroot(root))
		return vzctl_err(VZCTL_E_CHROOT, errno,
				"chroot %s failed", root);
	if (setsid() == -1)
		logger(0, errno, "setsid()");
	sigemptyset(&sigset);
	sigprocmask(SIG_SETMASK, &sigset, NULL);
	sigemptyset(&act.sa_mask);
	act.sa_handler = SIG_DFL;
	act.sa_flags = 0;
	for (i = 1; i <= NSIG; ++i)
		sigaction(i, &act, NULL);
	return 0;
}

int vzctl2_set_vzlimits(const char *name)
{
	return -1;
}
