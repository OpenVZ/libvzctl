/*
 * include/linux/vziolimit.h
 *
 * Copyright (c) 2010-2015 Parallels IP Holdings GmbH
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
 */

#ifndef _LINUX_VZIOLIMIT_H
#define _LINUX_VZIOLIMIT_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define VZIOLIMITTYPE 'I'

struct iolimit_state {
	unsigned int id;
	unsigned int speed;
	unsigned int burst;
	unsigned int latency;
};

#define VZCTL_SET_IOLIMIT	_IOW(VZIOLIMITTYPE, 0, struct iolimit_state)
#define VZCTL_GET_IOLIMIT	_IOR(VZIOLIMITTYPE, 1, struct iolimit_state)
#define VZCTL_SET_IOPSLIMIT	_IOW(VZIOLIMITTYPE, 2, struct iolimit_state)
#define VZCTL_GET_IOPSLIMIT	_IOR(VZIOLIMITTYPE, 3, struct iolimit_state)

#endif /* _LINUX_VZIOLIMIT_H */
