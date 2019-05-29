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

#ifndef _LOGGER_H_
#define _LOGGER_H_
#include <stdarg.h>

#define VZCTL_LOG_FILE	"/var/log/vzctl.log"
#define	DBG_CFG		0x10000
#define	DBG_RES		0x10001
#define	DBG_CG		0x10002

#define debug(level, fmt, args...)	logger(level, 0, fmt, ##args)

#ifdef __cplusplus
extern "C" {
#endif

/** Print message to log file & stdout.
 *
 * @param log_level		message severity.
 * @param err_num		errno
 * @param format		fprintf format.
 */
void logger(int log_level, int err_num, const char *format, ...)
	 __attribute__ ((__format__ (__printf__, 3, 4)));
void log_quiet(int log_level, int err_num, const char *format, ...)
	 __attribute__ ((__format__ (__printf__, 3, 4)));
int vzctl_err(int err, int eno, const char *format, ...)
        __attribute__ ((__format__ (__printf__, 3, 4)));

/** Close logging.
 */
void vzctl_free_log();

#ifdef __cplusplus
}
#endif
#endif /* _LOGGER_H_ */
