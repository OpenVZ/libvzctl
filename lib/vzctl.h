/*
 *  Copyright (c) 1999-2017, Parallels International GmbH
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
 */

#ifndef __VZCTL_H__
#define __VZCTL_H__

#include "libvzctl.h"


#ifdef __cplusplus
extern "C" {
#endif


/************************* Technologies ****************************/
/** Check supported technologies.
 * Compare technologies in mask with running kernel technologies,
 * return unsupported technologies mask.
 *
 * @param mask          requested technologies
 * @return              unsupported technologies
 */
unsigned long vzctl_check_tech(unsigned long mask);

/** Get technology name by id
 *
 * @param id		technologie ID
 * @return		name
 */
const char *vzctl_tech2name(unsigned long long id);
unsigned long long vzctl_name2tech(const char *name);

/** Check VE name is allowed name
 * 
 * @param		VE name in UTF-8
 * @return		1 - valid
 *			0 - not valid
 */
int vzctl_is_env_name_valid(const char *name);

/** Convert string from current locale to the internal libvzctl representation
 * This helper function used to convert parameters from comman dline encoding
 * to the internal encoding 'UTF8' for further passing in the functions like
 * vzctl2_get_envid_by_name()
 *
 * @param src		source string
 * @param dst		destination string
 * @param dst_size	destination string size
 * @return		0 on sucess
 */
int vzctl_convertstr(const char *src, char *dst, int dst_size);

/** Get vz service status
 * 1 - running
 * 0 - stopped
 * -1- error
 */
int vzctl_vz_status();

/** Get VEID by ip
 * Note: vzctl_open() have to be called before use this function
 *
 * @param	IPv4/6 in string notation
 * @return	VEID
		-1 on error (errno == EADDRNOTAVAIL means no such ip)
 */
int vzctl_get_envid_by_ip(const char *ip);

/** Get list of private areas
 * This function scan file system and return found VE_PRIBVATE.
 * Algo: Read shared file system from STORAGE_LIST if not exists read from
 * /proc/mounts and look for fs && ve.conf && .ve_layout pattern.
 * Caller should freed returned array.
 *
 * @return	Return array of (char *) found VE private areas terminated by 0
 *		NULL in case error.
 */
char **vzctl_scan_private(void);

/** Get list of storage
 * Return STORAGE_LIST if not defined scan /proc/mount for shared fs
 * Caller should freed returned array.
 *
 * @return	Return array of (char *) terminated by 0
 *		NULL in case error.
 */
char **vzctl_get_storage(void);

#ifdef __cplusplus
}
#endif
#endif /* __VZCTL_H__ */
