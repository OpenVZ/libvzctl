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
#ifndef _LOCK_H_
#define _LOCK_H_

struct vzctl_env_handle;

#ifdef __cplusplus
extern "C" {
#endif

#define VZCTL_LOCK_EX   0x1
#define VZCTL_LOCK_SH   0x2
#define VZCTL_LOCK_NB   0x4

int vzctl_lock(const char *lockfile, int mode, unsigned int timeout);
void vzctl_unlock(int fd, const char *lockfile);

int get_enter_lock(struct vzctl_env_handle *h);
void release_enter_lock(int lockfd);
int is_enter_locked(struct vzctl_env_handle *h);
int vzctl_env_conf_lock(struct vzctl_env_handle *h, int mode);
int vzctl_env_conf_unlock(int fd);
const char *get_dir_lock_file(const char *dir, char *buf, int size);
#ifdef __cplusplus
}
#endif
#endif	/* _LOCK_H_ */
