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

#ifndef __COMMON_H__
#define __COMMON_H__
void xfree(void *p);
int xstrdup(char **dst, const char *src);
void free_ar_str(char *ar[]);
void free_str(list_head_t *head);
struct vzctl_str_param *add_str_param(list_head_t *head, const char *str);
const struct vzctl_str_param *find_str(list_head_t *head, const char *str);
int stat_file(const char *file);
int make_dir(const char *path, int full);
void strip_end(char *str);
int parse_int(const char *str, int *val);
int parse_ul(const char *str, unsigned long *val);
int read_pid(const char *path, pid_t *pid);
int set_personality32(void);
int reset_loginuid(void);
int open_proc_fd();
int _close_fds(int close_mode, int *skip_fds);
int env_wait(int pid, int timeout, int *retcode);
int wait_on_fifo(void *data);
int set_ns(pid_t pid, const char *name, int flags);
int env_enter(ctid_t ctid, int flags);
#endif /* __COMMON_H__ */

