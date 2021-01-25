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

#ifndef	_EXEC_H_
#define	_EXEC_H_

enum {
	EXEC_STD_REDIRECT = (1 << 16),	/* redirect std[in,out,err] from/to VE */
	EXEC_OPENPTY = (1 << 17),	/* emulate pty in VE*/
	EXEC_LOG_OUTPUT = (1 << 18),
	EXEC_NOENV = (1<< 19),
	EXEC_QUIET =	(1<<20)
};

struct exec_param {
	const char *ve_root;
	exec_mode_e exec_mode;
	char *const *argv;
	char *const *envp;
	char *std_in;
	int *stdfd;
	execFn fn;
	void *data;
	int *data_fd;
	int status_p[2];
	int in_p[2];
	int out_p[2];
	int err_p[2];
	int comm;
	int timeout;
};

#ifdef __cplusplus
extern "C" {
#endif
void close_array_fds(int close_std, int *fds, ...);
void real_env_exec_close(struct exec_param *param);
int real_env_exec_fn(struct vzctl_env_handle *h, execFn fn, void *data,
                int *data_fd, int timeout, int flags);
int real_env_exec(struct vzctl_env_handle *h, struct exec_param *param, int flags);

void set_timeout_handler(pid_t pid, int timeout);
int real_env_exec_init(struct exec_param *param);
char **build_arg(char **a, char *const *b);

/** Execute function inside VE.
 * All file descriptors are closed.
 *
 * @param veid		VE id.
 * @param root		VE root.
 * @param fn		function pointer
 * @param data		function argument
 * @param timeout	execution timeout, 0 - unlimited.
 * @return		0 on success.
 */
int vzctl2_env_exec_fn(unsigned veid, const char *root, execFn fn, void *data,
	int timeout);

int vzctl2_env_execve_priv(struct vzctl_env_handle *h, exec_mode_e exec_mode,
		char *const argv[], char *const envp[], int timeout,
		int stdfd[4], int flags);
int vzctl2_env_exec_pty_priv(struct vzctl_env_handle *h, int exec_mode,
		char *const argv[], char *const envp[], int fds[4], int flags);

int vzctl2_exec_script(char *const argv[], char *const env[], int flags);

int vzctl2_env_exec_script(struct vzctl_env_handle *h,
	char *const argv[], char *const envp[], const char *fname,
	const char *inc, int timeout, int flags);

int vzctl2_wrap_env_exec_script(struct vzctl_env_handle *h,
        char *const argv[], char *const envp[], const char *fname, int timeout, int flags);

int vzctl2_wrap_env_exec_vzscript(struct vzctl_env_handle *h,
        char *const argv[], char *const envp[], const char *fname, int timeout, int flags);

int vzctl2_wrap_exec_script(char *const argv[], char *const envp[], int flags);
void vzctl_stdredir(int rdfd, int wrfd, int log);
int vzctl_env_exec_fn(struct vzctl_env_handle *h, execFn fn, void *data,
		int timeout);
int vzctl_wrap_action(struct vzctl_env_handle *h, char *action,
		char *const arg[]);
#ifdef __cplusplus
}
#endif
#endif	/* __EXEC_H__ */
