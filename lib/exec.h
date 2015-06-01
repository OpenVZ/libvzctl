/*
 *  Copyright (c) 1999-2015 Parallels IP Holdings GmbH
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
	int *status_p;
	int *in_p;
	int *out_p;
	int *err_p;
};

#ifdef __cplusplus
extern "C" {
#endif
int vz_env_exec(struct vzctl_env_handle *h, struct exec_param *param,
                int flags, int *pid);
int ns_env_exec(struct vzctl_env_handle *h, struct exec_param *param,
                int flags, int *pid);
int vz_env_exec_fn(struct vzctl_env_handle *h, execFn fn, void *data,
		int *data_fd, int timeout, int flags);
int ns_env_exec_fn(struct vzctl_env_handle *h, execFn fn, void *data,
                int *data_fd, int timeout, int flags);

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

int vzctl2_env_exec_async(struct vzctl_env_handle *h, exec_mode_e exec_mode,
	char *const argv[], char *const envp[], char *std_in, int timeout,
	int flags, int stdfd[3], int *err);

int vzctl2_exec_script(char *const argv[], char *const env[], int flags);

int vzctl2_env_exec_script(const ctid_t ctid, const char *ve_root,
	char *const argv[], char *const envp[], const char *fname,
	const char *inc, int timeout, int flags);

int vzctl2_wrap_env_exec_script(struct vzctl_env_handle *h, const char *ve_root,
        char *const argv[], char *const envp[], const char *fname, int timeout, int flags);

int vzctl2_wrap_env_exec_vzscript(struct vzctl_env_handle *h, const char *ve_root,
        char *const argv[], char *const envp[], const char *fname, int timeout, int flags);

int vzctl2_wrap_exec_script_rc(char *const argv[], char *const env[], int flags, int *retcode);
int vzctl2_wrap_exec_script(char *const argv[], char *const envp[], int flags);
int vzctl2_stdredir(int rdfd, int wrfd);

#ifdef __cplusplus
}
#endif
#endif	/* __EXEC_H__ */
