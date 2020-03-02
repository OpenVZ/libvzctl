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

#include <sys/ioctl.h>
#include <linux/limits.h>

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <poll.h>

#include <termios.h>
#include <pty.h>
#include <grp.h>
#include <pwd.h>

#include "vzctl.h"
#include "vz.h"
#include "exec.h"
#include "env.h"
#include "logger.h"
#include "util.h"
#include "vzerror.h"
#include "env_ops.h"
#include "cleanup.h"
#include "lock.h"

#define DEV_TTY		"/dev/tty"
static struct termios _tios;

static volatile sig_atomic_t alarm_flag, child_exited, win_changed;
static __thread int s_timeout_pid;
static char _proc_title[PATH_MAX];
static int _proc_title_len = sizeof(_proc_title);

static char *argv_bash[] = {"bash", NULL};
static char *envp_bash[] = {"HOME=/", "TERM=linux",
	ENV_PATH,
	"SHELL=/bin/bash",
	NULL};

static void exec_handler(int sig)
{
	child_exited = 1;
}

int execvep(const char *path, char *const argv[], char *const envp[])
{
	if (!strchr(path, '/')) {
		char *p = DEF_PATH;
		for (; p && *p;) {
			char partial[FILENAME_MAX];
			char *p2;

			p2 = strchr(p, ':');
			if (p2) {
				size_t len = p2 - p;

				strncpy(partial, p, len);
				partial[len] = 0;
			} else {
				strcpy(partial, p);
			}
			if (strlen(partial))
				strcat(partial, "/");
			strcat(partial, path);

			execve(partial, argv, envp != NULL ? envp : envp_bash);

			if (errno != ENOENT)
				return -1;
			if (p2) {
				p = p2 + 1;
			} else {
				p = 0;
			}
		}
		return -1;
	} else
		return execve(path, argv, envp);
}

#define MAX_SKIP_FD	255
void close_array_fds(int close_std, int *fds, ...)
{
	va_list ap;
	int skip_fds[MAX_SKIP_FD + 1];
	int fd, i = 0;

	va_start(ap, fds);
	for (i = 0; i < MAX_SKIP_FD; i++) {
		fd = va_arg(ap, int);
		skip_fds[i] = fd;
		if (fd == -1)
			break;
	}
	skip_fds[i] = -1;
	va_end(ap);

	if (fds != NULL) {
		int j;
		for (j = 0; fds[j] != -1 && i < MAX_SKIP_FD; j++, i++)
			skip_fds[i] = fds[j];
	}
	skip_fds[i] = -1;
	_close_fds(close_std, i == 0 ? NULL : skip_fds);
}

/** Close all fd.
 * @param close_std	flag for closing the [0-2] fds
 * @param ...		list of fds are skiped, (-1 is the end mark) 
*/
void close_fds(int close_std, ...)
{
	int fd, i;
	va_list ap;
	int skip_fds[MAX_SKIP_FD + 1];

	va_start(ap, close_std);
	for (i = 0; i < MAX_SKIP_FD; i++) {
		fd = va_arg(ap, int);
		skip_fds[i] = fd;
		if (fd == -1)
			break;
	}
	skip_fds[i] = -1;
	va_end(ap);
	_close_fds(close_std, skip_fds);
}

static __thread char _s_logbuf[10240];
static __thread char *plogbuf;

void initoutput(void)
{
	plogbuf = _s_logbuf;
	*plogbuf = '\0';
}

void addoutput(char *buf, int len)
{
	char *ep = _s_logbuf + sizeof(_s_logbuf) - 1;

	if (ep > plogbuf) {
		int lenlog = _s_logbuf + sizeof(_s_logbuf) - plogbuf;
		lenlog = (len < lenlog) ? len : lenlog;
		memcpy(plogbuf, buf, lenlog);
		plogbuf += lenlog;
		*plogbuf = 0;
	}
}

void writeoutput(int level)
{
	char buf[4096];
	char *bp, *ep, *ps;

	if (*_s_logbuf == '\0')
		return;
	ep = buf + sizeof(buf);
	bp = buf;
	ps = _s_logbuf;
	while (*ps) {
		char *pse = ps;
		int len2, len;

		while (*pse && *pse != '\n') ++pse;
		len = pse - ps;
		len2 = (bp + len < ep) ? len : ep - bp;
		memcpy(bp, ps, len2);
		bp += len2;
		*bp = '\0';
		if (*pse == '\n') {
			log_quiet(level, 0, "%s", buf);
			while (*pse && *pse == '\n') ++pse;
			bp = buf;
		}
		ps = pse;
	}
	if (bp != buf)
		log_quiet(level, 0, "%s", buf);
}

static int stdredir(int rdfd, int wrfd, int log)
{
	int lenr, lenw, lentotal, lenremain, n;
	char buf[10240];
	char *p;
	fd_set wr_set;

	lenr = read(rdfd, buf, sizeof(buf)-1);
	if (lenr > 0) {
		if (log)
			addoutput(buf, lenr);
		lentotal = 0;
		lenremain = lenr;
		p = buf;
		while (lentotal < lenr) {
			while ((lenw = write(wrfd, p, lenremain)) < 0) {
				switch (errno) {
				case EINTR:
					continue;
				case EAGAIN:
					FD_ZERO(&wr_set);
					FD_SET(wrfd, &wr_set);
					n = select(FD_SETSIZE, NULL, &wr_set,
								NULL, NULL);
					if (n < 1)
						return -1;
					break;
				default:
					return -1;
				}
			}
			lentotal += lenw;
			lenremain -= lenw;
			p += lenw;
		}
	} else if (lenr == 0) {
		return -1;
	} else {
		if (errno == EAGAIN)
			return 1;
		else if (errno != EINTR)
			return -1;
	}
	return 0;
}

void vzctl_stdredir(int rdfd, int wrfd, int log)
{
	initoutput();
	while (stdredir(rdfd, wrfd, log) == 0);
	if (log)
		writeoutput(0);
}

static void winchange_handler(int sig)
{
	win_changed = 1;
}

static void timeout_handler(int sig)
{
	alarm_flag = 1;
	if (s_timeout_pid > 0)
		kill(s_timeout_pid, SIGTERM);
}

void set_timeout_handler(pid_t pid, int timeout)
{
	struct sigaction act = {};

	s_timeout_pid = pid;

	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	act.sa_handler = timeout_handler;
	sigaction(SIGALRM, &act, NULL);

	alarm(timeout);
}

int real_env_exec_init(struct exec_param *param)
{
	struct sigaction act = {};

	if (pipe(param->status_p) < 0 || pipe(param->in_p) < 0 )
		return vzctl_err(VZCTL_E_PIPE, errno, "Unable to create pipe");

	if (param->stdfd == NULL) {
		if (pipe(param->out_p) < 0 || pipe(param->err_p) < 0)
			return vzctl_err(VZCTL_E_PIPE, errno, "Unable to create pipe");
		/* Set non block mode */
		set_not_blk(param->out_p[0]);
		set_not_blk(param->err_p[0]);
	}

	sigemptyset(&act.sa_mask);
	act.sa_handler = SIG_IGN;
	act.sa_flags = 0;
	sigaction(SIGPIPE, &act, NULL);

	child_exited = 0;
	act.sa_flags = SA_NOCLDSTOP;
	act.sa_handler = exec_handler;
	sigaction(SIGCHLD, &act, NULL);

	return 0;
}

void real_env_exec_close(struct exec_param *param)
{
	p_close(param->status_p);
	p_close(param->out_p);
	p_close(param->err_p);
	p_close(param->in_p);
}

int real_env_exec(struct vzctl_env_handle *h, struct exec_param *param, int flags)
{
	int ret;
	int skip_fds[7];
	int n, i = 0;
	struct sigaction act = {.sa_handler = SIG_DFL};

	if (param->stdfd != NULL) {
		int fd = open("/dev/null", O_RDWR);
		dup2(param->stdfd[0] != -1 ? param->stdfd[0] : fd, STDIN_FILENO);
		dup2(param->stdfd[1] != -1 ? param->stdfd[1] : fd, STDOUT_FILENO);
		dup2(param->stdfd[2] != -1 ? param->stdfd[2] : fd, STDERR_FILENO);
		close(fd);
	} else {
		dup2(param->in_p[0], STDIN_FILENO);
		dup2(param->out_p[1], STDOUT_FILENO);
		dup2(param->err_p[1], STDERR_FILENO);
	}

	if (param->data_fd != NULL)
		skip_fds[i++] = *param->data_fd;
	if (param->stdfd != NULL) {
		if (param->stdfd[0] != -1)
			skip_fds[i++] = param->stdfd[0];
		if (param->stdfd[1] != -1)
			skip_fds[i++] = param->stdfd[1];
		if (param->stdfd[2] != -1)
			skip_fds[i++] = param->stdfd[2];
	}

	fcntl(param->status_p[1], F_SETFD, FD_CLOEXEC);
	skip_fds[i++] = param->status_p[1];
	skip_fds[i++] = -1;

	_close_fds(0, skip_fds);

	if (param->exec_mode == MODE_EXECFN) {
		close(param->status_p[1]);
		return param->fn(param->data);
	} else if (param->exec_mode == MODE_EXEC) {
		if (param->argv == NULL) {
			ret = VZCTL_E_INVAL;
			goto err;
		}

		sigaction(SIGPIPE, &act, NULL);
		execvep(param->argv[0], param->argv,
				param->envp != NULL ? param->envp : envp_bash);
		ret = -errno;
	} else {
		sigaction(SIGPIPE, &act, NULL);
		if (flags & EXEC_NOENV) {
			execv("/bin/bash", param->argv != NULL ? param->argv : argv_bash);
			execv("/bin/sh", param->argv != NULL ? param->argv : argv_bash);
		} else {
			execve("/bin/bash",
					param->argv != NULL ? param->argv : argv_bash,
					param->envp != NULL ? param->envp : envp_bash);
			execve("/bin/sh",
					param->argv != NULL ? param->argv : argv_bash,
					param->envp != NULL ? param->envp : envp_bash);
		}
		ret = -errno;
	}

err:
	n = write(param->status_p[1], &ret, sizeof(ret));
	if (n != sizeof(ret))
		logger(-1, errno, "failed to write to status pipe");

	return ret;
}

int real_env_exec_waiter(struct exec_param *param, int pid, int timeout, int flags)
{
	int log = flags & EXEC_LOG_OUTPUT;
	int ret = 0;

	close(param->status_p[1]); param->status_p[1] = -1;
	close(param->out_p[1]); param->out_p[1] = -1;
	close(param->err_p[1]); param->err_p[1] = -1;
	close(param->in_p[0]); param->in_p[0] = -1;
	logger(10, 0, "* Wait on status");
	while (read(param->status_p[0], &ret, sizeof(ret)) == -1)
		if (errno != EINTR)
			return vzctl_err(VZCTL_E_SYSTEM, errno,
					"Failed to wait status");
	logger(10, 0, "* Wait done ret=%d", ret);
	if (ret) {
		int eno = 0;
		const char *cmd;

		if (ret < 0) {
			eno = -ret;
			ret = eno == ENOENT ? VZCTL_E_BAD_TMPL : VZCTL_E_RESOURCE;
		}
		if (param->exec_mode == MODE_EXEC)
			cmd = param->argv[0];
		else if (param->exec_mode== MODE_EXECFN)
			cmd = "f()";
		else
			cmd = "bash";
		return vzctl_err(ret, eno, "Failed to exec %s", cmd);
	}

	if (param->std_in != NULL) {
		if (write(param->in_p[1], param->std_in, strlen(param->std_in)) < 0) {
			close(param->in_p[1]);
			param->in_p[1] = -1;
			if (errno == EPIPE)
				return env_wait(pid, timeout, NULL);
			return vzctl_err(VZCTL_E_EXEC, errno, "Failed to write to in pipe");
		}
		/* do not set STDIN_FILENO in select() */
		close(param->in_p[1]);
		param->in_p[1] = -1;
	}
	if (param->exec_mode == MODE_BASH_NOSTDIN) {
		close(param->in_p[1]);
		param->in_p[1] = -1;
	}
	/* The std processed by external handler */
	if (param->stdfd != NULL) {
		close(param->stdfd[0]);
		close(param->stdfd[1]);
		close(param->stdfd[2]);
		goto out;
	}

	initoutput();
	do {
		int n;
		fd_set rd_set;
	
		if (param->out_p[0] == -1 && param->err_p[0] == -1) {
			/* all fd are closed */
			close(param->in_p[1]);
			param->in_p[1] = -1;
			break;
		}
		FD_ZERO(&rd_set);
		if (param->in_p[1] != -1)
			FD_SET(STDIN_FILENO, &rd_set);
		if (param->out_p[0] != -1)
			FD_SET(param->out_p[0], &rd_set);
		if (param->err_p[0] != -1)
			FD_SET(param->err_p[0], &rd_set);

		n = select(FD_SETSIZE, &rd_set, NULL, NULL, NULL);
		if (n > 0) {
			if (param->out_p[0] != -1 && FD_ISSET(param->out_p[0], &rd_set))
				if (stdredir(param->out_p[0], STDOUT_FILENO, log) < 0) {
					close(param->out_p[0]);
					param->out_p[0] = -1;
				}
			if (param->err_p[0] != -1 && FD_ISSET(param->err_p[0], &rd_set))
				if (stdredir(param->err_p[0], STDERR_FILENO, log) < 0) {
					close(param->err_p[0]);
					param->err_p[0] = -1;
				}
			if (param->in_p[1] != -1 && FD_ISSET(STDIN_FILENO, &rd_set))
				if (stdredir(STDIN_FILENO, param->in_p[1], 0) < 0) {
					close(param->in_p[1]);
					param->in_p[1] = -1;
				}
		} else if (n < 0 && errno != EINTR) {
			logger(-1, errno, "Error in select()");
			close(param->out_p[0]); param->out_p[0] = -1;
			close(param->err_p[0]); param->err_p[0] = -1;
			break;
		}
	} while (param->out_p[0] != -1 || param->err_p[0] != -1);

	writeoutput(0);
out:

	return env_wait(pid, timeout, NULL);
}

static int do_env_exec(struct vzctl_env_handle *h, exec_mode_e exec_mode,
		char *const argv[], char *const envp[], char *std_in,
		execFn fn, void *data, int *data_fd, int timeout,
		int flags, int stdfd[3])
{
	int ret;
	pid_t pid;
	struct vzctl_cleanup_hook *hook;
	struct exec_param param = {
		.exec_mode = exec_mode,
		.argv = argv,
		.envp = envp,
		.std_in = std_in,
		.stdfd = stdfd,
		.fn = fn,
		.data = data,
		.data_fd = data_fd,
		.in_p = {-1, -1},
		.out_p = {-1, -1},
		.err_p = {-1, -1},
		.status_p = {-1, -1},
		.timeout = timeout,
	};


	if (is_enter_locked(h, flags))
		return VZCTL_E_LOCK;

	ret = real_env_exec_init(&param);
	if (ret)
		goto err;

	ret = get_env_ops()->env_exec(h, &param, flags, &pid);
	if (ret)
		goto err;

	hook = register_cleanup_hook(cleanup_kill_process, (void *) &pid);
	ret = real_env_exec_waiter(&param, pid, timeout, flags);

	unregister_cleanup_hook(hook);
err:
	real_env_exec_close(&param);

	return ret;
}

int real_env_exec_fn(struct vzctl_env_handle *h, execFn fn, void *data,
		int *data_fd, int timeout, int flags)
{
	int ret;

	_close_fds(data_fd != NULL ? VZCTL_CLOSE_STD : 0, data_fd);
	vzctl2_set_log_file(NULL);

	ret = fn(data);

	if (timeout) {
		alarm(0);
		s_timeout_pid = -1;
	}

	return ret;
}

static void set_proc_title(char *tty)
{
	char *p;

	p = tty;
	if (p != NULL && !strncmp(p, "/dev/", 5))
		p += 5;
	memset(_proc_title, 0, _proc_title_len);
	snprintf(_proc_title, _proc_title_len - 1, "vzctl: %s",
			p != NULL ? p : "");
}

static int pty_alloc(int *master, int *slave, struct termios *tios,
		struct winsize *ws)
{
	char name[PATH_MAX] = "";

	if (openpty(master, slave, name, tios, ws) < 0)
		return vzctl_err(-1, errno, "Unable to open pty");

	set_proc_title(name);

	return 0;
}

static void set_ctty(int ttyfd)
{
	int fd;

	if ((fd = open(DEV_TTY, O_RDWR | O_NOCTTY)) >= 0) {
		ioctl(fd, TIOCNOTTY, NULL);
		close(fd);
	}
	if (setsid() < 0)
		logger(-1, errno, "setsid");
	if (ioctl(ttyfd, TIOCSCTTY, NULL) < 0)
		logger(-1, errno, "Failed to connect to controlling tty");
	setpgrp();
}

static void raw_off(void)
{
        if (tcsetattr(0, TCSADRAIN, &_tios) == -1)
		logger(-1, errno, "Unable to restore term attr");
}

static void raw_on(void)
{
	struct termios tios;

	if (tcgetattr(0, &tios) == -1) {
		logger(-1, errno, "Unable to get term attr");
		return;
	}
	/* store original settings */
	memcpy(&_tios, &tios, sizeof(struct termios));
	cfmakeraw(&tios);
	if (tcsetattr(0, TCSADRAIN, &tios) == -1)
		logger(-1, errno, "Unable to set raw mode");
}

static int winchange(int info, int ptyfd)
{
	int ret;
	struct winsize ws;

	ret = read(info, &ws, sizeof(ws));
	if (ret < 0)
		return -1;
	else if (ret != sizeof(ws))
		return 0;
	ioctl(ptyfd, TIOCSWINSZ, &ws);
	return 0;
}

void redirect_loop(int r_in, int w_in,  int r_out, int w_out, int info)
{
	int n, fl = 0;
	fd_set rd_set;

	set_not_blk(r_in);
	set_not_blk(r_out);
	while (!child_exited) {
		/* Process SIGWINCH
		 * read winsize from stdin and send announce to the other end.
		 */
		if (win_changed) {
			struct winsize ws;

			if (!ioctl(r_in, TIOCGWINSZ, &ws))
				n = write(info, &ws, sizeof(ws));
			win_changed = 0;
		}
		FD_ZERO(&rd_set);
		if (!(fl & 1))
			FD_SET(r_in, &rd_set);
		if (!(fl & 2))
			FD_SET(r_out, &rd_set);
		if (!(fl & 4))
			FD_SET(info, &rd_set);

		n = select(FD_SETSIZE, &rd_set, NULL, NULL, NULL);
		if (n > 0) {
			if (FD_ISSET(r_in, &rd_set))
				if (stdredir(r_in, w_in, 0) < 0) {
					close(w_in);
					fl |= 1;
				}
			if (FD_ISSET(r_out, &rd_set))
				if (stdredir(r_out, w_out, 0) < 0) {
					close(r_out);
					fl |= 2;
					break;
				}
			if (FD_ISSET(info, &rd_set)) {
				if (winchange(info, w_in) < 0)
					fl |= 4;
			}
		} else if (n < 0 && errno != EINTR) {
			close(r_out);
			logger(-1, errno, "Error in select()");
			break;
		}
	}
	/* Flush fds */
	if (!(fl & 2))
		while (stdredir(r_out, w_out, 0) == 0);
}

static void preload_lib(void)
{
	/* Preload libnss */
	(void)getpwnam("root");
	endpwent();
	(void)getgrnam("root");
	endgrent();
}

static int env_exec_pty(struct vzctl_env_handle *h, int exec_mode,
		char *const argv[], char *const envp[], char *std_in,
		execFn fn, void *data, int *data_fd, int timeout, int flags)
{
	int pid, ret, status, raw_flag;
	int in[2] = {-1, -1};
	int out[2] = {-1, -1};
	int st[2] = {-1, -1};
	int info[2] = {-1, -1};
	struct sigaction act = {};
	int i;
	int fd_flags[2];

	for (i = 0; i < 2; i++) {
		fd_flags[i] = fcntl(i, F_GETFL);
		if (fd_flags[i] < 0)
			return vzctl_err(VZCTL_E_SYSTEM, errno,
					"Unable to get fd%d flags", i);
	}

	if (is_enter_locked(h, flags))
		return VZCTL_E_LOCK;

	if (pipe(in) < 0 || pipe(out) < 0 || pipe(st) < 0 || pipe(info) < 0) {
		ret = vzctl_err(VZCTL_E_PIPE, errno,  "Unable to create pipe");
		goto out;
	}

	preload_lib();
	act.sa_handler = SIG_IGN;
	act.sa_flags = 0;
	sigaction(SIGPIPE, &act, NULL);

	act.sa_handler = winchange_handler;
	sigaction(SIGWINCH, &act, NULL);

	ret = get_env_ops()->env_setluid(h);
	if (ret)
		goto out;

	if ((pid = fork()) < 0) {
		ret = vzctl_err(VZCTL_E_FORK, errno, "Cannot fork");
		goto out;
	} else if (pid == 0) {
		int master, slave;
		struct termios tios;
		struct winsize ws;

		/* get terminal settings from 0 */
		ioctl(0, TIOCGWINSZ, &ws);
		tcgetattr(0, &tios);
		close(in[1]); close(out[0]); close(st[0]); close(info[1]);
		fcntl(st[1], F_SETFD, FD_CLOEXEC);

		ret = get_env_ops()->env_enter(h, flags);
		if (ret)
			goto err;

		/* list of skipped fds -1 the end mark */
		close_fds(1, in[0], out[1], st[1], info[0], -1);
		dup2(out[1], 1);
		dup2(out[1], 2);

		if ((ret = pty_alloc(&master, &slave, &tios, &ws)))
			goto err;
		pid = fork();
		if (pid < 0) {
			ret = vzctl_err(VZCTL_E_FORK, errno, "Unable to fork");
			if (write(st[1], &ret, sizeof(ret)) == -1)
				logger(1, errno, "Failed write(st[1])");
			_exit(ret);
		} else if (pid == 0) {
			char prompt[128];
			char id[64];
			char buf[64];
			char *term;
			char *arg[] = {"-bash", NULL};
			char *env[] = {ENV_PATH,
				"HISTFILE=/dev/null",
				"USER=root", "HOME=/root", "LOGNAME=root",
				prompt,
				NULL, /* for TERM */
				NULL};
			close(master);
			set_ctty(slave);
			dup2(slave, 0);
			dup2(slave, 1);
			dup2(slave, 2);
			close(slave);
			close(in[0]); close(out[1]); close(st[1]); close(info[0]);
			snprintf(id, sizeof(id), "CT-%s", EID(h));
			snprintf(prompt, sizeof(prompt), "PS1=%s \\W\\$ ", id);

			act.sa_handler = SIG_DFL;
			sigaction(SIGPIPE, &act, NULL);
			sigaction(SIGWINCH, &act, NULL);

			if ((term = getenv("TERM")) != NULL) {
				snprintf(buf, sizeof(buf), "TERM=%s", term);
				env[sizeof(env)/sizeof(env[0]) - 2] = buf;
			}
			if (exec_mode == MODE_EXECFN) {
				ret = fn(data);
				_exit(ret);
			} else if (exec_mode == MODE_EXEC) {
				execvep(argv[0], argv,
						envp != NULL ? envp : envp_bash);
			} else {
				execve("/bin/bash",
						argv != NULL ? argv : arg,
						envp != NULL ? envp : env);
				execve("/bin/sh",
						argv != NULL ? argv : arg,
						envp != NULL ? envp : env);
			}
			logger(-1, errno, "enter failed: unable to exec bash");
			_exit(1);
		}
		close(slave);
		close(st[1]);
		redirect_loop(in[0], master, master, out[1], info[0]);
		ret = env_wait(pid, timeout, NULL);
		close(master);
		_exit(0);
err:
		if (write(st[1], &ret, sizeof(ret)) == -1)
			logger(-1, errno, "Failed write(st[1]");
		_exit(ret);
	}
	close(in[0]); in[0] = -1;
	close(out[1]); out[1] = -1;
	close(st[1]); st[1] = -1;
	close(info[0]); info[0] = -1;
	raw_flag = 0;
	/* wait for pts allocation */
	ret = read(st[0], &status, sizeof(status));
	if (!ret) {
		fprintf(stdout, "entered into CT %s\n", h->ctid);
		raw_on();
		raw_flag = 1;
		redirect_loop(fileno(stdin), in[1], out[0], fileno(stdout), info[1]);
	} else {
		logger(-1, 0, "enter into CT failed\n");
		set_not_blk(out[0]);
		while (stdredir(out[0], fileno(stdout), 0) == 0);
	}
	ret = env_wait(pid, timeout, NULL);
	if (raw_flag)
		raw_off();
	fprintf(stdout, "exited from CT %s\n", h->ctid);
out:

	for (i = 0; i < 2; i++)
		fcntl(i, F_SETFL, fd_flags[i]);

	p_close(in);
	p_close(out);
	p_close(st);
	p_close(info);

	return ret;
}

int vzctl2_env_exec_async(struct vzctl_env_handle *h, exec_mode_e exec_mode,
		char *const argv[], char *const envp[], char *std_in, int timeout,
		int flags, int stdfd[3], int *err)
{
	int pid, ret;

	if (!is_env_run(h)) {
		*err = vzctl_err(VZCTL_E_ENV_NOT_RUN, 0, "Container is not running");
		return -1;
	}

	if ((pid = fork()) < 0) {
		*err = vzctl_err(VZCTL_E_FORK, errno, "Cannot fork");
		return -1;
	} else if (pid == 0) {
		ret = do_env_exec(h, exec_mode, argv, envp, NULL,
			NULL, NULL, NULL, timeout, flags, stdfd);
		_exit(ret);
	}
	return pid;
}

int vzctl2_env_exec_wait(int pid, int *retcode)
{
	return env_wait(pid, 0, retcode);
}

int vzctl2_env_exec(struct vzctl_env_handle *h, exec_mode_e exec_mode,
		char *const argv[], char *const envp[], char *std_in, int timeout, int flags)
{
	if (!is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_NOT_RUN, 0, "Container is not running");

	return do_env_exec(h, exec_mode, argv, envp, std_in, NULL, NULL, NULL, timeout, flags, NULL);
}

static int do_env_exec_fn(struct vzctl_env_handle *h, execFn fn, void *data,
		int *data_fd, int timeout, int flags)
{
	pid_t pid;
	int ret;
	struct vzctl_cleanup_hook *hook;

	if (is_enter_locked(h, flags))
		return VZCTL_E_LOCK;

	ret = get_env_ops()->env_exec_fn(h, fn, data, data_fd, timeout, flags, &pid);
	if (ret)
		return ret;

	hook = register_cleanup_hook(cleanup_kill_process, (void *) &pid);
	ret = env_wait(pid, timeout, NULL);
	unregister_cleanup_hook(hook);

	return ret;
}

int vzctl_env_exec_fn(struct vzctl_env_handle *h, execFn fn, void *data,
		int timeout)
{
	if (!is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_NOT_RUN, 0, "Container is not running");

	return do_env_exec_fn(h, fn, data, NULL, timeout, 0);
}

int vzctl2_env_exec_fn2(struct vzctl_env_handle *h, execFn fn, void *data,
		int timeout, int flags)
{
	if (!is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_NOT_RUN, 0, "Container is not running");


	return do_env_exec_fn(h, fn, data, NULL, timeout, flags);
}

int vzctl2_env_exec_fn_async(struct vzctl_env_handle *h, execFn fn,
		void *data, int *data_fd, int timeout, int flags, int *err)
{
	int pid;

	if (!is_env_run(h)) {
		*err = vzctl_err(VZCTL_E_ENV_NOT_RUN, 0, "Container is not running");;
		return -1;
	}

	if (is_enter_locked(h, flags)) {
		*err = VZCTL_E_LOCK;
		return -1;
	}

	*err = get_env_ops()->env_exec_fn(h, fn, data, data_fd, timeout,
								flags, &pid);
	if (*err)
		return -1;

	return pid;
}

int vzctl2_env_enter(struct vzctl_env_handle *h)
{
	int pid, ret;

	if (!is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_NOT_RUN, 0, "Container is not running");

	if (get_env_ops()->get_feature() & F_SETLUID) {
		if ((pid = fork()) < 0) {
			return vzctl_err(VZCTL_E_FORK, errno, "Cannot fork");
		} else if (pid == 0) {
			ret = env_exec_pty(h, MODE_BASH, NULL, NULL, NULL,
					NULL, NULL, NULL, 0, 0);
			_exit(ret);
		}
		ret = env_wait(pid, 0, NULL);
	} else
		ret = env_exec_pty(h, MODE_BASH, NULL, NULL, NULL,
				NULL, NULL, NULL, 0, 0);

	return ret;
}

static char * const* make_bash_env(char * const *env)
{
	char **penv;
	int i, j, cnt = 0;

	for (i = 0; env != NULL && env[i] != NULL; i++)
		cnt++;
	for (i = 0; envp_bash[i] != NULL; i++)
		cnt++;

	penv = (char **)malloc((cnt + 1) * sizeof(char *));
	if (penv == NULL)
		return NULL;
	for (i = 0; env != NULL && env[i] != NULL; i++)
		penv[i] = env[i];
	for (j = 0; envp_bash[j] != NULL; j++)
		penv[i++] = envp_bash[j];
	penv[i] = NULL;

	return penv;
}

int vzctl2_env_exec_script(struct vzctl_env_handle *h,
		char *const argv[], char *const envp[], const char *fname,
		const char *inc, int timeout, int flags)
{
	int ret, len;
	char *script = NULL;
	char *const *_envp = NULL;

	if (!is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_NOT_RUN, 0, "Container is not running");

	logger(1, 0, "Running the script: %s flags=%d", fname, flags);
	if ((len = read_script(fname, inc, &script)) < 0)
		return VZCTL_E_NOSCRIPT;

	_envp = make_bash_env(envp);

	ret = do_env_exec(h, MODE_BASH_NOSTDIN, argv, _envp, script,
			NULL, NULL, NULL, 0, flags, NULL);

	free(script);
	free((void*)_envp);

	return ret;
}

int vzctl2_env_exec_action_script(struct vzctl_env_handle *h, const char *name,
		char *const env[], int timeout, int flags)
{
	int ret;
	const char *fname;

	ret = read_dist_actions(h);
	if (ret)
		return ret;

	fname = get_dist_action_script(h->dist_actions, name);
	if (fname == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0, "Action %s is not found",
				name);

	if (vzctl2_wrap_env_exec_vzscript(h, NULL, env, fname,
				VZCTL_SCRIPT_EXEC_TIMEOUT, EXEC_LOG_OUTPUT))
		return vzctl_err(VZCTL_E_ACTIONSCRIPT, 0,
				"Failed to exec action script %s", fname);

	return 0;
}

static int get_ar_size(char * const *a)
{
	int i = 0;

	if (a == NULL)
		return 0;
	while (a[i] != NULL) i++;

	return i;
}

char **build_arg(char **a, char *const *b)
{
	int nelem;
	char **ar;
	int i, j;

	nelem = get_ar_size(a) + get_ar_size(b);

	ar = malloc((nelem + 1) * sizeof(char *));
	if (ar == NULL)
		return NULL;
	i = 0;
	for (j = 0; a != NULL && a[j] != NULL; j++)
		ar[i++] = a[j];
	for (j = 0; b != NULL && b[j] != NULL; j++)
		ar[i++] = b[j];
	ar[i] = NULL;
	return ar;
}

static int do_wrap_env_exec_script(struct vzctl_env_handle *h,
	char *const argv[], char *const envp[], const char *fname,
	int timeout, int flags,  int use_vz_func, int *retcode)
{
	int pid;
	char *argv_param[8];
	char timeout_str[11];
	char flags_str[11];
	char **argv_new;
	char **envp_new;

	argv_param[0] = VZCTL_EXEC_WRAP_BIN;
	argv_param[1] = (h == NULL) ?  "" : EID(h);
	argv_param[2] = (char *)fname;
	argv_param[3] = "";
	snprintf(timeout_str, sizeof(timeout_str), "%d", timeout);
	argv_param[4] = timeout_str;
	argv_param[5] = use_vz_func ? "1" : "0";
	snprintf(flags_str, sizeof(flags_str), "%d", flags | EXEC_NOENV);
	argv_param[6] = flags_str;
	argv_param[7] = NULL;

	argv_new = build_arg(argv_param, argv);
	envp_new = build_arg(envp_bash, envp);
	if (argv_new == NULL || envp_new == NULL) {
		free(argv_new); free(envp_new);
		return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "malloc");
	}

	pid = vfork();
	if (pid == -1) {
		free(argv_new);
		free(envp_new);
		return vzctl_err(VZCTL_E_FORK, errno, "Cannot fork");
	} else if (pid == 0) {
		execvep(argv_new[0], argv_new, envp_new);
		vzctl_err(VZCTL_E_EXEC, errno, "failed to exec %s", argv_new[0]);
		_exit(-1);
	}
	free(argv_new);
	free(envp_new);

	return env_wait(pid, 0, retcode);
}

int vzctl2_wrap_env_exec_script(struct vzctl_env_handle *h,
	char *const argv[], char *const envp[], const char *fname,
	int timeout, int flags)
{
	return do_wrap_env_exec_script(h, argv, envp, fname, timeout, flags, 0, NULL);
}

int vzctl2_wrap_env_exec_vzscript(struct vzctl_env_handle *h,
	char *const argv[], char *const envp[], const char *fname,
	int timeout, int flags)
{
	if (vzctl2_get_flags() & VZCTL_FLAG_DONT_USE_WRAP)
		return vzctl2_env_exec_script(h, argv, envp,
				fname, DIST_FUNC, timeout, flags);
	return do_wrap_env_exec_script(h, argv, envp, fname,
			timeout, flags, 1, NULL);
}

int vzctl2_wrap_exec_script_rc(char *const argv[], char *const env[], int flags, int *retcode)
{
	return do_wrap_env_exec_script(NULL, argv, env, argv[0], 0, flags, 0, retcode);
}

int vzctl2_wrap_exec_script(char *const argv[], char *const env[], int flags)
{
	if (vzctl2_get_flags() & VZCTL_FLAG_DONT_USE_WRAP)
		return vzctl2_exec_script(argv, env, flags);
	return vzctl2_wrap_exec_script_rc(argv, env, flags, NULL);
}
