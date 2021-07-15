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

#define _GNU_SOURCE
#include <sys/ioctl.h>
#include <linux/limits.h>
#include <sched.h>

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

enum {
	EXEC_MSG_TERMIOS,
	EXEC_MSG_WINSIZE,
};

struct exec_msg_hdr {
	int type;
};

struct exec_msg_data {
	union {
		struct termios tios;
		struct winsize ws;
	};
};

struct exec_msg {
	struct exec_msg_hdr hdr;
	struct exec_msg_data data;
};

#define DEV_TTY		"/dev/tty"
static struct termios _tios;

static volatile sig_atomic_t alarm_flag, child_exited, win_changed;
static __thread int s_timeout_pid;
static char _proc_title[PATH_MAX];
static int _proc_title_len = sizeof(_proc_title);

static char *envp_bash[] = {"HOME=/", "TERM=linux",
	ENV_PATH,
	"SHELL=/bin/bash",
	NULL, NULL};

static size_t get_msg_size(int type)
{
	switch (type) {
	case EXEC_MSG_TERMIOS:
		return sizeof(struct termios);
	case EXEC_MSG_WINSIZE:
		return sizeof(struct winsize);
	default:
		return -1;
	}
}

static int send_exec_msg(int fd, struct exec_msg *m)
{
	size_t n, size;

	n = TEMP_FAILURE_RETRY(write(fd, &m->hdr, sizeof(struct exec_msg_hdr)));
	if (n != sizeof(struct exec_msg_hdr))
		return vzctl_err(VZCTL_E_SYSTEM, errno, "Cannot write exec message header");

	size = get_msg_size(m->hdr.type);

	n = TEMP_FAILURE_RETRY(write(fd, &m->data, size));
	if (n != size)
		return vzctl_err(VZCTL_E_SYSTEM, errno, "Cannot write exec msg data");

	return 0;	
}

static int read_exec_msg(int fd, struct exec_msg *m)
{
	ssize_t n, size;

	n = TEMP_FAILURE_RETRY(read(fd, &m->hdr, sizeof(struct exec_msg_hdr)));
	if (n != sizeof(struct exec_msg_hdr))
		return vzctl_err(VZCTL_E_SYSTEM, errno, "Cannot read msg header ret: %lu", n);

	size = get_msg_size(m->hdr.type);

	n = TEMP_FAILURE_RETRY(read(fd, &m->data, size));
	if (n != size)
		return vzctl_err(VZCTL_E_SYSTEM, errno, "Cannot read exec msg data ret: %lu", n);

	return 0;
}

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

			if (envp)
				execve(partial, argv, envp);
			else
				execv(partial, argv);

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
int close_fds(int close_std, ...)
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
	return _close_fds(close_std, skip_fds);
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
	int i = 0;
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

	fcntl(param->status_p[1], F_SETFD, FD_CLOEXEC);
	skip_fds[i++] = param->status_p[1];
	skip_fds[i++] = -1;

	ret = _close_fds(0, skip_fds);
	if (ret)
		return ret;

	if (param->exec_mode == MODE_EXECFN) {
		close(param->status_p[1]);
		return param->fn(param->data);
	} else if (param->exec_mode == MODE_EXEC) {
		if (param->argv == NULL)
			return VZCTL_E_INVAL;

		sigaction(SIGPIPE, &act, NULL);
		if (flags & EXEC_NOENV) {
			execvep(param->argv[0], param->argv, NULL);
		} else {
			execvep(param->argv[0], param->argv,
				param->envp != NULL ? param->envp : envp_bash);
		}
		ret = -errno;
	} else {
		char *arg[] = {"bash", "-c", NULL, NULL};
		char *cmd;

		if (param->argv == NULL)
			arg[1] = NULL;
		else {
			cmd = arg2str(param->argv);
			if (cmd == NULL)
				return vzctl_err(-ENOMEM, ENOMEM, "real_env_exec malloc"); 
			arg[2] = cmd;
		}

		sigaction(SIGPIPE, &act, NULL);
		if (flags & EXEC_NOENV) {
			execv("/bin/bash", arg);
			execv("/bin/sh", arg);
		} else {
			execve("/bin/bash" , arg,
					param->envp != NULL ? param->envp : envp_bash);
			execve("/bin/sh", arg,
					param->envp != NULL ? param->envp : envp_bash);
		}
		free(arg[2]);
		ret = -errno;
	}

	return ret;
}

static int real_env_exec_waiter(struct exec_param *param, int timeout, int pid, int flags)
{
	struct vzctl_cleanup_hook *hook;
	int log = flags & EXEC_LOG_OUTPUT;
	int ret = 0;

	hook = register_cleanup_hook(cleanup_kill_process, (void *) &pid);
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

	/* The std processed by external handler */
	if (param->stdfd != NULL) {
		ret = 0;
		goto out;
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
	ret = env_wait(pid, timeout, NULL);
	unregister_cleanup_hook(hook);

	return ret;
}

static int do_env_exec(struct vzctl_env_handle *h, exec_mode_e exec_mode,
		char *const argv[], char *const envp[], char *std_in,
		execFn fn, void *data, int *data_fd, int timeout,
		int flags, int stdfd[3], int comm)
{
	int ret, pid;
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
		.comm = comm,
		.timeout = timeout,
	};

	if (!is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_NOT_RUN, 0, "Container is not running");

	if (is_enter_locked(h, flags))
		return VZCTL_E_LOCK;

	ret = real_env_exec_init(&param);
	if (ret)
		goto err;

	ret = get_env_ops()->env_exec(h, &param, flags, &pid);
	if (ret)
		goto err;

	ret = real_env_exec_waiter(&param, param.timeout, pid, flags);

err:
	real_env_exec_close(&param);

	return ret;
}

int real_env_exec_fn(struct vzctl_env_handle *h, execFn fn, void *data,
		int *data_fd, int timeout, int flags)
{
	int ret;

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
	struct exec_msg m;

	if (read_exec_msg(info, &m))
		return -1;
	if (m.hdr.type != EXEC_MSG_WINSIZE)
		return -1;

	ioctl(ptyfd, TIOCSWINSZ, &m.data.ws);

	return 0;
}

void redirect_loop(int r_in, int w_in,  int r_out, int w_out, int info)
{
	int n, fl = info == -1 ? 4 : 0;
	fd_set rd_set;

	set_not_blk(r_in);
	set_not_blk(r_out);
	while (!child_exited) {
		if (win_changed && !(fl & 4)) {
			struct exec_msg m = {.hdr.type = EXEC_MSG_WINSIZE};

			win_changed = 0;
			if (ioctl(r_in, TIOCGWINSZ, &m.data.ws))
				continue;
			send_exec_msg(info, &m);
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
			if (!(fl & 1) && FD_ISSET(r_in, &rd_set)) {
				if (stdredir(r_in, w_in, 0) < 0)
					fl |= 1;
			}
			if (!(fl & 2) && FD_ISSET(r_out, &rd_set))
				if (stdredir(r_out, w_out, 0) < 0) {
					fl |= 2;
					break;
				}
			if (!(fl & 4) && FD_ISSET(info, &rd_set)) {
				if (winchange(info, w_in) < 0)
					fl |= 4;
			}
		} else if (n < 0 && errno != EINTR) {
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

static int do_env_exec_pty(struct vzctl_env_handle *h, int exec_mode,
                char *const argv[], char *const envp[],
		struct termios *tios, struct winsize *ws, int fds[4], int flags)
{
	int ret, pid, status;
	int master, slave;
	int st[2] = {-1, -1};
	struct vzctl_cleanup_hook *hook;
	struct sigaction act = {};

	if (fds == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0, "fds is not set");

	act.sa_handler = SIG_DFL;
	sigaction(SIGWINCH, &act, NULL);

	preload_lib();
	set_not_blk(fds[0]);
	set_not_blk(fds[1]);

	ret = get_env_ops()->env_enter(h, flags);
	if (ret)
		return ret;

	ret = close_fds(VZCTL_CLOSE_NOCHECK, fds[0], fds[1], fds[3], -1);
	if (ret)
		return ret;

	if ((ret = pty_alloc(&master, &slave, tios, ws)))
		return ret;

	if (pipe2(st, O_CLOEXEC) < 0) {
		ret = vzctl_err(VZCTL_E_PIPE, errno,  "Unable to create pipe");
		goto err;
	}

	pid = fork();
	if (pid < 0) {
		ret = vzctl_err(VZCTL_E_FORK, errno, "Unable to fork");
		goto err;
	} else if (pid == 0) {
		char prompt[128];
		char id[64];
		char buf[64];
		char *term;
		char *arg[] = {"-bash", NULL};
		char *env[] = {ENV_PATH,
			"HISTFILE=/dev/null",
			"USER=root", "HOME=/root", "LOGNAME=root",
			prompt, NULL, /* for TERM */ NULL};
		set_ctty(slave);
		dup2(slave, 0);
		dup2(slave, 1);
		dup2(slave, 2);
		close_fds(0, -1);
		snprintf(id, sizeof(id), "CT-%s", EID(h));
		snprintf(prompt, sizeof(prompt), "PS1=%s \\W\\$ ", id);

		act.sa_handler = SIG_DFL;
		sigaction(SIGPIPE, &act, NULL);

		if ((term = getenv("TERM")) != NULL) {
			snprintf(buf, sizeof(buf), "TERM=%s", term);
			env[sizeof(env)/sizeof(env[0]) - 2] = buf;
		}
		execve("/bin/bash", argv != NULL ? argv : arg,
				envp != NULL ? envp : env);
		execve("/bin/sh", argv != NULL ? argv : arg,
				envp != NULL ? envp : env);
		logger(-1, errno, "enter failed: unable to exec bash");
		ret = 1;
		if (write(st[1], &ret, sizeof(ret)) != sizeof(ret))
			vzctl_err(0, errno, "do_env_exec_pty: can not write status");
		_exit(1);
	}
	close(slave);
	close(st[1]);
	st[1] = -1;
	hook = register_cleanup_hook(cleanup_kill_force, (void *) &pid);
	ret = read(st[0], &status, sizeof(status));
	if (ret == 0) {
		redirect_loop(fds[0], master, master, fds[1], fds[3]);
	} else {
		while (stdredir(master, fds[1], 0) == 0);
	}

	ret = env_wait(pid, 0, NULL);
	unregister_cleanup_hook(hook);
err:
	p_close(st);
	close(master);
	close(slave);

	return ret;
}

int vzctl2_env_exec_pty_priv(struct vzctl_env_handle *h, int exec_mode,
		char *const argv[], char *const envp[], int fds[4], int flags)
{
	int ret;
	struct sigaction act = {};
	struct exec_msg m;
	struct termios tios;
	struct winsize ws;

	act.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &act, NULL);

	ret = read_exec_msg(fds[3], &m);
	if (ret)
		return ret;
	memcpy(&tios, &m.data.tios, sizeof(tios));

	ret = read_exec_msg(fds[3], &m);
	if (ret)
		return ret;
	memcpy(&ws, &m.data.ws, sizeof(ws));

	return do_env_exec_pty(h, exec_mode, argv, envp, &tios, &ws, fds, flags);
}

int vzctl2_env_execve_priv(struct vzctl_env_handle *h, exec_mode_e exec_mode,
		char *const argv[], char *const envp[], int timeout,
		int stdfd[4], int flags)
{
	int comm = stdfd ? stdfd[3] : -1;

	return do_env_exec(h, exec_mode, argv, envp, NULL, NULL, NULL, NULL, timeout, flags, stdfd, comm);
}

int vzctl2_env_exec_wait(int pid, int *retcode)
{
	return env_wait(pid, 0, retcode);
}

int vzctl2_env_exec(struct vzctl_env_handle *h, exec_mode_e exec_mode,
		char *const argv[], char *const envp[], char *std_in, int timeout, int flags)
{
	return do_env_exec(h, exec_mode, argv, envp, std_in, NULL, NULL, NULL, timeout, flags, NULL, -1);
}

int do_env_exec_fn(struct vzctl_env_handle *h, execFn fn, void *data,
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
	int ret;
	struct termios tios;
	struct winsize ws;
	struct sigaction act = {};
	struct vzctl_cleanup_hook *hook;
	struct vzctl_exec_handle *exec = NULL;
	int fds[2];
	int in[2] = {-1. -1}, out[2] = {-1, -1};

	if (!is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_NOT_RUN, 0, "Container is not running");

	if (pipe2(in, O_CLOEXEC) || pipe2(out, O_CLOEXEC)) {
		p_close(in);
		p_close(out);
		return vzctl_err(VZCTL_E_PIPE, errno, "Unable to create pipe");
	}

	fds[0] = in[0];
	fds[1] = out[1];

	act.sa_handler = winchange_handler;
	sigaction(SIGWINCH, &act, NULL);

	/* get terminal settings from 0 */
	tcgetattr(0, &tios);
	ioctl(0, TIOCGWINSZ, &ws);

	ret = vzctl2_env_exec_pty(h, NULL, NULL, fds, &tios, &ws, &exec);
	close(in[0]);
	close(out[1]);
	if (ret)
		goto err;

	hook = register_cleanup_hook(cleanup_kill_process, (void *) &exec->pid);
	raw_on();
	redirect_loop(fileno(stdin), in[1], out[0], fileno(stdout), exec->comm[0]);
	unregister_cleanup_hook(hook);
	raw_off();

	ret = env_wait(exec->pid, 0, NULL);
err:
	close(in[1]);
	close(out[0]);

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
			NULL, NULL, NULL, 0, flags, NULL, -1);
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

static int do_wrap_env_exec(struct vzctl_env_handle *h,	char *const argv[],
		char *const envp[], int stdfd[3], exec_mode_e mode,
		struct vzctl_exec_handle *exec)
{
	char *argv_param[8];
	char stdfd_str[34] = "";
	char **argv_new;
	char **envp_new;

	argv_param[0] = VZCTL_EXEC_WRAP_BIN;
	argv_param[1] = EID(h);
	argv_param[2] = "";
	snprintf(stdfd_str, sizeof(stdfd_str), "%d:%d:%d:%d",
		stdfd[0], stdfd[1], stdfd[2], exec->comm[1]);
	argv_param[3] = stdfd_str;
	argv_param[4] = "0"; // timeout
	switch (mode) {
	default:
	case MODE_EXEC:
		argv_param[5] = "0";
		break;
	case MODE_BASH:
		argv_param[5] = "1";
		break;
	case MODE_TTY:
		argv_param[5] = "4";
		break;
	}
	
	argv_param[6] = "0";
	argv_param[7] = NULL;

	argv_new = build_arg(argv_param, argv);
	envp_new = build_arg(envp_bash, envp);
	if (argv_new == NULL || envp_new == NULL) {
		free(argv_new); free(envp_new);
		return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "malloc");
	}

	exec->pid = vfork();
	if (exec->pid == -1) {
		free(argv_new);
		free(envp_new);
		return vzctl_err(VZCTL_E_FORK, errno, "Cannot fork");
	} else if (exec->pid == 0) {
		drop_cloexec(stdfd[0], FD_CLOEXEC);
		drop_cloexec(stdfd[1], FD_CLOEXEC);
		drop_cloexec(stdfd[2], FD_CLOEXEC);
		drop_cloexec(exec->comm[1], FD_CLOEXEC);
		execve(argv_new[0], argv_new, envp_new);
		vzctl_err(VZCTL_E_EXEC, errno, "failed to exec %s", argv_new[0]);
		_exit(-1);
	}
	close(exec->comm[1]); exec->comm[1] = -1;

	free(argv_new);
	free(envp_new);

	return 0;
}

static int do_wrap_env_exec_script(struct vzctl_env_handle *h,
	char *const argv[], char *const envp[], const char *fname,
	int timeout, int flags, int use_vz_func)
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
		execve(argv_new[0], argv_new, envp_new);
		vzctl_err(VZCTL_E_EXEC, errno, "failed to exec %s", argv_new[0]);
		_exit(-1);
	}
	free(argv_new);
	free(envp_new);
	return env_wait(pid, timeout, NULL);
}

int vzctl2_wrap_env_exec_script(struct vzctl_env_handle *h,
		char *const argv[], char *const envp[], const char *fname,
		int timeout, int flags)
{

	if (vzctl2_get_flags() & VZCTL_FLAG_DONT_USE_WRAP)
		return vzctl2_env_exec_script(h, NULL, NULL, fname, 0,
				timeout, flags);
	return do_wrap_env_exec_script(h, argv, envp, fname, timeout, flags, 0);
}

int vzctl2_wrap_env_exec_vzscript(struct vzctl_env_handle *h,
	char *const argv[], char *const envp[], const char *fname,
	int timeout, int flags)
{
	if (vzctl2_get_flags() & VZCTL_FLAG_DONT_USE_WRAP)
		return vzctl2_env_exec_script(h, argv, envp,
				fname, DIST_FUNC, timeout, flags);
	return do_wrap_env_exec_script(h, argv, envp, fname, timeout, flags, 1);
}

int vzctl2_wrap_exec_script(char *const argv[], char *const env[], int flags)
{
	if (vzctl2_get_flags() & VZCTL_FLAG_DONT_USE_WRAP)
		return vzctl2_exec_script(argv, env, flags);
	return do_wrap_env_exec_script(NULL, argv, env, argv[0], 0, flags, 0);
}


static struct vzctl_exec_handle *alloc_exec_handle(void)
{
	struct vzctl_exec_handle *h;
	h = calloc(1, sizeof(struct vzctl_exec_handle *));
	if (h == NULL) {
		vzctl_err(VZCTL_E_NOMEM, ENOMEM, "alloc_exec_handle");
		return NULL;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, h->comm)) {
		vzctl_err(VZCTL_E_NOMEM, errno, "socketpair");
		free(h);
		return NULL;
	}

	return h;
}

void vzctl2_release_exec_handle(struct vzctl_exec_handle *exec)
{
	p_close(exec->comm);
	free(exec);
}

int vzctl2_env_execve(struct vzctl_env_handle *h, char *const argv[], char *const envp[],
		int stdfd[3], exec_mode_e mode, struct vzctl_exec_handle **exec)
{
	int ret, fds[3] = {-1, -1, -1};
	
	if (!is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_NOT_RUN, 0, "Container is not running");

	*exec = alloc_exec_handle();
	if (*exec == NULL)
		return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "alloc_exec_handle");

	ret = do_wrap_env_exec(h, argv, envp, stdfd ? stdfd : fds, mode, *exec);
	if (ret) {
		vzctl2_release_exec_handle(*exec);
		*exec = NULL;
	}

	return ret;
}

int vzctl2_env_waitpid(struct vzctl_exec_handle *exec, int nohang, int *status)
{
	int pid;

	while ((pid = waitpid(exec->pid, status, nohang ? WNOHANG : 0)) == -1)
		if (errno != EINTR)
			return vzctl_err(-1, errno, "Error in waitpid(%d)",
					exec->pid);
	if (pid == exec->pid)
		exec->exited = 1;

	return pid;
}

int vzctl2_env_exec_pty(struct vzctl_env_handle *h, char *const argv[], char *const envp[],
		int fds[2], struct termios *tios, struct winsize *ws,
		struct vzctl_exec_handle **exec)
{
	int ret;
	struct exec_msg m;
	int f[4] = {fds[0], fds[1], -1, -1};
	struct termios t = {
		.c_iflag = 0x6506,
		.c_oflag = OPOST|ONLCR,
		.c_cflag = 0xbf,
		.c_lflag = ISIG|ICANON|ECHO|ECHOE|ECHOK|ECHOCTL|ECHOKE,
		.c_cc = "\003\034\177\025\004\000\001\000\021\023\032\377\022\017\027\026\377",
	};

	if (fds == NULL || ws == NULL || exec == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0, "Invalid argument");

	if (!is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_NOT_RUN, 0, "Container is not running");

	if (is_enter_locked(h, 0))
		return vzctl_err(VZCTL_E_LOCK, 0, "ENTER is locked");

	*exec = alloc_exec_handle();
	if (*exec == NULL)
		return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "alloc_exec_handle");

	ret = do_wrap_env_exec(h, argv, envp, f, MODE_TTY, *exec);
	if (ret)
		goto err;

	m.hdr.type = EXEC_MSG_TERMIOS;
	memcpy(&m.data, tios ? tios : &t, sizeof(struct termios));
	ret = send_exec_msg((*exec)->comm[0], &m);
	if (ret)
		goto err;

	m.hdr.type = EXEC_MSG_WINSIZE;
	memcpy(&m.data, ws, sizeof(*ws));
	ret = send_exec_msg((*exec)->comm[0], &m);
	if (ret)
		goto err;
err:
	if (ret) {
		int status;

		vzctl2_env_exec_terminate(*exec);
		vzctl2_env_waitpid(*exec, 0, &status);

		vzctl2_release_exec_handle(*exec);
		*exec = NULL;
	}
		
	return ret;
}

void vzctl2_env_exec_terminate(struct vzctl_exec_handle *exec)
{
	if (exec->pid && !exec->exited)
		kill(exec->pid, SIGTERM);
}

int vzctl2_env_exec_set_winsize(struct vzctl_exec_handle *exec,
		struct winsize *ws)
{
	struct exec_msg m;

	m.hdr.type = EXEC_MSG_WINSIZE;
	memcpy(&m.data, ws, sizeof(struct winsize));

	return send_exec_msg(exec->comm[0], &m);
}

struct open_tty_pair_arg {
	struct vzctl_env_handle *h;
	struct vzctl_console *con;
};

int open_tty_pair(void *arg)
{
	struct open_tty_pair_arg *a = arg;
	struct vzctl_env_handle *h = a->h;
	int master_fd = -1, slave_fd = -1;
	int i;

	if (vzctl2_enter_mnt_ns(h)) {
		vzctl_err(-1, 0, "vzcon_start: Failed to enter containers mnt ns");
		return VZCTL_E_SYSTEM;
	}

	// handle the race with CT start
	for (i = 0; i < 30; i++) {
		master_fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
		if (master_fd == -1 && errno == ENOENT)
			sleep(1);
	}

	if (master_fd == -1) {
		vzctl_err(-1, errno, "vzcon_start: Failed to open /dev/ptmx");
		goto err;
	}

	if (grantpt(master_fd)) {
		vzctl_err(-1, errno, "vzcon_start: grantpt on /dev/ptmx failed");
		goto err;
	}
	if (unlockpt(master_fd)) {
		vzctl_err(-1, errno, "vzcon_start: unlockpt on /dev/ptmx failed");
		goto err;
	}

	if (ptsname_r(master_fd, a->con->tty_path, sizeof(a->con->tty_path))) {
		vzctl_err(-1, errno, "vzcon_start: ptsname_r on /dev/ptmx failed");
		goto err;
	}

	/*
	 * Although vzctl console side of pseudoterminal will perform io
	 * on master-side fd, we also need to open slave_fd to hold one
	 * last reference for it. If we don't do it, any other process
	 * that opens the slave-side part via /devpts/N path and then
	 * closes it, the pseudoterminal pipe gets' destroyed and further
	 * read/writes will result in EIO. We want to keep the pipe alive.
	 */
	slave_fd = open(a->con->tty_path, O_RDWR | O_NOCTTY);
	if (slave_fd == -1) {
		vzctl_err(-1, errno, "Failed to open %s",
				a->con->tty_path);
		goto err;
	}

	a->con->slave_fd = slave_fd;
	a->con->master_fd = master_fd;

	return 0;
err:
	if (master_fd != -1)
		close(master_fd);
	if (slave_fd != -1)
		close(slave_fd);
	return -1;
}

int call_in_child_process(int (*fn)(void *), void *arg)
{
	int status;
	pid_t pid;
	char child_stack[4096 * 10];

	/*
	 * Parent freezes till child exit, so child may use the same stack.
	 * No SIGCHLD flag, so it's not need to block signal.
	 */
	pid = clone(fn, child_stack + sizeof(child_stack), CLONE_VFORK | CLONE_VM | CLONE_FILES |
		    CLONE_SIGHAND, arg);
	if (pid == -1)
		return vzctl_err(VZCTL_E_SYSTEM,
			errno, "Failed to clone child process");

	errno = 0;
	if (waitpid(pid, &status, __WALL) != pid)
		return vzctl_err(VZCTL_E_SYSTEM, errno, "Failed to wait for child process");

	if (status)
		return vzctl_err(VZCTL_E_SYSTEM, errno, "Bad child exit status");

	return 0;
}

int vzctl2_console_start(struct vzctl_env_handle *h, struct vzctl_console *con)
{
	int ret = VZCTL_E_SYSTEM;
	char tty[256] = "";
	char term[64];
	char *env[] = {tty, term, NULL};
	char *p;
	struct open_tty_pair_arg open_arg = { h, con };

	if (!is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_NOT_RUN, 0, "Container is not running.");
	/*
	 * Explanation of why getgrnam is needed here:
	 * this process enters container's mnt namespace and opens /dev/ptmx,
	 * then it prepares a slave-end of pseudoterminal via grantpt/unlockpt.
	 * grantpt triggers lazy load of /lib64/libnss_systemd.so.2, already
	 * inside of a container's mnt namespace. libnss_systemd.so.2 will mmap
	 * itself into the process and will thus hold one extra reference to it's
	 * opened fd.
	 * Because /lib64/libnss_systemd.so.2 is a inode on a container's fs,
	 * it is not possible to unmount this fs until this process holds a
	 * reference to it.
	 * This code is exectute in vzctl console ..
	 * If 'vzctl stop' get's called while 'vzctl console', this extra ref
	 * will block ploop image unmount procedure until vzctl console gets
	 * killed.
	 *
	 * By adding getgrnam we force libnss_systemd.so.2 to be called on a
	 * host level filesystem.
	 */
	if (getgrnam(""))
		return vzctl_err(VZCTL_E_SYSTEM, errno, "vzcon_start: getgrnam() failed");

	if (call_in_child_process(open_tty_pair, &open_arg))
		return vzctl_err(VZCTL_E_SYSTEM, errno,
			"vzcon_start: Failed to open tty pair");

	snprintf(tty, sizeof(tty), "START_CONSOLE_ON_DEV=%s",
			con->tty_path + strlen("/dev/"));
	p = getenv("TERM");
	if (p)
		snprintf(term, sizeof(term), "TERM=%s", p);

	ret = vzctl2_env_exec_action_script(h, "SET_CONSOLE", env, 0, 0);
	if (ret) {
		vzctl_err(-1, errno, "vzcon_start: failed to start getty on %s",
				con->tty_path);
		return VZCTL_E_SYSTEM;
	}

	return 0;
}
