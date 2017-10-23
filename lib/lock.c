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
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/param.h>
#include <signal.h>
#include <time.h>

#include "util.h"
#include "logger.h"
#include "vztypes.h"
#include "fs.h"
#include "config.h"
#include "cluster.h"
#include "vz.h"

#define VZCTL_ENTER_WAIT_TM     6
#define VZCTL_ENTER_LOCK_DIR    "/var/lock/vzctl/"

const char *get_enter_lock_fname(struct vzctl_env_handle *h, char *path, int size)
{
	snprintf(path, size, VZCTL_ENTER_LOCK_DIR"%s-enter.lck", EID(h));
	return path;
}

/*
 * Read pid id from lock file:
 * return: -1 read error
 * 	    0 incorrect pid
 * 	   >0 pid id
 */
static int getlockpid(char *file)
{
	int fd, pid = -1;
	char buf[STR_SIZE];
	int len;

	if ((fd = open(file, O_RDONLY)) == -1)
		return -1;
	if ((len = read(fd, buf, sizeof(buf) - 1)) >= 0) {
		buf[len] = 0;
		if (sscanf(buf, "%d", &pid) != 1) {
			logger(1, 0, "Incorrect process ID: %s in %s", buf, file);
			pid = 0;
		}
	}
	close(fd);

	return pid;
}

static const char *getcmdline(int pid, char *buf, int len)
{
	char fname[STR_SIZE];
	int fd, n;

	buf[0] = '\0';
	snprintf(fname, sizeof(fname), "/proc/%d/cmdline", pid);
	if ((fd = open(fname, O_RDONLY)) != -1) {
		n = read(fd, buf, len - 1);
		if (n != -1)
			buf[n -1] = '\0';

		close(fd);
	}

	return buf;
}

const char *get_dir_lock_file(const char *dir, char *buf, int size)
{
	snprintf(buf, size, "%s/.lck", dir);

	return buf;
}

/* Get lock file name wrapper
 * if lockfile id directory 'DIR' use the file 'DIR.lck'
 */
static const char *get_lock_file_wrap(const char *lockfile, char *buf, int size)
{
	struct stat st;

	if (stat(lockfile, &st) == 0 && S_ISDIR(st.st_mode))
		get_dir_lock_file(lockfile, buf, size);
	else
		snprintf(buf, size, "%s", lockfile);
	return buf;
}

static int _open_lock_file(const char *lockfile)
{
	int fd, i;
	char buf[PATH_MAX];

	get_lock_file_wrap(lockfile, buf, sizeof(buf));
	for (i = 0; i < 3; i++) {
		fd = open(buf, O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,
					S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
		if (fd == -1 && errno == EEXIST) {
			fd = open(buf, O_RDWR|O_CLOEXEC, 0);
			if (fd == -1 && errno == ENOENT)
				continue;
		}
		break;
	}

	if (fd == -1)
		return vzctl_err(-1, errno, "Unable to open the lock file %s", buf);
	logger(5, 0, "Lock %s fd=%d", buf, fd);

	return fd;
}

/** Lock VPS.
 * Create lock file $dir/$ctid.lck.
 * @param ctid		VPD id.
 * @param dir		lock directory.
 * @param status	transition status.
 * @return		0 - success
 *			1 - locked
 *			-1- error.
 */
static int _lock_file(const ctid_t ctid, char *dir, const char *status)
{
	int fd, pid;
	char buf[STR_SIZE];
	char lockfile[STR_SIZE];
	char tmp_file[STR_SIZE];
	struct stat st;
	int retry = 0;
	int ret = -1;

	if (check_var(dir, "lockdir is not set"))
		return -1;
	if (!stat_file(dir))
		if (make_dir(dir, 1))
			return -1;
	/* Create temp lock file */
	snprintf(lockfile, sizeof(lockfile), "%s/%s.lck", dir, ctid);
	logger(10, 0, "file lock %s", lockfile);
	snprintf(tmp_file, sizeof(tmp_file), "%sXXXXXX", lockfile);
	if ((fd = mkstemp(tmp_file)) < 0) {
		if (errno == EROFS)
			logger(-1, errno, "Unable to create"
				" the lock file %s, use the --skiplock option",
				tmp_file);
		else
			logger(-1, errno, "Unable to create the"
				" temporary lock file: %s", tmp_file);
		return -1;
	}
	snprintf(buf, sizeof(buf), "%d\n%s\n", getpid(),
		status == NULL ? "" : status);
	if (write(fd, buf, strlen(buf)) == -1)
		logger(-1, errno, "write %s", tmp_file);
	close(fd);
	while (retry < 3) {
		/* vps locked */
		if (!link(tmp_file, lockfile)) {
			ret = 0;
			break;
		}
		pid = getlockpid(lockfile);
		if (pid < 0) {
			/*  Error read pid id */
			usleep(500000);
		} else if (pid == 0) {
			/* incorrect pid, remove lock file */
			unlink(lockfile);
		} else {
			snprintf(buf, sizeof(buf), "/proc/%d", pid);
			if (!stat(buf, &st)) {
				char data[STR_SIZE];

				logger(-1, 0, "Locked info: pid=%d cmdline=%s",
						pid, getcmdline(pid, data, sizeof(data)));
				ret = -2;
				break;
			} else {
				logger(0, 0, "Removing the stale lock file %s",
						lockfile);
				unlink(lockfile);
			}
		}
		retry++;
	}
	unlink(tmp_file);
	return ret;
}

/** Unlock VPS.
 *
 * @param ctid		VPS id.
 * @param dir		lock directory.
 */
static void _unlock_file(const ctid_t ctid, char *dir)
{
	char lockfile[4096];

	if (dir) {
		snprintf(lockfile, sizeof(lockfile), "%s/%s.lck", dir, ctid);
		unlink(lockfile);
	}
}

static void timer_handler(int ino)
{
}

#define SEC_TO_NSEC(sec) ((clock_t)(sec) * 1000000000)
static clock_t get_cpu_time(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
		logger(-1, errno, "clock_gettime");
		return (clock_t)-1;
	}
	return SEC_TO_NSEC(ts.tv_sec) + ts.tv_nsec;
}

static int set_timer(timer_t *tid, clock_t *end, unsigned int timeout)
{
	struct sigevent sigev = {};
	struct itimerspec it = {};

	*end = get_cpu_time();
	if (*end == (clock_t)-1)
		return -1;
	*end += SEC_TO_NSEC(timeout);

	sigev.sigev_notify = SIGEV_SIGNAL;
	sigev.sigev_signo = SIGRTMIN;
	sigev.sigev_value.sival_ptr = tid;

	if (timer_create(CLOCK_MONOTONIC, &sigev, tid))
		return vzctl_err(-1, errno, "timer_create");

	it.it_value.tv_sec = timeout;
	it.it_value.tv_nsec = 0;

	if (timer_settime(*tid, 0, &it, NULL)) {
		timer_delete(*tid);
		return vzctl_err(-1, errno, "timer_settime");
	}
	return 0;
}

static int _lock_flock(int fd, int mode, int timeout)
{
	int op = 0;
	int r, _errno;
	timer_t tid;
	clock_t end = 0;
	struct sigaction osa;
	struct sigaction sa = {
		.sa_handler = timer_handler,
	};

	logger(10, 0, "flock lock");
	if (mode & VZCTL_LOCK_SH)
		op |= LOCK_SH;
	if (mode & VZCTL_LOCK_EX)
		op |= LOCK_EX;
	if (mode & VZCTL_LOCK_NB)
		op |= LOCK_NB;

	if (timeout) {
		sigaction(SIGRTMIN, &sa, &osa);
		if (set_timer(&tid, &end, timeout))
			goto err;
	}

	while ((r = flock(fd, op)) == -1) {
		_errno = errno;
		if (_errno != EINTR)
			break;
		if (timeout == 0 || get_cpu_time() < end)
			continue;
		_errno = EAGAIN;
		break;
	}

	if (timeout) {
		timer_delete(tid);
		sigaction(SIGRTMIN, &osa, NULL);
	}

	if (r != 0) {
		if (_errno == EAGAIN) {
			close(fd);
			return -2;
		} else {
			logger(-1, _errno, "Error in flock");
			goto err;
		}
	}
	return fd;

err:
	close(fd);
	return -1;
}

static int _lock_fcntl(int fd, int mode, unsigned int timeout)
{
	struct flock fl;
	int op = 0;
	int r, _errno;
	timer_t tid;
	clock_t end = 0;
	struct sigaction osa;
	struct sigaction sa = {
		.sa_handler = timer_handler,
	};

	logger(10, 0, "fcntl lock");
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0; /* until EOF */
	if (mode & VZCTL_LOCK_SH)
		op |= F_RDLCK;
	if (mode & VZCTL_LOCK_EX)
		op |= F_WRLCK;
	fl.l_type = op;

	if (mode & VZCTL_LOCK_NB) {
		if (fcntl(fd, F_GETLK, &fl)) {
			logger(-1, errno, "Unable to get lock information");
			goto err;
		}
		if (fl.l_type != F_UNLCK) {
			/* already locked */
			close(fd);
			return -2;
		}
		fl.l_type = op; /* restore l_type */
	}

	if (timeout) {
		sigaction(SIGRTMIN, &sa, &osa);
		if (set_timer(&tid, &end, timeout))
			goto err;
	}

	while ((r = fcntl(fd, F_SETLK, &fl)) == -1) {
		_errno = errno;
		if (_errno != EINTR)
			break;
		if (timeout == 0 || get_cpu_time() < end)
			continue;
		_errno = EAGAIN;
		break;
	}

	if (timeout) {
		timer_delete(tid);
		sigaction(SIGRTMIN, &osa, NULL);
	}

	if (r == -1) {
		logger(-1, errno, "Unable to lock the file");
		goto err;
	}

	return fd;

err:
	close(fd);
	return -1;
}

int vzctl2_lock(const char *lockfile, int mode, unsigned int timeout)
{
	int fd;

	if ((fd = _open_lock_file(lockfile)) == -1)
		return -1;

	return is_nfs(lockfile) ? _lock_fcntl(fd, mode, timeout) :
				_lock_flock(fd, mode, timeout);
}

void vzctl2_unlock(int fd, const char *lockfile)
{
	char buf[PATH_MAX];

	if (fd < 0)
		return;
	/* just close fd to unlock */
	close(fd);
	if (lockfile != NULL) {
		get_lock_file_wrap(lockfile, buf, sizeof(buf));
		logger(5, 0, "Unlock %s fd=%d", buf, fd);
		if (unlink(buf))
			logger(3, errno, "failed unlink %s", buf);
	} else
		logger(5, 0, "Unlock fd=%d", fd);
}

static int do_enter_lock(struct vzctl_env_handle *h, int mode)
{
	int fd;
	char fname[PATH_MAX];
	struct stat st;

	if (stat(VZCTL_ENTER_LOCK_DIR, &st)) {
		if (errno != ENOENT)
			return vzctl_err(-1, errno, "Failed to stat "VZCTL_ENTER_LOCK_DIR);
		if (mkdir(VZCTL_ENTER_LOCK_DIR, 0755) && errno != EEXIST)
			return vzctl_err(-1, errno, "failed to create "VZCTL_ENTER_LOCK_DIR);
	}

	get_enter_lock_fname(h, fname, sizeof(fname));
	fd = vzctl2_lock(fname, mode, VZCTL_ENTER_WAIT_TM);
	if (fd < 0)
		logger(-1, 0, "Unable to lock ENTER operation");

	return fd;
}

void release_enter_lock(int lockfd)
{
	if (lockfd >= 0)
		close(lockfd);
}

int get_enter_lock(struct vzctl_env_handle *h)
{
	return do_enter_lock(h, VZCTL_LOCK_EX);
}

int is_enter_locked(struct vzctl_env_handle *h)
{
	int fd;

	fd = do_enter_lock(h, VZCTL_LOCK_SH | VZCTL_LOCK_NB);
	if (fd < 0)
		return 1;

	release_enter_lock(fd);

	return 0;
}

int vzctl_env_conf_lock(struct vzctl_env_handle *h, int mode)
{
	int fd;
	char lockfile[PATH_MAX];

	get_env_conf_lockfile(h, lockfile, sizeof(lockfile));
	if ((fd = _open_lock_file(lockfile)) == -1)
		return -1;

	return _lock_flock(fd, mode, 0);
}

void vzctl_env_conf_unlock(int lckfd)
{
	if (lckfd != -1) {
		logger(5, 0, "Unlock conf fd=%d", lckfd);
		close(lckfd);
	}
}

int vzctl2_env_lock_prvt(const ctid_t ctid, const char *prvt, const char *status)
{
	int lckfd = -1;
	int ret;
	struct vzctl_conf_simple g_conf = {};

	if (vzctl_parse_conf_simple(ctid, GLOBAL_CFG, &g_conf))
		return -1;

	/* If Container private does not exist just lock with old schema */
	if (prvt && stat_file(prvt)) {
		lckfd = vzctl2_lock(prvt, VZCTL_LOCK_EX|VZCTL_LOCK_NB, 0);
		if (lckfd < 0) {
			vzctl_free_conf_simple(&g_conf);
			return lckfd;
		}
	}
	/* Lock with old locking schema */
	if ((ret = _lock_file(ctid, g_conf.lockdir, status))) {
		if (lckfd >= 0)
			vzctl2_unlock(lckfd, prvt);
		lckfd = -1;
	}
	vzctl_free_conf_simple(&g_conf);

	return lckfd > 0 ? lckfd : ret ;
}

/* Lock Container
 * For Container layout == 4 create lock file under VE_PRIVATE/.lck
 * and lock with old locking schema LOCKDIR/VEID.lck
 * @return:	> 0 file descriptor
 *		-1 locking error
 *		-2 Container locked
 */
int vzctl2_env_lock(struct vzctl_env_handle *h, const char *status)
{
	if (h == NULL)
		return vzctl_err(-1, 0, "Unable to lock CT: invalid handle");

	return vzctl2_env_lock_prvt(h->ctid, h->env_param->fs->ve_private, status);
}

void vzctl2_env_unlock_prvt(const ctid_t ctid, int lckfd, const char *prvt)
{
	struct vzctl_conf_simple g_conf;

	bzero(&g_conf, sizeof(struct vzctl_conf_simple));
	vzctl_parse_conf_simple(ctid, GLOBAL_CFG, &g_conf);
	if (lckfd > 0)
		vzctl2_unlock(lckfd, prvt);

	_unlock_file(ctid, g_conf.lockdir);
	vzctl_free_conf_simple(&g_conf);
}

void vzctl2_env_unlock(struct vzctl_env_handle *h, int lckfd)
{
	if (h == NULL)
		vzctl2_unlock(lckfd, NULL);
	else
		vzctl2_env_unlock_prvt(h->ctid, lckfd, NULL);
}


