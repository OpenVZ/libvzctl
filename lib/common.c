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
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <grp.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/personality.h>
#include <sys/types.h>
#include <fcntl.h>
#include <poll.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sched.h>
#include <dirent.h>

#include "logger.h"
#include "vzerror.h"
#include "list.h"
#include "libvzctl.h"
#include "vztypes.h"
#include "util.h"
#include "readelf.h"
#include "cgroup.h"

void xfree(void *p)
{
        if (p != NULL) free(p);
}

int xstrdup(char **dst, const char *src)
{
	char *t;

	if (src == NULL || *dst == src)
		return 0;
	if ((t = strdup(src)) == NULL)
		return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "xstrdup");
	if (*dst != NULL)
		free(*dst);
	*dst = t;
	return 0;
}

void free_ar_str(char *ar[])
{
	char **p;

	for (p = ar; *p != NULL; p++) free(*p);
}

const char *find_ar_str(char *ar[], const char *str)
{
	for (; *ar != NULL; ar++)
		if (strcmp(*ar, str) == 0)
			return *ar;
	return NULL;
}


static void free_str_param(struct vzctl_str_param *p)
{
	free(p->str);
}

void free_str(list_head_t *head)
{
	struct vzctl_str_param *tmp, *it;

	if (list_empty(head))
		return;
	list_for_each_safe(it, tmp, head, list) {
		list_del(&it->list);
		free_str_param(it);
		free(it);
	}
	list_head_init(head);
}

struct vzctl_str_param *add_str_param(list_head_t *head, const char *str)
{
	struct vzctl_str_param *p;

	if ((p = malloc(sizeof(struct vzctl_str_param))) == NULL)
		goto err;
	if ((p->str = strdup(str)) == NULL) {
		free(p);
		goto err;
	}
	list_add_tail(&p->list, head);
	return p;
err:
	vzctl_err(-1, ENOMEM, "Unable to allocate memory");
	return NULL;
}


const struct vzctl_str_param *find_str(list_head_t *head, const char *str)
{
	struct vzctl_str_param *it;

	list_for_each(it, head, list) {
		if (!strcmp(it->str, str))
			return it;
	}
	return NULL;
}

int is_ip6(const char *ip)
{
	return (strchr(ip, ':') != NULL);
}

/*
	1 - exist
	0 - does't exist
	-1 - error
*/
int stat_file(const char *file)
{
	struct stat st;

	if (stat(file, &st)) {
		if (errno != ENOENT) {
			logger(-1, errno, "unable to stat %s", file);
			return -1;
		}
		return 0;
	}
	return 1;
}

int make_dir2(const char *path, mode_t mode, int full)
{
	char buf[4096];
	const char *ps, *p;
	int len;

	if (path == NULL)
		return 0;

	if (access(path, F_OK) == 0)
		return 0;

	ps = path + 1;
	while ((p = strchr(ps, '/'))) {
		len = p - path + 1;
		snprintf(buf, len, "%s", path);
		ps = p + 1;
		if (!stat_file(buf)) {
			if (mkdir(buf, mode) && errno != EEXIST)
				return vzctl_err(VZCTL_E_CREATE_DIR, errno,
					"Can't create directory %s", buf);
		}
	}
	if (!full)
		return 0;
	if (!stat_file(path)) {
		if (mkdir(path, mode) && errno != EEXIST)
			return vzctl_err(VZCTL_E_CREATE_DIR, errno,
				"Can't create directory %s", path);
	}
	return 0;
}

int make_dir(const char *path, int full)
{
	return make_dir2(path, 0700, full);
}

static const char *get_pidfile(const ctid_t ctid, const char *sfx, char *out)
{
	sprintf(out, VZCTL_VE_RUN_DIR "/%s.%s" , ctid, sfx);
	return out;
}

const char *get_init_pidfile(const ctid_t ctid, char *out)
{
	return get_pidfile(ctid, "init.pid", out);
}

const char *get_criu_pidfile(const ctid_t ctid, char *out)
{
	return get_pidfile(ctid, "criu.pid", out);
}

int write_init_pid(const ctid_t ctid, pid_t pid)
{
	int ret = 0;
	char path[PATH_MAX];
	FILE *fp;

	get_init_pidfile(ctid, path);

	logger(10, 0, "Write init pid=%d %s", pid, path);
	if ((ret = make_dir(path, 0)))
		return ret;

	if ((fp = fopen(path, "w")) == NULL)
		return vzctl_err(-1, errno, "Failed to create %s", path);

	if ((fprintf(fp, "%d", pid)) < 0)
		ret = vzctl_err(-1, 0, "Failed to write Container init pid");

	if (fclose(fp))
		return vzctl_err(-1, errno, "Failed to write pid %s", path);
	return ret;
}

int read_pid(const char *path, pid_t *pid)
{
	int ret = 0;
	FILE *fp;

	*pid = 0;
	if ((fp = fopen(path, "r")) == NULL) {
		if (errno != ENOENT)
			vzctl_err(-1, errno, "Unable to open %s", path);

		return -1;
	}

	if (fscanf(fp, "%d", pid) < 1)
		ret = vzctl_err(-1, 0, "Unable to read pid from %s", path);

	fclose(fp);
	return ret;
}

int read_init_pid(const ctid_t ctid, pid_t *pid)
{
	char path[PATH_MAX];

	get_init_pidfile(ctid, path);
	return read_pid(path, pid);
}

int clear_init_pid(const ctid_t ctid)
{
	char f[PATH_MAX];

	get_init_pidfile(ctid, f);

	if (remove(f) < 0 && errno != ENOENT)
		return vzctl_err(-1, 0, "Unable to clear Container init pid file: %s", f);

	return 0;
}

void strip_end(char *str)
{
	char *ep = str + strlen(str) - 1;

	while (ep >= str && (isspace(*ep) || *ep == '\n')) *ep-- = '\0';
}

static char *unescapestr(char *src)
{
	char *p1, *p2;
	int fl;

	if (src == NULL)
		return NULL;
	p2 = src;
	p1 = p2;
	fl = 0;
	while (*p2) {
		if (*p2 == '\\' && !fl)	{
			fl = 1;
			p2++;
		} else {
			*p1 = *p2;
	                p1++; p2++;
			fl = 0;
		}
	}
	*p1 = 0;

	return src;
}



/*
 *   man bash
 *  ...a word beginning with # causes that word and all remaining characters on that line to be
 *  ignored.
 */
char *uncommentstr(char * str)
{
        char * p1;
        int inb1 = 0, inb2 = 0, inw = 1;

        for (p1 = str; *p1; p1++) {
                if (inb1 && (*p1 != '\''))
                        continue;

                if (inb2 && (*p1 != '"'))
                        continue;

                switch(*p1) {
                case '\'':
                        inb1 ^= 1;
                        inw = 0;
                        break;
                case '"':
                        inb2 ^= 1;
                        inw = 0;
                        break;
                case '#':
                        if( !inw )
                                break;
                        *p1 = 0;
                        return str;
                default:
                        if(isspace(*p1))
                                inw = 1;
                        else
                                inw = 0;
                        break;
                }
        }

        return str;
}

char *parse_line(char *str, char *ltoken, int lsz)
{
	char *sp = str;
	char *ep, *p;
	int len;

	unescapestr(str);
	uncommentstr(str);
	while (*sp && isspace(*sp)) sp++;
	if (!*sp || *sp == '#')
		return NULL;

	strip_end(sp);

	ep = sp + strlen(sp) - 1;
	if (*ep == '"' || *ep == '\'')
		*ep = 0;
	if (!(p = strchr(sp, '=')))
		return NULL;
	len = p - sp;
	if (len >= lsz)
		return NULL;
	strncpy(ltoken, sp, len);
	ltoken[len] = 0;
	p++;
	if (*p == '"' || *p == '\'' )
		p++;

	return p;
}

int parse_int(const char *str, int *val)
{
	char *tail;
	long int n;

	if (*str == '\0')
		return 1;

	errno = 0;
	n = strtol(str, (char **)&tail, 10);
	if (*tail != '\0' || errno == ERANGE || n > INT_MAX)
		return 1;
	*val = (int)n;

	return 0;
}

int parse_ul(const char *str, unsigned long *val)
{
	char *tail;

	if (*str == '\0')
		return 1;

	errno = 0;
	*val = strtoul(str, (char **)&tail, 10);
	if (*tail != '\0' || errno == ERANGE)
		return 1;

	return 0;
}

void free_ip(list_head_t *head)
{
	struct vzctl_ip_param *tmp, *it;

	list_for_each_safe(it, tmp, head, list) {
		list_del(&it->list);
		free_ip_param(it);
	}
	list_head_init(head);
}

int get_ip_name(const char *ipstr, char *buf, int size)
{
	unsigned int addr[4];
	int family;

	family = get_netaddr(ipstr, addr);
	if (family == -1)
		return -1;
	inet_ntop(family, addr, buf, size);

	return 0;
}

static int get_net_family(const char *ip)
{
	return is_ip6(ip) ? AF_INET6 : AF_INET;
}

int get_netaddr(const char *ip, unsigned int *addr)
{
	int family = get_net_family(ip);

	if (inet_pton(family, ip, addr) <= 0)
		return vzctl_err(-1, errno, "An incorrect ip address %s", ip);
	return family;
}

void free_ip_param(struct vzctl_ip_param *ip)
{
	if (ip != NULL) {
		free(ip->ip);
		free(ip);
	}
}

const struct vzctl_ip_param *find_ip(list_head_t *head,
	struct vzctl_ip_param *ip)
{
	struct vzctl_ip_param *it;

	list_for_each(it, head, list) {
		if (!strcmp(it->ip, ip->ip))
			return it;
	}
	return NULL;
}

void add_ip_param2(list_head_t *head, struct vzctl_ip_param *ip)
{
	list_add_tail(&ip->list, head);
}

struct vzctl_ip_param *new_ip_param(const struct vzctl_ip_param *ip)
{
	struct vzctl_ip_param *new;

	if ((new = calloc(1, sizeof(struct vzctl_ip_param))) == NULL)
		return NULL;

	if (ip != NULL) {
		memcpy(new, ip, sizeof(struct vzctl_ip_param));
		new->ip = strdup(ip->ip);
	}
	return new;
}

struct vzctl_ip_param *add_ip_param(list_head_t *head,
		const struct vzctl_ip_param *ip)
{
	struct vzctl_ip_param *new;

	if ((new = new_ip_param(ip)) != NULL)
		list_add_tail(&new->list, head);
	return new;
}

struct vzctl_ip_param *add_ip_param_str(list_head_t *head, char *str)
{
	struct vzctl_ip_param tmp;

	bzero(&tmp, sizeof(struct vzctl_ip_param));
	tmp.ip = (char *)str;
	return add_ip_param(head, &tmp);
}

int copy_ip_param(list_head_t *dst, list_head_t *src)
{
	struct vzctl_ip_param *it;

	free_ip(dst);
	list_for_each(it, src, list) {
		if (add_ip_param(dst, it) == NULL)
			return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "add_ip_param");
	}
	return 0;
}

int set_personality(unsigned long mask)
{
	unsigned long per;

	per = personality(0xffffffff) | mask;
	logger(3, 0, "Set personality %#10.8lx", per);
	if (personality(per) == -1)
		return vzctl_err(VZCTL_E_SET_PERSONALITY, errno,
				"Unable to set personality");
	return 0;
}

int set_personality32(void)
{
#ifdef  __x86_64__
	if (get_arch_from_elf("/sbin/init") == elf_32)
		return set_personality(PER_LINUX32);
#endif
	return 0;
}

int reset_loginuid(void)
{
	int fd;
	static const char luid[] = "4294967295";

	logger(10, 0, "Reset loginuid");
	fd = open("/proc/self/loginuid", O_RDWR);
	if (fd == -1) {
		if (errno == ENOENT)
			return 0;
		return vzctl_err(-1, errno, "Cannot open /proc/self/loginuid");
	}

	if (write(fd, luid, sizeof(luid) -1) == -1) {
		vzctl_err(-1, errno, "Cannot reset loginuid");
		close(fd);

		return -1;
	}

	close(fd);

	return 0;
}

static int is_fd_in_list(int *fds, int fd)
{
	int i;

	if (fds == NULL)
		return 0;

	for (i = 0; fds[i] != -1; i++)
		if (fds[i] == fd)
			return 1;
	return 0;
}


static int proc_fd = -1;
int open_proc_fd()
{
	if (proc_fd == -1) {
		proc_fd = open("/proc", O_RDONLY);
		if (proc_fd == -1)
			vzctl_err(-1, errno, "Can not open /proc");
	}

	return proc_fd;
}

static int get_proc_fd()
{
	return proc_fd;
}

int _close_fds(int close_mode, int *skip_fds)
{
	int fd;
	struct stat st;
	char buf[STR_SIZE];
	struct dirent *ent;
	DIR *dir;

	if (close_mode & VZCTL_CLOSE_STD) {
		fd = open("/dev/null", O_RDWR);
		if (fd != -1) {
			dup2(fd, 0); dup2(fd, 1); dup2(fd, 2);
			close(fd);
		} else {
			close(0); close(1); close(2);
		}
	}

	fd = get_proc_fd();
	if (fd == -1)
		fd = open_proc_fd();

	snprintf(buf, sizeof(buf), "self/fd");
	fd = openat(fd, buf, O_RDONLY);
	if (fd == -1)
		return vzctl_err(VZCTL_E_SYSTEM, errno, "openat %s", buf);

	dir = fdopendir(fd);
	if (dir == NULL) {
		close(fd);
		return vzctl_err(VZCTL_E_SYSTEM, errno, "fdopendir %s", buf);
	}

	while ((ent = readdir(dir)) != NULL) {
		int f;
		if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
			continue;
		if (sscanf(ent->d_name, "%d", &f) != 1)
			continue;
		if (dirfd(dir) == f || f < 3)
			continue;
		if (is_fd_in_list(skip_fds, f)) {
			if ((close_mode & VZCTL_CLOSE_NOCHECK) ||
					(fstat(f, &st) == 0 &&
					 S_ISFIFO(st.st_mode)))
				continue;
		}
		close(f);
	}
	closedir(dir);

	return 0;
}

#define MAX_WAIT_TIMEOUT	60 * 30
volatile sig_atomic_t alarm_flag;
static void alarm_handler(int sig)
{
	alarm_flag = 1;
}

int wait_on_fifo(void *data)
{
	int fd, buf, ret;
	struct sigaction act, actold;

	ret = 0;
	alarm_flag = 0;
	act.sa_flags = 0;
	act.sa_handler = alarm_handler;
	sigemptyset(&act.sa_mask);
	sigaction(SIGALRM, &act, &actold);

	alarm(MAX_WAIT_TIMEOUT);
	fd = open(VZFIFO_FILE, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Unable to open " VZFIFO_FILE " %s\n",
			strerror(errno));
		ret = VZCTL_E_WAIT;
		goto err;
	}
	if (read(fd, &buf, sizeof(buf)) == -1)
		ret = VZCTL_E_WAIT;
err:
	if (alarm_flag)
		ret = VZCTL_E_TIMEOUT;
	alarm(0);
	sigaction(SIGALRM, &actold, NULL);
	unlink(VZFIFO_FILE);

	if (fd != -1)
		close(fd);

	return ret;
}



int env_wait(int pid, int timeout, int *retcode)
{
	int ret, status;

	while ((ret = waitpid(pid, &status, 0)) == -1)
		if (errno != EINTR)
			return vzctl_err(VZCTL_E_SYSTEM, errno,
					"Error in waitpid(%d)", pid);

	ret = VZCTL_E_SYSTEM;
	if (WIFEXITED(status)) {
		ret = WEXITSTATUS(status);
		if (retcode != NULL) {
			*retcode = ret;
			ret = 0;
		}
	} else if (WIFSIGNALED(status)) {
		logger(-1, 0, "Got signal %d", WTERMSIG(status));
		if (timeout && alarm_flag)
			return VZCTL_E_TIMEOUT;
	}

	return ret;
}

int set_ns(pid_t pid, const char *name, int flags)
{
        int ret, fd;
        char path[PATH_MAX];

        snprintf(path, sizeof(path), "/proc/%d/ns/%s", pid, name);
        if ((fd = open(path, O_RDONLY)) < 0)
                return vzctl_err(-1, errno, "Failed to open %s", path);

        logger(10, 0, "* attach to %s", name);
        ret = setns(fd, flags);
        if (ret)
                logger(-1, errno, "Failed to set context for %s", name);
        close(fd);

	return ret;
}

int env_enter(ctid_t ctid, int flags)
{
	DIR *dp;
	struct dirent *ep;
	pid_t pid;
	char path[PATH_MAX];
	int ret;

	if (open_proc_fd() == -1)
		return VZCTL_E_SYSTEM;

	ret = reset_loginuid();
	if (ret)
		return ret;

	if (cg_env_get_init_pid(ctid, &pid))
		return vzctl_err(VZCTL_E_SYSTEM, 0, "Unable to get init pid");

	logger(10, 0, "* Attach by pid %d", pid);

	snprintf(path, sizeof(path), "/proc/%d/ns", pid);
	dp = opendir(path);
	if (dp == NULL)
		return vzctl_err(-1, errno, "Unable to open dir %s", path);

	ret = cg_attach_task(ctid, getpid(), NULL);
	if (ret)
		goto err;

	while ((ep = readdir (dp))) {
		if (!strcmp(ep->d_name, ".") ||
		    !strcmp(ep->d_name, "..") ||
		    !strcmp(ep->d_name, "time") ||
		    !strcmp(ep->d_name, "time_for_children") ||
		    !strcmp(ep->d_name, "mnt"))
			continue;

		ret = set_ns(pid, ep->d_name, 0);
		if (ret)
			goto err;
	}

	ret = set_ns(pid, "mnt", 0);
	if (ret)
		goto err;

	/* Clear supplementary group IDs */
	if (setgroups(0, NULL)) {
		ret = vzctl_err(-1, errno, "ns_env_enter: setgroups()");
		goto err;
	}
	
	ret = set_personality32();

err:
	closedir(dp);

	return ret;
}

int is_ub_supported()
{
	return (access("/sys/fs/cgroup/beancounter", F_OK) == 0);
}
