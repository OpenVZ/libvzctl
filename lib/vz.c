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
#include <ctype.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/statfs.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <libgen.h>
#include <netdb.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/utsname.h>

#include <linux/vzlist.h>
#include <linux/vzctl_netstat.h>
#include <ploop/libploop.h>
#include "vz.h"
#include "env.h"
#include "env_config.h"
#include "fs.h"
#include "config.h"
#include "util.h"
#include "logger.h"
#include "vztypes.h"
#include "vzerror.h"
#include "cluster.h"
#include "evt.h"
#include "util.h"
#include "image.h"
#include "env_ops.h"
#include "ha.h"
#include "cpt.h"
#include "exec.h"
#include "ha.h"
#include "disk.h"
#include "name.h"

#define PROC_VEINFO	"/proc/vz/veinfo"
static int _initialized = 0;
static unsigned int __global_flags;
static char _g_hostname[STR_SIZE];
static pthread_mutex_t _g_hostname_mtx = PTHREAD_MUTEX_INITIALIZER;
static int vzctl_check_owner_quiet(const char *ve_private, char *host,
		size_t hsize, char *ve_host, size_t ve_hsize);

unsigned int vzctl2_get_flags(void)
{
        return __global_flags;
}

void vzctl2_set_flags(unsigned int flags)
{
        __global_flags = flags;
}

void vzctl2_lib_close(void)
{
	if (_initialized)
		get_env_ops()->close();

	_initialized = 0;
}

int vzctl2_lib_init(void)
{
	int ret;

	if (_initialized)
		return 0;

	init_env_ops();
	if (get_env_ops()->open == NULL)
		return vzctl_err(VZCTL_E_BAD_KERNEL, 0,
				"Your kernel does not support working with virtual"
				" environments or necessary modules are not loaded");
	ret = get_env_ops()->open();
	if (ret)
		return ret;

	_initialized = 1;

	return 0;
}

vzctl_ids_t *vzctl2_alloc_env_ids(void)
{
	vzctl_ids_t *ids;

	ids = malloc(sizeof(*ids));
	if (ids == NULL) {
		logger(-1, ENOMEM, "vzctl2_alloc_env_ids");
		return NULL;
	}
	ids->size = 256;
	ids->ids = malloc(sizeof(*ids->ids) * ids->size);
	if (ids->ids == NULL) {
		logger(-1, ENOMEM, "vzctl2_alloc_env_ids");
		free(ids);
		return NULL;
	}
	return ids;
}

void vzctl2_free_env_ids(vzctl_ids_t *ctids)
{
	if (ctids->ids != NULL)
		free(ctids->ids);
	free(ctids);
}

static int add_eids(vzctl_ids_t *ctids, ctid_t ctid, unsigned cnt)
{
	void *t;

	if (cnt > ctids->size) {
		unsigned size = ctids->size + 100;

		t = realloc(ctids->ids, size * sizeof(ctid_t));
		if (t == NULL)
			return vzctl_err(-1, ENOMEM, "get_env_ids_proc");

		ctids->size = size;
		ctids->ids = t;
	}
	SET_CTID(ctids->ids[cnt - 1], ctid);

	return 0;
}

static int get_env_ids_proc(vzctl_ids_t *ctids)
{
	FILE *fp;
	char buf[256];
	int res, classid, nproc;
	int ret;
	ctid_t ctid, id;

	if ((fp = fopen(PROC_VEINFO, "r")) == NULL)
		return vzctl_err(-2, errno, "Unabel to open" PROC_VEINFO);

	ret = 0;
	while (1) {
		if (fgets(buf, sizeof(buf), fp) == NULL) {
			if (!feof(fp))
				ret = -1;
			break;
		}

		res = sscanf(buf, "%37s %d %d", id, &classid, &nproc);
		if (res != 3 || vzctl2_parse_ctid(id, ctid) || !strcmp(id, "0"))
			continue;

		if (add_eids(ctids, ctid, ++ret)) {
			ret = -1;
			break;
		}
	}
	fclose(fp);
	return ret;
}

static int get_env_ids_running(vzctl_ids_t *ctids)
{
	return get_env_ids_proc(ctids);
}


#if 0
static int u32_sort(const void *p1, const void *p2)
{
        return (*(const unsigned int *) p1 > *(const unsigned int *) p2);
}

static int get_all_env_ids(vzctl_ids_t *ids)
{
	DIR *dir;
	struct dirent *ent;
	unsigned veid, *tmp;
	int cnt, size;
	char *p;

	if ((dir = opendir(VZ_ENV_CONF_DIR)) == NULL)
		return 0;
	cnt = 0;
	while ((ent = readdir(dir)) != NULL) {
		if ((p = strrchr(ent->d_name, '.')) == NULL)
			continue;
		if (strcmp(p, ".conf"))
			continue;
		if (sscanf(ent->d_name, "%u.conf", &veid) != 1)
			continue;
		if (cnt == ids->size) {
			size = ids->size + 1;
			tmp = realloc(ids->ids,
					size * sizeof(unsigned));
			if (tmp == NULL) {
				logger(-1, ENOMEM, "get_env_ids_proc");
				cnt = -1;
				break;
			}
			ids->size = size;
			ids->ids = tmp;
		}
		ids->ids[cnt++] = veid;
	}
	closedir(dir);

	if (cnt != 0)
		qsort(ids->ids, cnt, sizeof(unsigned int), u32_sort);

	return cnt;
}
#endif

static int get_env_ids_exists(vzctl_ids_t *ctids)
{
	DIR *dir;
	struct dirent *ent;
	int cnt;
	char path[512];
	struct vzctl_conf_simple g_conf, l_conf;

	if (vzctl_parse_conf_simple(0, GLOBAL_CFG, &g_conf))
		return 0;
	if ((dir = opendir(VZ_ENV_CONF_DIR)) == NULL)
		return 0;
	cnt = 0;
	while ((ent = readdir(dir)) != NULL) {
		ctid_t id, ctid = {};
		char str[6];

		if (sscanf(ent->d_name, "%37[^.].%5s", id, str) != 2 ||
				strcmp(str, "conf"))
			continue;

		if (vzctl2_parse_ctid(id, ctid))
			continue;

		vzctl2_get_env_conf_path(ctid, path, sizeof(path));
		if (vzctl_parse_conf_simple(ctid, path, &l_conf) == 0) {
			char ve_host[STR_SIZE] = "";
			char host[STR_SIZE] = "";

			if (l_conf.ve_private == NULL) {
				l_conf.ve_private = subst_VEID(ctid,
							g_conf.ve_private_orig);
			}
			if (l_conf.ve_private == NULL ||
					stat_file(l_conf.ve_private) != 1)
				continue;

			if (vzctl_check_owner_quiet(l_conf.ve_private, host,
					sizeof(host), ve_host, sizeof(ve_host)))
				continue;

			if (add_eids(ctids, ctid, ++cnt)) {
				cnt = -1;
				break;
			}
		}
		vzctl_free_conf_simple(&l_conf);
	}
	vzctl_free_conf_simple(&g_conf);
	closedir(dir);

	return cnt;
}

int vzctl2_get_env_ids_by_state(vzctl_ids_t *ctids, unsigned int mask)
{
	int ret = -1;

	if (mask & ENV_STATUS_EXISTS)
		ret = get_env_ids_exists(ctids);
	else if (mask & ENV_STATUS_RUNNING)
		ret = get_env_ids_running(ctids);
	return ret;
}

int vzctl2_env_is_mounted(struct vzctl_env_handle *h)
{
	const char *ve_private = h->env_param->fs->ve_private;
	const char *target = h->env_param->fs->ve_root;

	if (ve_private != NULL) {
		int layout = vzctl2_env_layout_version(ve_private);

		if (layout == VZCTL_LAYOUT_5) {
			struct vzctl_disk *d = find_root_disk(h->env_param->disk);

			if (d != NULL && !d->use_device)
				return vzctl2_is_image_mounted(d->path);

		} else if (layout == VZCTL_LAYOUT_4) {
			int ret;
			ret = get_bindmnt_target(h->env_param->fs->ve_private_fs, NULL, 0);
			return ret == -1 ? -1 : !ret;
		}
	}

	return fs_is_mounted_check_by_target(target);
}

static void read_env_transition(ctid_t ctid, char *lockdir, char *str, int sz)
{
	char buf[PATH_MAX];
	int fd, len;
	char *p, *ep;

	if (lockdir == NULL)
		return;
	snprintf(buf, sizeof(buf), "%s/%s.lck", lockdir, ctid);
	if (stat_file(buf) != 1)
		return;
	if ((fd = open(buf, O_RDONLY)) < 0)
		return;
	len = read(fd, buf, sizeof(buf));
	close(fd);
	if (len < 0 || len >= sizeof(buf))
		return;
	buf[len] = 0;
	/* skip pid */
	p = strchr(buf, '\n');
	if (p == NULL)
		return;
	p++;
	ep = strchr(p, '\n');
	if (ep == NULL)
		ep = buf + len;
	*ep = 0;
	len = ep - p + 1;
	snprintf(str, len > sz ? sz : len, "%s", p);
	return;
}

/** Get vz service status
 * 1 - running
 * 0 - stopped
 * -1- error
 */
int vzctl2_vz_status(void)
{
	int ret;
	struct utsname u;

	uname(&u);
	if (kver_cmp(u.release, "3.9") >= 0)
		return 1;

	/* Check /proc/vz/veinfo & /proc/vz/venetstat exists
	 * Fixme: try to find more correct way
	 */
	if ((ret = stat_file("/proc/vz/veinfo")) != 1)
		return ret;
	return 1;
}

int vzctl2_get_env_status_info(struct vzctl_env_handle *h,
		vzctl_env_status_t *status, int mask)
{
	int ret, exists = 0;
	char path[512];
	const char *ve_private = h->env_param->fs->ve_private;
	const char *ve_root = h->env_param->fs->ve_root;

	memset(status, 0, sizeof(vzctl_env_status_t));

	/* get running state */
	if (mask & ENV_STATUS_RUNNING) {
		if (is_env_run(h) == 1) {
			status->mask |= ENV_STATUS_RUNNING;
			get_env_ops()->env_get_cpt_state(h, &status->mask);
		}
	}
	/* do exit if only running status requested */
	if (mask == ENV_STATUS_RUNNING)
		return 0;

	if ((ret = check_var(ve_private, "VE_PRIVATE not set")))
		return ret;

	vzctl2_get_env_conf_path(EID(h), path, sizeof(path));
	if (stat_file(path) == 1 && stat_file(ve_private) == 1) {
		if (mask & ENV_SKIP_OWNER)
			exists = 1;
		else if (vzctl2_check_owner(ve_private) == 0)
			exists = 1;
	}

	if ((mask & ENV_STATUS_EXISTS) && exists)
		status->mask |= ENV_STATUS_EXISTS;

	/* get mounted state */
	if (mask & (ENV_STATUS_MOUNTED | ENV_STATUS_MOUNTED_FAST) && exists) {
		if ((ret = check_var(ve_root, "VE_ROOT not set")))
			return ret;
		ret = (mask & ENV_STATUS_MOUNTED) ? vzctl2_env_is_mounted(h) :
					 fs_is_mounted_check_by_target(ve_root);
		if (ret == 1)
			status->mask |= ENV_STATUS_MOUNTED;
	}
	/* get suspended state */
	if ((mask & ENV_STATUS_SUSPENDED) && exists && !(status->mask & ENV_STATUS_RUNNING)) {
		vzctl2_get_dump_file(h, path, sizeof(path));
		if (stat_file(path) == 1)
			status->mask |= ENV_STATUS_SUSPENDED;
	}
	read_env_transition(EID(h), h->env_param->opts->lockdir,
			status->transition, sizeof(status->transition));

	return 0;
}

int vzctl2_get_env_status(const ctid_t ctid, vzctl_env_status_t *status, int mask)
{
	char path[STR_SIZE];
	int ret;
	struct vzctl_env_handle *h;
	ctid_t id;
	int flags = mask == ENV_STATUS_RUNNING ? VZCTL_CONF_SKIP_PARSE : 0;

	if (vzctl2_parse_ctid(ctid, id))
		return vzctl_err(VZCTL_E_INVAL, 0, "Invalid CTID: %s", ctid);

	memset(status, 0, sizeof(struct vzctl_env_status));

	vzctl2_get_env_conf_path(id, path, sizeof(path));
	if (stat_file(path) == 0)
		return 0;

	h = vzctl2_env_open(ctid, flags, &ret);
	if (h == NULL)
		return ret;

	ret = vzctl2_get_env_status_info(h, status, mask);

	vzctl2_env_close(h);

	return ret;
}

/** Get id by name and check VEID.conf consistensy with name
 *
 * @param name		Container name in UTF8 encoding.
 * @param ctid		return CTID.
 * @return		-1 if no name or conflict.
 */
int vzctl2_get_envid_by_name(const char *name, ctid_t ctid)
{
	char buf[PATH_MAX];
	int rc;
	int id_by_ctid = 0;
	const char *id = NULL;
	struct vzctl_env_handle *h;

	/* 1. /etc/vz/conf/CTID.conf */
	if (vzctl2_parse_ctid(name, ctid) == 0) {
		vzctl2_get_env_conf_path(ctid, buf, sizeof(buf));
		rc = stat_file(buf);
		if (rc == -1)
			return -1;
		else if (rc == 1)
			id_by_ctid = 1;
	}

	/* 2. /etc/vz/name/name */
	snprintf(buf, sizeof(buf), ENV_NAME_DIR "%s", name);
	rc = stat_file(buf);
	if (rc == -1)
		return -1;
	else if (rc == 0) 
		return id_by_ctid ? 0 : -1;

	h = vzctl2_env_open_conf(NULL, buf, VZCTL_CONF_SKIP_GLOBAL, &rc);
	if (h == NULL)
		return -1;

	/* get CTID from VEID variable */
	rc = -1;
	if (h->env_param->name->name == NULL ||
			strcmp(h->env_param->name->name, name))
		goto err;

	vzctl2_env_get_param(h, "VEID", &id);
	if (vzctl2_parse_ctid(id, ctid)) {
		logger(-1, 0, "Unable to get ctid by name %s: "
				"invalid VEID=%s", name, id);
		goto err;
	} 

	/* Return ctid by name unconditionally
	 * Ignore id_by_ctid result
	 */
	rc = 0;

err:
	vzctl2_env_close(h);

	return rc;
}

int vzctl2_env_layout_version(const char *path)
{
	char buf[STR_SIZE];
	char ver[16];
	int id;
	struct stat st;

	if (path == NULL)
		return 0;

	snprintf(buf, sizeof(buf), "%s/" VZCTL_VE_LAYOUT, path);
	if (lstat(buf, &st) == -1) {
		if (errno != ENOENT)
			return vzctl_err(-1, errno, "Unable to get the"
				" Container layout: failed to stat %s", buf);

		if (stat(path, &st) && errno != ENOENT)
			return vzctl_err(-1, errno, "Unable to stat %s", path);

		return 0;
	}
	if (!S_ISLNK(st.st_mode))
		return 0;
	id = readlink(buf, ver, sizeof(ver));
	if (id < 0 || id >= sizeof(ver))
		return vzctl_err(-1, errno, "Error reading Ct layout version from %s",
				buf);
	ver[id] = 0;

	if (sscanf(ver, "%d", &id) != 1)
		return vzctl_err(-1, 0, "Unknown VZFS version (%s)", ver);

	return id;
}

int read_service_name(char *path, char *service_name, int size)
{
	char buf[4096];
	char *p;
	int fd, len;

	snprintf(buf, sizeof(buf), "%s/" VZCTL_VE_CLUSTER_SERVICE_NAME, path);
	if (stat_file(buf) == 0) {
		service_name[0] = 0;
		return 0;
	}
	if ((fd = open(buf, O_RDONLY)) == -1) {
		logger(-1, errno, "Unable to open %s", buf);
		return -1;
	}
	len = read(fd, service_name, size - 1);
	close(fd);
	if (len == -1) {
		logger(-1, errno, "Unable to read from %s", buf);
		return -1;
	}

	service_name[len] = 0;
	if ((p = strrchr(buf, '\n')) != NULL)
		*p = 0;

	return 0;
}

static int get_hostname(char *out, int len)
{
	struct hostent *he;
	char buf[STR_SIZE];

	if (gethostname(buf, sizeof(buf) - 1))
		return vzctl_err(-1, errno, "get_hostname function returned error");

	pthread_mutex_lock(&_g_hostname_mtx);
	if (strncmp(_g_hostname, buf, strlen(buf))) {
		he = gethostbyname(buf);
		if (he != NULL)
			snprintf(_g_hostname, sizeof(_g_hostname), "%s", he->h_name);
		else if (strrchr(buf, '.'))
			snprintf(_g_hostname, sizeof(_g_hostname), "%s", buf);
		else {
			/* use name from gethostname() as is, not cached */
			snprintf(out, len, "%s", buf);
			goto out;
		}
	}
	snprintf(out, len, "%s", _g_hostname);
out:
	pthread_mutex_unlock(&_g_hostname_mtx);

	return 0;
}

static int get_serverid(char *out, int len)
{
	get_global_param("SERVER_UUID", out, len);
	if (out[0] != '\0')
		return 0;

	return get_hostname(out, len);
}

#define START_ID	101

void vzctl2_unlock_envid(unsigned veid)
{
	char lckfile[STR_SIZE];

	snprintf(lckfile, sizeof(lckfile), VZ_ENV_CONF_DIR "%d.conf.lck", veid);
	unlink(lckfile);
}

static int is_dst_free(const char *dst, ctid_t ctid, int *fail_cnt)
{
	char *ve_private;
	int ret;

	if (dst == NULL)
		return 1;

	ve_private = subst_VEID(ctid, dst);

	ret = stat_file(ve_private);
	free(ve_private);
	if (ret == -1)
		(*fail_cnt)++;

	return (ret == 0 ? 1 : 0);
}

#define GET_FREE_ENVID_FAIL_MAX	12
int vzctl2_get_free_envid(unsigned *neweid, const char *dst,
		const char *unused)
{
	int i;
	struct vzctl_conf_simple conf;
	char file[STR_SIZE];
	char lckfile[STR_SIZE];
	char dstlck[PATH_MAX];
	struct stat st;
	int check_ve_private = 0;
	int check_ve_root = 0;
	int check_dst = 0;
	int fail_cnt = 0;
	int fd;
	ctid_t ctid = {};

	vzctl_parse_conf_simple(ctid, GLOBAL_CFG, &conf);

	if (conf.ve_private_orig != NULL && strstr(conf.ve_private_orig, "$VEID"))
		check_ve_private = 1;
	if (conf.ve_root_orig != NULL && strstr(conf.ve_root_orig, "$VEID"))
		check_ve_root = 1;
	if (dst != NULL && strstr(dst, "$VEID")) {
		snprintf(dstlck, sizeof(dstlck), "%s.lck", dst);
		check_dst = 1;
	}

	*neweid = 0;
	for (i = START_ID; i < INT_MAX/2 && fail_cnt < GET_FREE_ENVID_FAIL_MAX; i++) {
		ctid_t ctid = {i, };
		/* Check for VEID.conf */
		vzctl2_get_env_conf_path(ctid, file, sizeof(file));
		if (lstat(file, &st)) {
			if (errno != ENOENT) {
				logger(-1, errno, "Failed to stat %s", file);
				fail_cnt++;
				continue;
			}
		} else
			continue;
		/* lock envid */
		snprintf(lckfile, sizeof(lckfile), "%s.lck", file);
		fd = open(lckfile, O_CREAT|O_EXCL, 0644);
		if (fd == -1) {
			if (errno != EEXIST) {
				fail_cnt++;
				logger(-1, errno, "Failed to create %s", lckfile);
			}
			continue;
		}
		close(fd);

		/* check if PATH(s) exist */
		if ((check_ve_private && !is_dst_free(conf.ve_private_orig, ctid, &fail_cnt)) ||
		    (check_ve_root && !is_dst_free(conf.ve_root_orig, ctid, &fail_cnt)) ||
		    (check_dst &&
			(!is_dst_free(dst, ctid, &fail_cnt) || !is_dst_free(dstlck, ctid, &fail_cnt))))
		{
			/* unlock envid */
			unlink(lckfile);
			continue;
		}
		*neweid = i;
		break;
	}
	vzctl_free_conf_simple(&conf);

	if (*neweid == 0)
		return vzctl_err(-1, 0,  "Failed to get unused Countainer id");

	return 0;
}

int vzctl2_get_free_env_id(unsigned *neweid)
{
	return vzctl2_get_free_envid(neweid, NULL, NULL);
}

static int vzctl_check_owner_quiet(const char *ve_private, char *serverid,
		size_t size, char *ve_ownerid, size_t ve_size)
{
	char file[PATH_MAX];
	char *p;
	int len;
	FILE *fp;
	int ret;

	ret = is_shared_fs(ve_private);
	if (ret == -1) {
		if (errno == ENOENT)
			return 0;
		return VZCTL_E_SYSTEM;
	} else if (ret == 0)
		return 0;

	snprintf(file, sizeof(file), "%s/" VZCTL_VE_OWNER, ve_private);
	if ((fp = fopen(file, "r")) == NULL) {
		/* CT is not registered */
		if (errno == ENOENT)
			return 0;

		return vzctl_err(VZCTL_E_SYSTEM, errno,
			"Owner check failed, unable open file %s", file);
	}
	len = TEMP_FAILURE_RETRY(fread(ve_ownerid, 1, ve_size - 1, fp));
	fclose(fp);
	if (len == -1) {
		return vzctl_err(VZCTL_E_SYSTEM, errno,
			"Unable to read owner from %s", file);
	}
	ve_ownerid[len] = '\0';
	if ((p = strchr(ve_ownerid, '\n')) != NULL)
		*p = 0;

	if (vzctl2_get_normalized_uuid(ve_ownerid, file, sizeof(file))) {
		if (get_hostname(serverid, size - 1))
			return vzctl_err(VZCTL_E_ENV_MANAGE_DISABLED, errno,
				"Owner check failed, unable to get hostname");
	} else {
		get_serverid(serverid, size);
	}

	if (strcmp(serverid, ve_ownerid))
		return VZCTL_E_ENV_MANAGE_DISABLED;

	return 0;
}

enum {
	SKIP_PORT_REDIR_DESTROY = 0x01,
};

int vzctl2_destroy_net_stat(struct vzctl_env_handle *h, int flags)
{
	if (is_vz_kernel()) {
		int destroy = !(flags & SKIP_PORT_REDIR_DESTROY);

		if (vzctl2_clear_ve_netstat(h)) {
			if (!destroy && errno != EBUSY)
				logger(0, errno, "Failed to destroy network statistic");
		}
	}

	return 0;
}

static int cmp_stat(struct stat *a, struct stat *b)
{
	return !(a->st_dev == b->st_dev && a->st_ino == b->st_ino);
}

static int validate_eid(struct vzctl_env_handle *h, struct stat *veconf,
		ctid_t ctid)
{
	char conf[PATH_MAX];
	struct stat st;
	ctid_t ctid_conf;
	const char *data;

	if (vzctl2_env_get_param(h, "VEID", &data) == 0 && data != NULL)
		vzctl2_parse_ctid(data, ctid_conf);
	/* Check if VE_PRIVATE/ve.conf already registered
	 * /etc/vz/conf/ctid_conf.conf -> VE_PRIVATE/ve.conf
	 */
	if (!EMPTY_CTID(ctid_conf)) {
		vzctl2_get_env_conf_path(ctid_conf, conf, sizeof(conf));
		if (stat(conf, &st) == 0) {
			if (cmp_stat(veconf, &st) == 0)
				return vzctl_err(-1, 0, "Container is already"
					" registered with id %s", ctid_conf);
		} else if (errno != ENOENT)
			return vzctl_err(-1, errno, "Failed to stat %s", conf);
	}

	/* Check if ctid alredy used */
	vzctl2_get_env_conf_path(ctid, conf, sizeof(conf));
	if (lstat(conf, &st)) {
		if (errno == ENOENT)
			return 0;
		return vzctl_err(-1, errno, "Failed lstat %s", conf);
	} else if (!S_ISLNK(st.st_mode))
		return vzctl_err(-1, 0, "Container configuration file %s"
				" is not a link", conf);

	if (stat(conf, &st)) {
		if (errno == ENOENT)
			return 0;
		return vzctl_err(-1, errno, "Failed to stat %s", conf);
	}

	/* /etc/vz/conf/ctid.conf already exists */
	if (cmp_stat(veconf, &st) != 0 )
		return vzctl_err(-1, 0, "Error: Container ID %s is used", ctid);

	return 0;
}

static int renew_VE_PRIVATE(struct vzctl_env_handle *h, const char *path,
		ctid_t ctid)
{
	char path_new[PATH_MAX];
	char *dir, *p;

	dir = strdupa(path);
	if ((p = strrchr(dir, '/')) != NULL)
		*p = '\0';

	/* Sync VE_PRIVATE with EID */
	snprintf(path_new, sizeof(path_new), "%s/%s", dir, ctid);
	if (strcmp(path, path_new) == 0) {
		snprintf(path_new, sizeof(path_new), "%s/$VEID", dir);
		vzctl2_env_set_param(h, "VE_PRIVATE", path_new);
	} else
		vzctl2_env_set_param(h, "VE_PRIVATE", path);

	return 0;
}

/** Register Container
 * @param path		Container private data root
 * @param param		struct vzctl_reg_param
 * @param flags		registration flags
 * @return		veid or -1 in case error
 */
int vzctl2_env_register(const char *path, struct vzctl_reg_param *param, int flags)
{
	char buf[PATH_MAX];
	char veconf[STR_SIZE];
	char path_r[PATH_MAX];
	struct stat st;
	int ret, err;
	struct vzctl_env_handle *h;
	FILE *fp;
	char ve_host[STR_SIZE];
	char host[STR_SIZE];
	int owner_check_res;
	int on_pcs, on_shared;
	int ha_resource_added = 0;
	int ha_enable = 0;
	const char *data, *name;
	ctid_t ctid = {};
	ctid_t uuid = {};

	/* preserve compatibility
	 * VZ_REG_SKIP_HA_CLUSTER is alias for VZ_REG_SKIP_CLUSTER
	 */
	if (flags & VZ_REG_SKIP_HA_CLUSTER)
		flags |= VZ_REG_SKIP_CLUSTER;

	if (stat(path, &st) != 0)
		return vzctl_err(-1, errno, "Unable to stat %s", path);

	if (realpath(path, path_r) == NULL)
		return vzctl_err(-1, errno, "Failed to get realpath %s", path);

	ret = vzctl2_env_layout_version(path_r);
	if (ret == -1) {
		return -1;
	} else if (ret < VZCTL_LAYOUT_4)
		return vzctl_err(-1, 0, "Warning: Container in old data format,"
				" registration skipped.");

	snprintf(veconf, sizeof(veconf), "%s/" VZCTL_VE_CONF, path_r);
	if (stat(veconf, &st)) {
		logger(-1, 0, "Error: Broken Container, no %s file found", veconf);
		return -1;
	}

	h = vzctl2_env_open_conf(param->ctid, veconf, VZCTL_CONF_BASE_SET, &err);
	if (h == NULL)
		return -1;

	data = param->uuid;
	/* get UUID from config if not specified */
	if (data == NULL)
		vzctl2_env_get_param(h, "UUID", &data);

	if (get_cid_uuid_pair(param->ctid, data, ctid, uuid))
		goto err;

	owner_check_res = vzctl_check_owner_quiet(
			path_r, host, sizeof(host), ve_host, sizeof(ve_host));
	on_pcs = (is_pcs(path_r) == 1);
	on_shared = (is_shared_fs(path_r) == 1);

        if (vzctl2_env_get_param(h, "HA_ENABLE", &data) == 0 && data != NULL)
                ha_enable = yesno2id(data);

	if (on_pcs && ha_enable != VZCTL_PARAM_OFF &&
			check_external_disk(path_r, h->env_param->disk) &&
			shaman_is_configured())
	{
		logger(-1, 0, "Containers with external disks cannot be"
				" registered in a High Availability cluster");
		goto err;
	}

	if (!(flags & VZ_REG_FORCE)) {
		/* ignore renew option for pstorage (https://jira.sw.ru/browse/PSBM-16819) */
		if (on_pcs)
			flags &= ~VZ_REG_RENEW;

		if (!(flags & VZ_REG_RENEW) && owner_check_res) {
			if (owner_check_res == VZCTL_E_ENV_MANAGE_DISABLED) {
				logger(-1, 0, "Owner check failed on the server %s;"
					" Container is registered for %s", host, ve_host);
				if (on_pcs)
					logger(0, 0,
					"Failed to register the Container/virtual machine. "
					"You can force the registration, but this will revoke "
					"all access to the Container from the original server.");
			}
			goto err;
		}

		if (validate_eid(h, &st, ctid))
			goto err;
	} else if ((owner_check_res == VZCTL_E_ENV_MANAGE_DISABLED) && on_shared) {
		if (on_pcs && !(flags & VZ_REG_SKIP_CLUSTER)) {
			/* [pstorage:] if CT already registered on other node, revoke leases */
			/* before files editing (https://jira.sw.ru/browse/PSBM-16819) */
			char *argv[] = { "/usr/bin/pstorage", "revoke", "-R", (char *)path_r, NULL };
			/* it is irreversible operation */
			if (vzctl2_wrap_exec_script(argv, NULL, 0))
				goto err;
		}
		if (!(flags & VZ_REG_SKIP_CLUSTER) && (ha_enable != VZCTL_PARAM_OFF)) {
			/* remove resource from HA cluster
			 * TODO : execute 'del-everywhere' and 'add' by one command
			 *	 (https://jira.sw.ru/browse/PSBM-17374
			 */
			shaman_del_everywhere(ctid);
		}
	}
	if (!(flags & VZ_REG_SKIP_CLUSTER) && on_shared && (ha_enable != VZCTL_PARAM_OFF)) {
		/* TODO : execute 'del-everywhere' and 'add' by one command
		 *		(https://jira.sw.ru/browse/PSBM-17374)
		 * Right now ask HA cluster to register CT as resource
		 * and will do it before filesystem operations
		 */
		if (shaman_add_resource(ctid, h->conf, path_r)) {
			logger(-1, 0, "Error: Failed to register the Container %s on HA cluster",
					ctid);
			goto err;
		}
		ha_resource_added = 1;
	}

	if (!(flags & VZ_REG_SKIP_OWNER)) {
		snprintf(buf, sizeof(buf), "%s/" VZCTL_VE_OWNER, path_r);
		if ((fp = fopen(buf, "w")) == NULL) {
			logger(-1, errno, "Unable to register the Container; failed to create"
					" the file %s", buf);
			goto err;
		}
		if (get_serverid(buf, sizeof(buf)) == 0)
			fprintf(fp, "%s", buf);
		fclose(fp);
	}

	ret = renew_VE_PRIVATE(h, path, ctid);
	if (ret)
		goto err;

	/* restore CT name */
	name = param->name ?: h->env_param->name->name;
	if (name != NULL && *name != '\0') {
		ctid_t t;
		char x[PATH_MAX];
		const char *new_name = name;
		const char *veid = NULL;

		vzctl2_env_get_param(h, "VEID", &veid);

		if (vzctl2_get_envid_by_name(name, t) == 0 &&
				veid != NULL && CMP_CTID(t, veid))
		{
			logger(-1, 0, "Name %s is in use by CT %s", name, t);
			new_name = gen_uniq_name(name, x, sizeof(x));
		}

		vzctl2_env_set_param(h, "NAME", new_name);
		if (h->env_param->name->name) {
			struct stat st_n;

			snprintf(buf, sizeof(buf), ENV_NAME_DIR "%s",
					h->env_param->name->name);
			if (stat(buf, &st_n) == 0 && st.st_dev == st_n.st_dev)
				unlink(buf);
		}

		logger(0, 0, "Assign the name: %s", new_name);
		snprintf(buf, sizeof(buf), ENV_NAME_DIR "%s", new_name);
		unlink(buf);
		if (symlink(veconf, buf)) {
			logger(-1, errno, "Unable to create the link %s", buf);
			goto err;
		}
	}

	vzctl2_env_set_param(h, "VEID", ctid);
	/* Update UUID */
	vzctl2_env_set_param(h, "UUID", uuid);

	ret = vzctl2_env_save_conf(h, veconf);
	if (ret)
		goto err;

	/* create registration */
	vzctl2_get_env_conf_path(ctid, buf, sizeof(buf));
	unlink(buf);
	if (symlink(veconf, buf)) {
		logger(-1, errno, "Failed to create the symlink %s", buf);
		goto err;
	}

	vzctl2_env_close(h);
	vzctl2_send_state_evt(ctid, VZCTL_ENV_REGISTERED);

	logger(0, 0, "Container %s was successfully registered", ctid);
	return 0;

err:
	if (ha_resource_added)
		shaman_del_resource(ctid);
	vzctl2_env_close(h);
	logger(-1, 0, "Container registration failed: %s",
			vzctl2_get_last_error());

	return -1;
}

static int unregister_env_conf(struct vzctl_env_handle *h)
{
	char veconf[PATH_MAX];

	get_env_conf_lockfile(h, veconf, sizeof(veconf));
	unlink(veconf);

	vzctl2_get_env_conf_path(EID(h), veconf, sizeof(veconf));
	if (unlink(veconf) && errno != ENOENT)
		return vzctl_err(VZCTL_E_SYSTEM, errno, "Failed to unlink %s", veconf);

	return 0;
}

static int is_same_file(const char *f1, const char *f2)
{
	struct stat st1, st2;

	if (stat(f1, &st1) == 0 && stat(f2, &st2) == 0 &&
			st1.st_dev == st2.st_dev &&
			st1.st_ino == st2.st_ino)
		return 1;
	return 0;
}

int vzctl2_env_unreg(struct vzctl_env_handle *h, int flags)
{
	char buf[STR_SIZE];
	char host[STR_SIZE];
	int ret;
	const char *ve_root;
	const char *ve_private = h->env_param->fs->ve_private;

	/* preserve compatibility
	 * VZ_REG_SKIP_HA_CLUSTER is alias for VZ_REG_SKIP_CLUSTER
	 */
	if (flags & VZ_REG_SKIP_HA_CLUSTER)
		flags |= VZ_REG_SKIP_CLUSTER;

	if (is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_RUN, 0,
			"Container is running, Stop Container before proceeding.");

	if (access(ve_private, F_OK) && errno == ENOENT) {
		ret = unregister_env_conf(h);
		if (ret)
			return ret;
		goto out;
	}

	if (vzctl2_env_layout_version(ve_private) < VZCTL_LAYOUT_4)
		return 0;

	ret = vzctl_check_owner_quiet(ve_private, buf, sizeof(buf), host, sizeof(host));
	if (ret == VZCTL_E_ENV_MANAGE_DISABLED) {
		logger(0, 0, "Owner check failed on the server '%s':"
				" Container (%s) is registered for '%s'",
				buf, ve_private, host);
		ret = unregister_env_conf(h);
		if (ret)
			return ret;
		goto out;
	} else if (ret)
		return ret;

	ve_root = h->env_param->fs->ve_root;
	if (ve_root != NULL && vzctl2_env_is_mounted(h) == 1) {
		if (vzctl2_env_umount(h, 0))
			return vzctl_err(VZCTL_E_FS_MOUNTED, 0,
				"Container is mounted, Unmount Container "
				"before proceeding.");
	}

	if (!(flags & VZ_UNREG_PRESERVE)) {
		/* Remove VEID from /ve_private/ve.conf */
		vzctl2_env_set_param(h, "VEID", NULL);
		if (vzctl2_env_save(h))
			return VZCTL_E_UNREGISTER;

		/* Remove VE_PRIVATE/.owner */
		snprintf(buf, sizeof(buf), "%s/" VZCTL_VE_OWNER, ve_private);
		unlink(buf);
	}

	/* cleanup name */
	if (h->env_param->name->name != NULL) {
		char name_path[PATH_MAX];
		char veconf[PATH_MAX];

		snprintf(veconf, sizeof(veconf), "%s/" VZCTL_VE_CONF, ve_private);
		snprintf(name_path, sizeof(name_path), ENV_NAME_DIR "%s",
				h->env_param->name->name);
		if (is_same_file(name_path, veconf))
			unlink(name_path);
	}

	/* Remove /etc/vz/conf/VEID.conf */
	unregister_env_conf(h);

	if (!(flags & VZ_REG_SKIP_CLUSTER) &&
			is_shared_fs(ve_private) &&
			shaman_del_resource(EID(h)))
		logger(0, 0,"Warning: Failed to unregister the Container on HA cluster");

out:
	vzctl2_destroy_net_stat(h, 0);
	vzctl2_send_state_evt(EID(h), VZCTL_ENV_UNREGISTERED);
	logger(0, 0, "Container unregistered succesfully");

	return 0;
}

int vzctl2_env_unregister(const char *path, const ctid_t ctid, int flags)
{
	int ret;
	struct vzctl_env_handle *h;

	h = vzctl2_env_open(ctid, 0, &ret);
	if (h == NULL)
		return vzctl_err(ret, 0,
			"failed to open Container %s configuration file", ctid);

	ret = vzctl2_env_unreg(h, flags);

	vzctl2_env_close(h);

	return ret;
}

int vzctl2_check_owner(const char *ve_private)
{
	int ret;
	char ve_host[STR_SIZE] = "";
	char host[STR_SIZE] = "";

	if (ve_private == NULL)
		return vzctl_err(VZCTL_E_VE_PRIVATE_NOTSET, 0, "Owner check failed:"
				" Container private area is not set");

	ret = vzctl_check_owner_quiet(ve_private, host, sizeof(host), ve_host, sizeof(ve_host));
	if (ret == VZCTL_E_ENV_MANAGE_DISABLED)
		logger(-1, 0, "Owner check failed on the server '%s':"
				" Container (%s) is registered for '%s'",
				host, ve_private, ve_host);
	return ret;
}

char *get_running_state_fname(const char *ve_private, char *buf, int size)
{
	snprintf(buf, size, "%s/.running", ve_private);

	return buf;
}

void vzctl2_register_running_state(const char *ve_private)
{
	int fd;
	char fname[PATH_MAX];

	if (ve_private == NULL)
		return;

	get_running_state_fname(ve_private, fname, sizeof(fname));
	logger(4, 0, "register %s", fname);
	fd = open(fname, O_CREAT | O_RDONLY, 0600);
	if (fd == -1) {
		if (errno != EEXIST)
			logger(-1, errno, "Failed to create %s", fname);
		return;
	}
	close(fd);
}

void vzctl2_unregister_running_state(const char *ve_private)
{
	char fname[PATH_MAX];

	if (ve_private == NULL)
		return;

	get_running_state_fname(ve_private, fname, sizeof(fname));
	logger(4, 0, "unregister %s", fname);
	if (unlink(fname) && errno != ENOENT)
		logger(-1, errno, "Failed to unlink %s", fname);
}

