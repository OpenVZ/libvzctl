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
#define _GNU_SOURCE
#include <features.h>
#include <crypt.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>

#include "fs.h"
#include "env.h"
#include "vzerror.h"
#include "logger.h"
#include "util.h"

static int check_link(const char *file, int fd)
{
	struct stat st;

	if (fstat(fd, &st) < 0)
		return vzctl_err(-1, errno, "Unable to stat %s", file);

	if (!S_ISREG(st.st_mode))
		return vzctl_err(-1, 0, "password database %s is not regular file",
				file);
	return 0;
}

static FILE *openfile(const char *file)
{
	FILE *fp;
	struct stat st;

	if (stat(file, &st) < 0) {
		logger(-1, errno, "Unable to stat %s", file);
		return NULL;
	}
	if (!S_ISREG(st.st_mode)) {
		logger(-1, errno, "password database %s is not regular file\n",
			file);
		return NULL;
	}
	if ((fp = fopen(file, "r")) == NULL) {
		logger(-1, errno, "Unable to open %s", file);
		return NULL;
	}
	if (check_link(file, fileno(fp))) {
		fclose(fp);
		return NULL;
	}
	return fp;
}

static int check_gid_passwd(const char *user, int gid)
{
	FILE *fp;
	char buf[1024];
	char name[1024];
	char passwd[1024];
	int _uid, _gid;
	int ret;

	ret = VZCTL_E_AUTH_GUID;
	if ((fp = openfile("/etc/passwd")) == NULL)
		return ret;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		/* user:passwd:uid:gid: */
		if (sscanf(buf, "%[^:]:%[^:]:%d:%d",
					name, passwd, &_uid, &_gid) != 4)
			continue;
		if (!strcmp(name, user)) {
			if (gid == _gid)
				ret = 0;
			break;
		}
	}
	fclose(fp);
	return ret;
}

static int check_gid_group(const char *user, int gid)
{
	FILE *fp;
	char buf[1024];
	char users[1024];
	int id;
	int ret;
	const char *sp, *ep, *p;
	int len = 0;

	ret = VZCTL_E_AUTH_GUID;
	if ((fp = openfile("/etc/group")) == NULL)
		return ret;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		/* group:x:gid:user1,user2,... */
		if (sscanf(buf, "%*[^:]::%d:%s", &id, users) != 2 &&
		    sscanf(buf, "%*[^:]:%*[^:]:%d:%s", &id, users) != 2)
			continue;

		if (id != gid)
			continue;

		sp = users;
		ep = sp + strlen(sp);
		do {
			if ((p = strchr(sp, ',')) == 0)
				p = ep;
			len = p - sp + 1;
			strncpy(buf, sp, len);
			buf[len - 1] = 0;
			sp = p + 1;
			if (!strcmp(user, buf)) {
				fclose(fp);
				return 0;
			}
		} while (sp < ep);
	}
	fclose(fp);
	return ret;
}

static int check_gid(const char *user, int gid)
{
	int ret;

	if ((ret = check_gid_passwd(user, gid)))
		ret = check_gid_group(user, gid);

	return ret;
}

static char *get_user_pw(FILE *fp, const char *user)
{
	char buf[4096];
	char *pw = NULL;
	char *sp, *ep, *end;
	int len;

	len = strlen(user);
	if (len >= sizeof(buf))
		goto error;
	sp = buf + len;
	end = buf + sizeof(buf);

	while ((fgets(buf, sizeof(buf), fp)) != NULL) {
		if (strncmp(user, buf, len) || *sp != ':')
			continue;
		ep = sp;
		ep++;
		while (ep < end && *ep != '\0' && *ep != ':') ep++;
		if (*ep != ':' )
			break;
		snprintf(buf, ep - sp, "%s", sp + 1);
		pw = strdup(buf);
		break;
	}

error:
	return pw;
}

static int get_user_hash(const char *user, int gid, char **hash)
{
	FILE *fp;
	char str[64];
	char *pw;
	int ret;
	struct stat st;

	ret = VZCTL_E_AUTH;
	snprintf(str, sizeof(str), "/etc/shadow");
	if (stat(str, &st) < 0)
		snprintf(str, sizeof(str), "/etc/passwd");
	if ((fp = openfile(str)) == NULL)
		return VZCTl_E_FOPEN;
	pw = get_user_pw(fp, user);
	if (pw) {
		ret = 0;
		*hash = pw;
	}
	fclose(fp);

	return ret;
}

static int escape_chroot(int rootfd)
{
	int ret = fchdir(rootfd);
	if (ret == -1)
		return vzctl_err(VZCTL_E_SYSTEM, errno, "fchdir('/') failed");
	ret = chroot(".");
	if (ret == -1)
		logger(VZCTL_E_SYSTEM, errno, "chroot('/') failed");
	return ret;
}

static int userauth(const char *user, const char *password, int gid, int rootfd)
{
	int ret;
	char *pw, *pw_enc;

	if (gid != -1 && (ret = check_gid(user, gid)) != 0)
		return ret;
	ret = get_user_hash(user, gid, &pw);
	if (ret != 0)
		return ret;
	ret = escape_chroot(rootfd);
	if (ret == 0) {
		struct crypt_data data = {};
		ret = VZCTL_E_AUTH;
		pw_enc = crypt_r(password, pw, &data);
		if (pw_enc && !strcmp(pw_enc, pw))
			ret = 0;
	}
	free(pw);
	return ret;
}

static int pleskauth(const char *user, const char *passwd)
{
	FILE *fp;
	char str[512] = "";
	char *p;
	int ret;

	ret = VZCTL_E_AUTH;
	if ((fp = openfile("/etc/psa/.psa.shadow")) == NULL)
		return ret;

	if (fgets(str, sizeof(str), fp) != NULL) {
		if ((p = strrchr(str, '\n')) != NULL)
			*p = 0;
		if (strcmp(passwd, str) == 0)
			ret = 0;
	}
	fclose(fp);

	return ret;
}

/* Authenticate the user in a the Container
 * @param id            Container id
 * @param user          User name
 * @param password      User password
 * @param gid           if >= 0 user checked to be a member of group gid.
 * @param type          0 - system, 1 - pleskadmin
 * @return
 */
int vzctl2_env_auth(struct vzctl_env_handle *h, const char *user, const char *passwd,
		int gid, int type)
{
	int is_mounted = 0;
	int pid, ret;
	struct vzctl_env_param *env;

	if (user == NULL || passwd == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0, "Invalid argument");

	env = vzctl2_get_env_param(h);

	if (check_var(env->fs->ve_root, "VE_ROOT is not set"))
		 return VZCTL_E_VE_ROOT_NOTSET;

	is_mounted = vzctl2_env_is_mounted(h);
	if (!is_mounted) {
		ret = vzctl2_env_mount(h, 0);
		if (ret)
			return ret;
	}

	if (!(pid = fork())) {
		int rootfd = -1;
		if (type == 0) {
			rootfd = open("/", O_RDONLY);
			if (rootfd == -1)
				_exit(vzctl_err(VZCTL_E_SYSTEM, errno,
					"failed to open '/' "));
		}
		if ((ret = vzctl_chroot(env->fs->ve_root)) == 0) {
			if (type == 0)
				ret = userauth(user, passwd, gid, rootfd);
			else
				ret = pleskauth(user, passwd);
		}
		if (rootfd != -1)
			close(rootfd);
		_exit(ret);
	}
	ret = env_wait(pid, 0, NULL);

	if (!is_mounted)
		vzctl2_env_umount(h, 0);

	return ret;
}
