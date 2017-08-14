/*
 * Copyright (c) 2015-2017, Parallels International GmbH
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
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include "list.h"
#include "vzerror.h"
#include "util.h"
#include "exec.h"

static void trim_n(char *buf)
{
	char *p = strchr(buf, '\n');
	if (p != NULL)
		*p = '\0';
}

static int process_cmd_status(char **arg, int status, int quiet)
{
	int ret;

	if (WIFEXITED(status)) {
		ret = WEXITSTATUS(status);
		if (ret) {
			if (!quiet)
				logger(-1, 0, "command %s exited with error %d",
						arg[0], ret);
			return ret;
		}
	} else if (WIFSIGNALED(status))
		return vzctl_err(-1, 0, "command %s got signal %d",
				arg[0], WTERMSIG(status));

	return 0;
}

static int get_last_line(char **arg, char *buf, int len)
{
	FILE *fp;
	int ret;

	*buf = '\0';

	fp = vzctl_popen(arg, NULL, 0);
	if (fp == NULL)
		return -1;

	while (fgets(buf, len, fp) != NULL);

	ret = process_cmd_status(arg, vzctl_pclose(fp) , 0);
	if (ret == 0)
		trim_n(buf);

	return ret;
}

int vztmpl_get_ostmpl_name(const char *ostmpl, char *out, int len)
{
	int ret;
	char *arg[] = {VZPKG, "info", "-q", (char *)ostmpl, "name",  NULL};

	ret = get_last_line(arg, out, len);
	if (ret)
		return vzctl_err(ret, 0, "Unable to get full ostemplate name for %s", ostmpl);
	return 0;
}

int vztmpl_get_technologies(const char *name, unsigned long long *tech)
{
	char buf[STR_SIZE];
	char *token, *savedptr;
	int ret;
	unsigned long long n;
	char *arg[] = {VZPKG, "info", "-q", (char *)name, "technologies", NULL};

	ret = get_last_line(arg, buf, sizeof(buf));
	if (ret)
		return vzctl_err(ret, 0, "Unable to get technologies for %s", name);

	*tech = 0;
	if ((token = strtok_r(buf, "\t ", &savedptr)) != NULL) {
		do {
			if ((n = vzctl2_name2tech(token)))
				*tech |= n;
		} while ((token = strtok_r(NULL, "\t ", &savedptr)) != NULL);
	}

	return 0;
}

int vztmpl_get_distribution(const char *ostmpl, char *out, int len)
{
	int ret;
	char *arg[] = {VZPKG, "info", "-q", (char *)ostmpl, "distribution", NULL};

	ret = get_last_line(arg, out, len);
	if (ret)
		return vzctl_err(ret, 0, "Unable to get distribution for %s", ostmpl);

	return 0;
}

int vztmpl_get_osrelease(const char *ostmpl, char *out, int len)
{
	int ret;
	char *arg[] = {VZPKG, "info", "-q", (char *)ostmpl, "osrelease", NULL};

	out[0] = '\0';
	ret = get_last_line(arg, out, len);
	if (ret && ret != 24 /* Template was not found */)
		return vzctl_err(VZCTL_E_GET_OSRELEASE, errno, "Failed to get osrelease for %s",
				ostmpl);
	return 0;
}

int vztmpl_is_jquota_supported(const char *ostmpl)
{
        char buf[STR_SIZE];
        char *arg[] = {VZPKG, "info", (char *)ostmpl, "-q", "jquota", NULL};

	if (get_last_line(arg, buf, sizeof(buf)))
		return -1;

	return (strncmp(buf, "yes", 3) == 0);
}

static int vztmpl_create_cache(const char *ostmpl, const char *fstype)
{
	const char *p;
	char *arg[8];
	char progress[STR_SIZE] = "";
	char *env[] = {progress, NULL };
	int i = 0;

	arg[i++] = VZPKG;
	arg[i++] = "create";
	arg[i++] = "cache";
	if (vzctl2_get_log_quiet())
		arg[i++] = "-q";
	arg[i++] = (char *)ostmpl;
	if (fstype) {
		arg[i++] = "--vefstype";
		arg[i++] = (char *)fstype;
	}
	arg[i++] = NULL;

	if ((p = getenv("VZ_PROGRESS_FD")))
		snprintf(progress, sizeof(progress), "VZ_PROGRESS_FD=%s", p);

	return vzctl2_wrap_exec_script(arg, env, 0);
}

static int vztmpl_create_appcache(const char *config, const char *ostmpl, const char *fstype)
{
	char *arg[11];
	int i = 0;

	arg[i++] = VZPKG;
	arg[i++] = "create";
	arg[i++] = "appcache";
	if (vzctl2_get_log_quiet())
		arg[i++] = "-q";
	arg[i++] ="--config";
	arg[i++] = (char *)config;
	arg[i++] = "--ostemplate";
	arg[i++] = (char *)ostmpl;
	if (fstype) {
		arg[i++] = "--vefstype";
		arg[i++] = (char *)fstype;
	}
	arg[i++] = NULL;

	return vzctl2_wrap_exec_script(arg, NULL, 0);
}

int vztmpl_install_app(ctid_t ctid, const char *apps, int force)
{
	char **arg;
	char *str = NULL;
	char *token, *savedptr;
	int total = 255;
	int ret, i = 0;

	arg = calloc(total + 1, sizeof(char *));
	if (arg == NULL)
		return VZCTL_E_NOMEM;

	ret = xstrdup(&str, apps);
	if (ret)
		goto err;

	logger(0, 0, "Installing applications: %s", str);
	token = strtok_r(str, LIST_DELIMITERS, &savedptr);
	if (token == NULL) {
		ret = 0;
		goto err;
	}

	arg[i++] = strdup(VZPKG);
	arg[i++] = strdup("install");
	arg[i++] = strdup("--skiplock");
	arg[i++] = strdup("--quiet");
	if (force)
		arg[i++] = strdup("--force");
	arg[i++] = strdup(ctid);
	do {
		if (i == total) {
			char **tmp;

			total += 255;
			tmp = (char **) realloc(arg,
					(total + 1) * sizeof(char *));
			if (tmp == NULL)
				goto err;
			arg = tmp;
		}
		arg[i++] = strdup(token);
		arg[i] = NULL;
	} while ((token = strtok_r(NULL, LIST_DELIMITERS, &savedptr)));
	arg[i] = NULL;

	ret = vzctl2_wrap_exec_script(arg, NULL, 0);
	if (ret)
		goto err;

err:
	free_ar_str(arg);
	free(arg);
	free(str);

	return ret ? VZCTL_E_INSTALL_APPS : 0;
}

static const char *get_full_ostmpl(const char *ostmpl, char *out, int size)
{
	if (strstr(ostmpl, "-x86") == NULL)
		snprintf(out, size, "%s-x86_64", ostmpl);
	else
		snprintf(out, size, "%s", ostmpl);

	return out;
}

static int vztmpl_get_appcache_tarball(const char *cache_config, const char *ostmpl,
		const char *fstype, list_head_t *applist, char *tarball, int len)
{
	FILE *fp;
	char buf[4096];
	char f_ostmpl[STR_SIZE];
	char *arg[10];
	int ret = 0, i = 0;

	/* vzpkg info -a [--config name] --ostemplate name [--vefstype=type] */
	arg[i++] = VZPKG;
	arg[i++] = "info";
	arg[i++] = "-q";
	if (cache_config != NULL) {
		arg[i++] = "--config";
		arg[i++] = (char *)cache_config;
	}
	arg[i++] = "--ostemplate";
	arg[i++] = (char *)get_full_ostmpl(ostmpl, f_ostmpl, sizeof(f_ostmpl));
	if (fstype != NULL) {
		arg[i++] = "--vefstype";
		arg[i++] = (char *)fstype;
	}
	arg[i++] = NULL;

	fp = vzctl_popen(arg, NULL, DONT_REDIRECT_ERR2OUT);
	if (fp == NULL)
		goto err;

	*tarball = '\0';
	/* Parse vzpkg output */
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		/* First, get the tarball, Second+, get the unsupported by
		 * Golden Image template list
		 */
		trim_n(buf);
		if (*tarball == '\0')
			snprintf(tarball, len, "%s", buf);
		else if (add_str_param(applist, buf) == NULL)
			goto err;
	}

	ret = process_cmd_status(arg, vzctl_pclose(fp), 1);
	if (ret)
		goto err;

	return 0;
err:
	return ret;
}

#ifndef VZT_TMPL_NOT_CACHED
#define VZT_TMPL_NOT_CACHED 23
#endif

#ifndef VZT_TMPL_NOT_FOUND
#define VZT_TMPL_NOT_FOUND 24
#endif

int vztmpl_get_cache_tarball(const char *config, char **ostmpl,
		const char *fstype, char **applist, int use_ostmpl,
		char *tarball, int len)
{
	int ret = 0;
	const char *config_name = config;
	LIST_HEAD(unsupported_applist);
	char full_ostmpl[STR_SIZE];

	tarball[0] = '\0';
	ret = vztmpl_get_appcache_tarball(config_name, *ostmpl, fstype,
			&unsupported_applist, tarball, len);
	if (ret == 0)
		goto out;

	if (ret != VZT_TMPL_NOT_CACHED) {
		/* Other vztt errors are fatal, stop here */
		if (ret == VZT_TMPL_NOT_FOUND)
			logger(-1, 0, "Error: Unable to find ostemplate: %s",
					*ostmpl);
		else 
			logger(-1, 0, "Unable to get appcache tarball name"
					" for %s with ostemplate %s",
					config_name, *ostmpl);
		goto err;
	}

	/* Handle reinstall/recover logic
	 * if App cache tarball does not exists use ostemplate
	 */
	if (use_ostmpl) {
		config_name = NULL;
		ret = vztmpl_get_appcache_tarball(config_name, *ostmpl,
				fstype, &unsupported_applist, tarball, len);
		if (ret != 0 && ret != VZT_TMPL_NOT_CACHED) {
			logger(-1, 0, "Unable to get appcache tarball name for %s with "
				"ostemplate %s", config_name, *ostmpl);
			goto err;
		}
	}

	if (tarball[0] == '\0') {
		if (applist && *applist != NULL && !use_ostmpl) {
			logger(0, 0, "Cached package set '%s' with applications"
					" from config %s is not found, run create "
					"appcache utility...", *ostmpl, config_name);

			if (vztmpl_create_appcache(config_name, *ostmpl, fstype))
				goto err;
		} else {
			logger(0, 0, "Cached package set '%s' is not found, run"
					" create cache utility...", *ostmpl);
			if (vztmpl_create_cache(*ostmpl, fstype))
				goto err;
		}
	}

	/* Update OSTEMPLATE */
	if (vztmpl_get_ostmpl_name(*ostmpl, full_ostmpl, sizeof(full_ostmpl)))
		goto err;

	ret = xstrdup(ostmpl, full_ostmpl);
	if (ret)
		return ret;

	if (vztmpl_get_appcache_tarball(config_name, full_ostmpl, fstype,
				&unsupported_applist, tarball, len))
	{
		logger(-1, 0, "Unable to get appcache tarball name for %s with "
			"ostemplate %s", config_name, full_ostmpl);
		goto err;
	}

out:

	/* Override the given applist to install unsupported templates */
	if (applist != NULL && config != NULL) {
		free(*applist);
		*applist = list2str("", &unsupported_applist);
	}

	free_str(&unsupported_applist);

	return 0;

err:
	free_str(&unsupported_applist);

	return VZCTL_E_FS_NEW_VE_PRVT;
}

static char *skip_trailing_space(char *str)
{
	char *ep;

	ep = str + strlen(str) - 1;
	while (isspace(*ep) && ep >= str) *ep-- = '\0';
	return str;
}

int vztmpl_get_applist(ctid_t ctid, list_head_t *head, const char *ostmpl)
{
	char buf[STR_SIZE];
	char package[STR_SIZE];
	FILE *fd;
	char *p;
	int status, exitcode;
	char *argv[] = {VZPKG, "list", "-q", "--old-format", ctid, NULL};

	if ((fd = vzctl_popen(argv, NULL, 0)) == NULL)
		return VZCTL_E_GET_APPS;
	*buf = 0;
	while ((p = fgets(buf, sizeof(buf), fd))) {
		char *p1, *p2;

		skip_trailing_space(buf);
		/* find pkg name */
		p1 = strchr(buf, ' ');
		/* find last version */
		p2 = strrchr(buf, ' ');
		if (p1 == NULL) {
			snprintf(package, sizeof(package), "%s", buf);
		} else if (p2 != NULL) {
			*p1 = 0;
			snprintf(package, sizeof(package), "%s/%s", buf, ++p2);
		} else {
			logger(-1, 0, "Invalid format in the list: %s", buf);
			continue;
		}
		/* Skip ostemplate */
		if (ostmpl != NULL && !strcmp(buf, ostmpl))
			continue;

		add_str_param(head, package);
	}
	status = vzctl_pclose(fd);

	if ((exitcode = WEXITSTATUS(status))) {
		logger(-1, 0, "Unable to get the list of installed package"
				" sets " VZPKG " exitcode [%d]", exitcode);
		free_str(head);
		return VZCTL_E_GET_APPS;
	}
	return 0;
}
