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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/stat.h>
#include <pthread.h>

#include "vzctl.h"
#include "config.h"
#include "env_config.h"
#include "util.h"
#include "logger.h"
#include "vzerror.h"

static pthread_mutex_t gconf_mtx = PTHREAD_MUTEX_INITIALIZER;
static struct vzctl_config *__gconf;

const struct vzctl_config_param *param_get_by_name(
		const struct vzctl_config_param *param, const char *name)
{
	const struct vzctl_config_param *p;

	for (p = param; p->id != -1; p++) {
		if (p->name == NULL)
			continue;
		if (!strcmp(p->name, name))
			return p;
	}
	return NULL;
}

const struct vzctl_config_param *param_get_by_id(
		const struct vzctl_config_param *param, int id)
{
	const struct vzctl_config_param *p;

	for (p = param; p->id != -1; p++)
		if (p->id == id)
			return p;
	return NULL;
}

const struct vzctl_config_param *get_conf_param(
		const struct vzctl_config_param *param,
		struct vzctl_data_param *data)
{
	if (data->name != NULL)
		return param_get_by_name(param, data->name);
	return param_get_by_id(param, data->id);
}

struct vzctl_config_data *find_conf_data(const struct vzctl_config *conf,
		const char *name)
{
	struct vzctl_config_data *data;
	int i;

	for (i = 0; i < conf->map.last; i++) {
		data = &conf->map.data[i];
		if (!strcmp(data->name, name))
			return data;
	}
	return NULL;
}

#if 0
struct vzctl_config_data *get_conf_val(const struct vzctl_config *conf,
		const char *name)
{
	struct vzctl_config_data *data;

	if ((data = find_conf_data(conf, name)) !=  NULL)
		return data->val;
	return NULL;
}
#endif

int add_conf_data(struct vzctl_config *conf, const char *name,
		const char *val, int mask)
{
	int idx, size, ret;
	struct vzctl_config_data *data;

#define VZCTL_DATA_DELTA	255

	assert(name);
	/* Update config data */
	if ((data = find_conf_data(conf, name)) != NULL) {
		debug(DBG_CFG, "%s: <up> %s=%s", __func__,
				name, val);
		if (val != NULL) {
			if ((ret = xstrdup(&data->val, val)))
				return ret;
		} else {
			if (data->val != NULL) free(data->val);
			data->val = NULL;
		}
		data->mask |= mask;
		return 0;
	}
	debug(DBG_CFG, "%s: <new> %s=%s", __func__, name, val);
	idx = conf->map.last;
	if (!(idx % VZCTL_DATA_DELTA)) {
		size = sizeof(struct vzctl_config_data) *
			(idx + VZCTL_DATA_DELTA + 1);
		if ((data = realloc(conf->map.data, size)) == NULL)
			return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "%s", __func__);
		conf->map.data = data;
	} else {
		data = conf->map.data;
	}
	data[idx].name = strdup(name);
	data[idx].val = val != NULL ? strdup(val) : NULL;
	data[idx].mask = (mask == 0 ? CONF_DATA_NEW : mask);
	++conf->map.last;
	return 0;
}

static void free_conf_data(struct vzctl_config *conf)
{
	int i;

	for (i = 0; i < conf->map.last; i++) {
		xfree(conf->map.data[i].name);
		xfree(conf->map.data[i].val);
	}
	free(conf->map.data);
	conf->map.last = 0;
}

struct vzctl_config *alloc_conf()
{
	struct vzctl_config *conf;

	if ((conf = calloc(1, sizeof(struct vzctl_config))) == NULL)
		logger(-1, ENOMEM, "alloc_conf");

	return conf;
}

static void free_conf(struct vzctl_config *conf)
{
	if (conf == NULL)
		return;
	free_conf_data(conf);
	xfree(conf->fname);
	free(conf);
}

static int merge_conf_data(struct vzctl_config *dst,
		const struct vzctl_config *src, param_filter_f filter)
{
	struct vzctl_config_data *data;
	int i, ret;

	debug(DBG_CFG, "merge_conf_data:");
	for (i = 0; i < src->map.last; i++) {
		data = &src->map.data[i];

		if (filter && filter(data->name))
			continue;

		if ((ret = add_conf_data(dst, data->name, data->val, 0)))
			return ret;
	}
	return 0;
}

static int parse_conf_data(struct vzctl_config *conf, const char *fname, int flags)
{
	FILE *fp;
	int line = 0;
	char *rtoken;
	int ret = 0;
	char ltoken[4096];
	char buf[4096 * 10];

	if ((fp = fopen(fname, "r")) == NULL) {
		if (errno == ENOENT && (flags & VZCTL_CONF_SKIP_NON_EXISTS))
			return 0;

		return vzctl_err(VZCTL_E_CONFIG, errno, "Unable to open %s",
				fname);
	}
	debug(DBG_CFG, "parse_conf_data: %s", fname);
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		line++;
		rtoken = parse_line(buf, ltoken, sizeof(ltoken));
		if (rtoken == NULL)
			continue;
		if ((flags & VZCTL_CONF_SKIP_PRIVATE) &&
				is_private_param(ltoken))
			continue;
		if ((ret = add_conf_data(conf, ltoken, rtoken, 0)))
			break;
	}
	fclose(fp);

	return ret;
}

int vzctl2_conf_save(struct vzctl_config *conf, const char *fname)
{
	char str[64 * 1024];
	FILE *fp_in, *fp_out;
	char tmp_path[4096], r_path[4096];
	char *rtoken;
	char ltoken[4096];
	int i;
	struct vzctl_config_data *data;

	/* Get real path in case fname is link */
	if (realpath(fname, r_path) == NULL) {
		if (errno != ENOENT) {
			logger(-1, errno, "conf_write: realpath(%s)", fname);
			return -1;
		}
		snprintf(r_path, sizeof(r_path), "%s",  fname);
	}

	debug(DBG_CFG, "vzctl2_conf_save [%s]", r_path);

	snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", r_path);
	if ((fp_out = fopen(tmp_path, "w")) == NULL) {
		logger(-1, errno, "Unable to create configuration"
			" file %s", tmp_path);
		return VZCTL_E_CONF_SAVE;
	}
	if ((fp_in = fopen(r_path, "r")) == NULL) {
		if (errno == ENOENT)
			goto skip_read;
		logger(-1, errno, "Unable to read %s", r_path);
		fclose(fp_out);
		goto err;
	}
	while (fgets(str, sizeof(str), fp_in)) {
		char *tmp = strdup(str);
		rtoken = parse_line(str, ltoken, sizeof(ltoken));
		if (rtoken == NULL) {
			fprintf(fp_out, "%s", tmp);
		} else {

			data = find_conf_data(conf, ltoken);
			if (data != NULL &&
					(data->mask & CONF_DATA_UPDATED)) {
				if (data->val != NULL) {
					debug(DBG_CFG, "%s: %s=%s", __func__,
						data->name, data->val);
					fprintf(fp_out, "%s=\"%s\"\n",
						data->name, data->val);
				}
				data->mask |= CONF_DATA_STORED;
			} else {
				fprintf(fp_out, "%s", tmp);
			}
		}
		free(tmp);
	}

skip_read:
	/* Store rest of data to the end */
	for (i = 0; i < conf->map.last; i++) {
		if (!(conf->map.data[i].mask & CONF_DATA_STORED) &&
		    (conf->map.data[i].mask & CONF_DATA_UPDATED) &&
		    conf->map.data[i].val != NULL)
		{
			debug(DBG_CFG, "%s: <new> %s=%s", __func__,
				conf->map.data[i].name, conf->map.data[i].val);

			fprintf(fp_out, "%s=\"%s\"\n",
				conf->map.data[i].name, conf->map.data[i].val);
		}
		conf->map.data[i].mask = CONF_DATA_NEW;
	}
	if (fp_in != NULL)
		fclose(fp_in);
	fsync(fileno(fp_out));
retry:
	if (rename(tmp_path, r_path)) {
		logger(-1, errno, "Failed to rename %s -> %s",
				tmp_path, r_path);
		if (errno == EBUSY) {
			usleep(500000);
			goto retry;
		}
		fclose(fp_out);
		goto err;
	}
	if (fclose(fp_out)) {
		logger(-1, errno, "Unable to close %s", tmp_path);
		goto err;
	}
	return 0;
err:
	unlink(tmp_path);
	return VZCTL_E_CONF_SAVE;
}

pthread_mutex_t *get_global_conf_mtx()
{
	return &gconf_mtx;
}

const struct vzctl_config *vzctl_global_conf()
{
	struct stat st;
	struct vzctl_config *conf;

	if (stat(GLOBAL_CFG, &st)) {
		logger(-1, errno, "Unable to read " GLOBAL_CFG);
		return NULL;
	}
	if (__gconf != NULL && __gconf->mtime == st.st_mtime)
		return __gconf;
	if ((conf = alloc_conf()) == NULL)
		return NULL;
	if (parse_conf_data(conf, GLOBAL_CFG, 0)) {
		free_conf(conf);
		return NULL;
	}
	free_conf(__gconf);
	__gconf = conf;
	__gconf->mtime = st.st_mtime;

	return __gconf;
}

int conf_parse(struct vzctl_config *conf, const char *fname, int flags)
{
	int ret;

	if (!(flags & VZCTL_CONF_SKIP_GLOBAL)) {
		const struct vzctl_config *g_conf = NULL;

		pthread_mutex_lock(get_global_conf_mtx());
		if ((g_conf = vzctl_global_conf()) == NULL) {
			pthread_mutex_unlock(get_global_conf_mtx());
			return VZCTL_E_NOMEM;
		}

		ret = merge_conf_data(conf, g_conf, local_param_filter);
		if (ret) {
			pthread_mutex_unlock(get_global_conf_mtx());
			return ret;
		}
		pthread_mutex_unlock(get_global_conf_mtx());
	}

	ret = xstrdup(&conf->fname, fname);
	if (ret)
		return ret;

	ret = parse_conf_data(conf, fname, flags);
	if (ret)
		return ret;

	return 0;
}

struct vzctl_config *vzctl2_conf_open(const char *fname, int flags, int *err)
{
	struct vzctl_config *conf;

	conf = alloc_conf();
	if (conf == NULL)
		return NULL;

	*err = conf_parse(conf, fname, flags);
	if (*err) {
		free_conf(conf);
		return NULL;
	}

	return conf;
}

int vzctl2_conf_parse(ctid_t ctid, struct vzctl_config *conf)
{
	return 0;
}

void vzctl2_conf_close(struct vzctl_config *conf)
{
	free_conf(conf);
}

int vzctl_conf_del_param(struct vzctl_config *conf, const char *name)
{
	return add_conf_data(conf, name, NULL, CONF_DATA_UPDATED);
}

int vzctl2_conf_get_param(const struct vzctl_config *conf, const char *name, const char **res)
{
	struct vzctl_config_data *conf_data;

	if ((conf_data = find_conf_data(conf, name)) != NULL)
		*res = conf_data->val;
	else
		*res = NULL;

	return 0;
}

int vzctl_conf_add_param(struct vzctl_config *conf, const char *name, const char *str)
{
	return add_conf_data(conf, name, str, CONF_DATA_UPDATED);
}

int vzctl2_conf_set_param(struct vzctl_config *conf, const char *name, const char *str)
{
	return vzctl_conf_add_param(conf, name, str);
}

