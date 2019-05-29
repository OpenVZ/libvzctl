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

#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <time.h>
#include <pthread.h>
#include "env.h"

enum {
	CONF_DATA_NEW		= 0x01,
        CONF_DATA_UPDATED	= 0x02,
        CONF_DATA_STORED	= 0x04,
};

struct vzctl_data_param {
	const char *name;
	const char *data;
	int id;
};

struct vzctl_config_param {
	char *name;
	int id;
	char *alias;
};

struct vzctl_config_data {
        char *name;
        char *val;
        int mask;
};

struct vzctl_config_map {
	struct vzctl_config_data *data;
	int size;
	int last;
};

struct vzctl_config {
	time_t mtime;
	unsigned veid;
	char *fname;
	struct vzctl_config_map map;	    /**< Data in the NAME=DATA format */
};

typedef int (* param_filter_f)(const char *name);


#ifdef __cplusplus
extern "C" {
#endif
int local_param_filter(const char *name);
const struct vzctl_config_param *get_conf_param(const struct vzctl_config_param *param, struct vzctl_data_param *data);
const struct vzctl_config_param *param_get_by_name( const struct vzctl_config_param *param, const char *name);
const struct vzctl_config *vzctl_global_conf();
int add_conf_data(struct vzctl_config *conf, const char *name, const char *val, int mask);
pthread_mutex_t *get_global_conf_mtx();
struct vzctl_config_data *find_conf_data(const struct vzctl_config *conf, const char *name);
int vzctl_conf_del_param(struct vzctl_config *conf, const char *name);
int vzctl_conf_add_param(struct vzctl_config *conf, const char *name, const char *str);
int vzctl_set_param(struct vzctl_env_handle *h, const char *name, const char *str);
struct vzctl_config *alloc_conf();
int conf_parse(struct vzctl_config *conf, const char *fname, int flags);

#ifdef __cplusplus
}
#endif
#endif /*__CONFIG_H__ */
