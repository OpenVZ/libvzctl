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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "list.h"
#include "vztypes.h"
#include "logger.h"
#include "config.h"
#include "util.h"

struct d_entry {
	list_elem_t list;
	char *name;
	int level;
};

static void free_d_entry(struct d_entry *entry)
{
	free(entry->name);
	free(entry);
}

static struct d_entry *new_entry(struct d_entry *root_ent, const char *name)
{
	int len, len_root;
	struct d_entry *ent;

	if ((ent = malloc(sizeof(struct d_entry))) == NULL) {
		logger(-1, errno, "Cannot allocate memory");
		return NULL;
	}

	len_root = strlen(root_ent->name);
	len = len_root + strlen(name) + 1;
	if ((ent->name = malloc(len + 1)) == NULL) {
		logger(-1, errno, "Cannot allocate memory");
		free(ent);
		return NULL;
	}

	sprintf(ent->name, "%s%s%s", root_ent->name,
		root_ent->name[len_root - 1] == '/' ? "" : "/", name);
	ent->level = root_ent->level + 1;

	return ent;
}

static void add_d_entry(list_head_t *head, struct d_entry *entry)
{
	list_add(&entry->list, head);
}

int vzctl2_is_ve_private(const char *root)
{
	DIR *dir;
	struct dirent *ent;
	int found = 0;

	if ((dir = opendir(root)) == NULL)
		return 0;

	while ((ent = readdir(dir)) != NULL) {
		/* Fixme: this is VE_PRIVATE if exists:
			ve.conf & .ve_layout
		*/
		if (!strcmp(ent->d_name, VZCTL_VE_LAYOUT) ||
		    !strcmp(ent->d_name, VZCTL_VE_CONF))
		{
			if (++found == 2) {
				closedir(dir);
				return 1;
			}
		}
	}
	closedir(dir);

	return 0;
}

static int scan_dir(list_head_t *pool, struct d_entry *root_ent)
{
	struct d_entry *entry;
	struct dirent *ent;
	struct stat st;
	char buf[PATH_MAX + 1];
	DIR *dir;
	int ret = 0, n;

	if ((dir = opendir(root_ent->name)) == NULL)
		return 0;

	while ((ent = readdir(dir)) != NULL) {
		if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
			continue;

		n = snprintf(buf, sizeof(buf), "%s/%s",
				root_ent->name, ent->d_name);
		if (n >= sizeof(buf))
			continue;

		if (stat(buf, &st) == 0 && !S_ISDIR(st.st_mode))
			continue;

		entry = new_entry(root_ent, ent->d_name);
		if (entry == NULL) {
			ret = -1;
			break;
		}

		add_d_entry(pool, entry);
	}
	closedir(dir);

	return ret;
}

int get_dir_list(list_head_t *head, const char *root, int level)
{
	struct d_entry *it, *tmp;
	struct d_entry root_entry;
	struct stat st_root, st;
	LIST_HEAD(pool);

	if (stat(root, &st_root)) {
		if (errno == ENOENT)
			return 0;
		return vzctl_err(-1, errno, "Unable to stat %s", root);
	}

	root_entry.name = (char *)root,
	root_entry.level = 0;
	if ((it = new_entry(&root_entry, "")) == NULL)
		return -1;

	add_d_entry(&pool, it);
	while (!list_empty(&pool)) {
		list_for_each_safe(it, tmp, &pool, list) {
			if (stat(it->name, &st) == 0 &&
					st.st_dev == st_root.st_dev &&
					(level == -1 || it->level <= level))
			{
				if (scan_dir(&pool, it))
					goto err;

				if (add_str_param(head, it->name) == NULL)
					goto err;
			}
			list_del(&it->list);
			free_d_entry(it);
		}
	}

	return 0;
err:

	list_for_each_safe(it, tmp, &pool, list) {
		list_del(&it->list);
		free_d_entry(it);
	}

	return -1;
}


