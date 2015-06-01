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
	if (entry->name != NULL) free(entry->name);
	free(entry);
}

static struct d_entry *new_entry(struct d_entry *root_ent, const char *name)
{
	int len, len_root;
	struct d_entry *ent;

	if ((ent = malloc(sizeof(struct d_entry))) == NULL)
		return NULL;
	len_root = strlen(root_ent->name);
	len = len_root + strlen(name) + 1;
	if ((ent->name = malloc(len + 1)) == NULL) {
		free(ent);
		return NULL;
	}
	sprintf(ent->name, "%s%s%s", root_ent->name,
		root_ent->name[len_root - 1] == '/' ? "" : "/", name);
	ent->level = root_ent->level + 1;
	return ent;
}

static inline void add_d_entry(list_head_t *head, struct d_entry *entry)
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
			fs & ve.conf & .ve_layout
		*/
		if (!strcmp(ent->d_name, "fs") ||
		    !strcmp(ent->d_name, VZCTL_VE_LAYOUT) ||
		    !strcmp(ent->d_name, VZCTL_VE_CONF))
		{
			if (++found > 2)
				break;
		}
	}
	closedir(dir);
	return (found > 2);
}

static int scan_dir(list_head_t *pool, struct d_entry *root_ent)
{
	struct d_entry *entry;
	struct dirent *ent;
	struct stat st;
	char buf[PATH_MAX + 1];
	DIR *dir;
	int ret = 0, nchars;

	if (vzctl2_is_ve_private(root_ent->name))
		return 1;
	if ((dir = opendir(root_ent->name)) == NULL)
		return 0;
	while ((ent = readdir(dir)) != NULL) {
		if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
			continue;
		nchars = snprintf(buf, sizeof(buf), "%s/%s", root_ent->name, ent->d_name);
		if (!nchars || nchars >= sizeof(buf))
			continue;
		/* ent->d_type on NFS always is DT_UNKNOWN, using stat instead */
		if ((stat(buf, &st) != 0) || !S_ISDIR(st.st_mode))
			continue;
		/* Fixme: Skip: template, pkgenv, *.migrated */
		if (!strcmp(ent->d_name, "template") ||
		    !strcmp(ent->d_name, "pkgenv") ||
		    strstr(ent->d_name, ".migrated") != NULL)
		{
			continue;
		}
		/* Skip processing NetApp .snapshot directory */
		if (root_ent->level == 1 && !strcmp(ent->d_name, ".snapshot"))
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

static int scan(list_head_t *head, char *root, int level)
{
	int ret;
	list_head_t pool, *p;
	struct d_entry *it, *tmp;
	struct d_entry root_entry;
	struct stat st_root, st;

	if (stat(root, &st_root)) {
		if (errno == ENOENT)
			return 0;
		logger(-1, errno, "Unable to stat %s", root);
		return -1;
	}
	root_entry.name = (char *)root,
	root_entry.level = 0;
	p = &pool;
	list_head_init(p);
	if ((it = new_entry(&root_entry, "")) == NULL)
		return -1;
	add_d_entry(p, it);
	while (!list_empty(p)) {
		list_for_each_safe(it, tmp, p, list) {
			if (stat(it->name, &st) == 0 &&
			    st.st_dev == st_root.st_dev &&
			    it->level <= level)
			{
				ret = scan_dir(p, it);
				if (ret == -1)
					goto err;
				if (ret &&
				    add_str_param(head, it->name) == NULL)
				{
					goto err;
				}
			}
			list_del(&it->list);
			free_d_entry(it);
		}
	}
	return 0;
err:

	list_for_each_safe(it, tmp, p, list) {
		list_del(&it->list);
		free_d_entry(it);
	}
	logger(-1, ENOMEM, "Scan %s", root);
	return -1;
}

/** Get list of private areas
 * This function scan file system and return found VE_PRIBVATE.
 * Algo: Read shared file system from STORAGE_LIST if not exists read from
 * /proc/mounts and look for fs && ve.conf && .ve_layout pattern.
 *
 * @return	Return array of (char *) found Container private areas terminated by 0
 *		NULL in case error
 */
char **vzctl2_scan_private(void)
{
	list_head_t head;
	char **storage;
	char **p;

	if ((storage = vzctl2_get_storage()) == NULL)
		return NULL;
	list_head_init(&head);
	for (p = storage; *p != NULL; p++) {
		if (scan(&head, *p, 5)) {
			free_str(&head);
			free_ar_str(storage);
			free(storage);
			return NULL;
		}
	}
	free_ar_str(storage);
	free(storage);
	p = list2ar_str(&head);
	free_str(&head);
	return p;
}
