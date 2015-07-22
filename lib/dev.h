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
#ifndef	_VZCTL_DEV_H_
#define	_VZCTL_DEV_H_

#include <sys/types.h>
#include "list.h"

#define DEV_MODE_READ		1
#define DEV_MODE_WRITE		2

/** Data structure for devices.
 */
struct vzctl_dev_perm {
	list_elem_t list;		/**< prev/next elements. */
	char name[32];			/**< device name. */
	dev_t dev;			/**< device number. */
	unsigned int type;		/**< S_IFBLK | S_IFCHR. */
	unsigned int mask;		/**< access mode. */
	int use_major;			/**< VE_USE_MAJOR | VE_USE_MINOR. */
};

struct vzctl_dev_param {
	list_head_t dev;
	list_head_t dev_del;
	list_head_t pci;
	list_head_t pci_del;
};

int parse_devnodes_str(struct vzctl_dev_perm *perm, const char *str);
int parse_devices_str(struct vzctl_dev_perm *perm, const char *str);
int add_dev_param(list_head_t *head, struct vzctl_dev_perm *perm);
int setup_vzlink_dev(struct vzctl_env_handle *h, int flags);
struct vzctl_dev_param *alloc_dev_param(void);
int apply_dev_param(struct vzctl_env_handle *h, struct vzctl_env_param *env, int flags);
int parse_devices(struct vzctl_dev_param *dev, const char *val);
int parse_devnodes(struct vzctl_dev_param *dev, const char *val);
char *devices2str(struct vzctl_dev_param *dev);
char *devnodes2str(struct vzctl_dev_param *dev, int ignore_none_perm);
char *pci2str(struct vzctl_dev_param *old, struct vzctl_dev_param *new);
int parse_pcidev(list_head_t *dev, const char *val, int validate, int replace);
void free_dev_param(struct vzctl_dev_param *dev);
int env_set_devperm(struct vzctl_env_handle *h, struct vzctl_dev_perm *perm);
int create_static_dev(const char *name, mode_t mode, dev_t dev);
void clean_static_dev(const char *filter);
int create_root_dev(void *data);

#endif
