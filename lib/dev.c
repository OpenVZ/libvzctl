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
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <string.h>
#include <mntent.h>
#include <dirent.h>

#include <linux/vzcalluser.h>

#include "vzerror.h"
#include "util.h"
#include "dev.h"
#include "env.h"
#include "logger.h"
#include "vz.h"
#include "exec.h"
#include "env_ops.h"

#define VZLINK          "vzlink"
#define VZLINKDEV       (0x7d << 8) /* major 125, minor 0 */
#define VZLINKDIR       "/etc/vz/dev/"

static int mk_vzlink(void)
{
	make_dir(VZLINKDIR, 1);
	unlink(VZLINKDIR VZLINK);
	return mknod(VZLINKDIR VZLINK, S_IFCHR | S_IRUSR | S_IWUSR, VZLINKDEV);
}

int setup_vzlink_dev(struct vzctl_env_handle *h, int flags)
{
	int ret;
	struct vzctl_dev_perm perm = {
		.dev = VZLINKDEV,
		.mask = S_IWOTH,
		.type = S_IFCHR | VE_USE_MINOR,
	};

	if (h->veid < 100)
		perm.mask |= S_IROTH;

	if (!(flags & VZCTL_SKIP_CONFIGURE))
		vzctl2_env_exec_fn2(h,(execFn) mk_vzlink, NULL, 0, 0);

	if ((ret = get_env_ops()->env_set_devperm(h, &perm)))
		return ret;

	return 0;
}

#define CAP_SYS_MODULE_STR "ConditionCapability=CAP_SYS_MODULE"
#define SYSTEMD_TMPFILES_SERVICE_CAP "/lib/systemd/system/systemd-tmpfiles-setup-dev.service"

static int remove_tmpfiles_caps(void)
{
	FILE *fp_src, *fp_dst;
	char unit[] = SYSTEMD_TMPFILES_SERVICE_CAP;
	char unit_t[] = SYSTEMD_TMPFILES_SERVICE_CAP".tmp";
	char buf[STR_MAX];
	struct stat st;
	int substituted = 0;
	int ret = -1;
	int len;

	if (stat(unit, &st)) {
		if (errno == ENOENT)
			return 0;
		return vzctl_err(-1, errno, "Failed to stat %s", unit);
	}

	if ((fp_src = fopen(unit, "r")) == NULL)
		return vzctl_err(-1, errno, "Failed to open %s for read",
			unit);

	if ((fp_dst = fopen(unit_t, "w")) == NULL) {
		fclose(fp_src);
		return vzctl_err(-1, errno, "Failed to open %s for write",
				unit_t);
	}

	while (fgets(buf, sizeof(buf), fp_src)) {
		if (strstr(buf, CAP_SYS_MODULE_STR)) {
			buf[0] = '\n';
			buf[1] = 0;
			substituted = 1;
		}

		len = strlen(buf);

		if (fwrite(buf, 1, len, fp_dst) < len) {
			logger(-1, errno, "Failed to write %s", unit_t);
			goto err;
		}
	}

	if (ferror(fp_src) || !feof(fp_src)) {
		logger(-1, errno, "fgets() from %s error", unit);
		goto err;
	}

	if (substituted) {
		if (rename(unit_t, unit)) {
			logger(-1, errno, "Failed to move %s to %s",
					unit_t, unit);
			goto err;
		}
		if (fchown(fileno(fp_dst), st.st_uid, st.st_gid))
			logger(-1, errno, "Can set owner for %s", unit);
		if (fchmod(fileno(fp_dst), st.st_mode & 07777))
			logger(-1, errno, "Can set mode for %s", unit);
	} else {
		unlink(unit_t);
	}

	ret = 0;

err:
	fclose(fp_dst);
	fclose(fp_src);

	return ret;
}

static int create_tmpfiles(const char *name, mode_t mode, dev_t dev)
{
	FILE *fp;
	char *p;
	char buf[STR_SIZE];
		
	snprintf(buf, sizeof(buf), "/etc/tmpfiles.d/device-%s.conf",
			get_devname(name));
	logger(0, 0, "Create %s", buf);
	fp = fopen(buf, "w");
	if (fp == NULL)
		return vzctl_err(-1, errno, "Failed to create %s", buf);

	snprintf(buf, sizeof(buf), "%s", name);
	p = strrchr(buf, '/');
	if (p != NULL) {
		*p = '\0';
		if (strcmp(buf, "/dev"))
			fprintf(fp, "d %s 0755 root root\n", buf);
	}
	fprintf(fp, "%c %s 0700 root root - %d:%d\n",
			S_ISBLK(mode) ? 'b' : 'c',
			name, gnu_dev_major(dev), gnu_dev_minor(dev));
	fclose(fp);

	return 0;
}

static const char *get_static_dev_dir(void)
{
	if (access("/etc/udev/devices", F_OK) == 0)
		return "/etc/udev/devices";
	else if (access("/lib/udev/devices", F_OK) == 0)
		return "/lib/udev/devices";
	else if (access("/etc/tmpfiles.d", F_OK) == 0)
		return "/etc/tmpfiles.d";

	return NULL;
}

int create_static_dev(const char *name, mode_t mode, dev_t dev)
{
	const char *dir;
	char buf[STR_SIZE];
	char device[STR_SIZE];
	
	if (name == NULL)
		return 0;

	if (name[0] != '/')
		snprintf(device, sizeof(device), "/dev/%s", name);
	else
		snprintf(device, sizeof(device), "%s", name);

	make_dir(device, 0);
	unlink(device);
	if (mknod(device, mode, dev))
		logger(-1, errno, "Failed to mknod %s", device);

	/* Additionally create static entry  */
	dir = get_static_dev_dir();
	if (dir != NULL) {
		if (strcmp(dir, "/etc/tmpfiles.d") == 0) {
			create_tmpfiles(device, mode, dev);
		} else {
			snprintf(buf, sizeof(buf), "%s/%s", dir,
					get_devname(device));
			unlink(buf);
			if (mknod(buf, mode, dev))
				logger(-1, errno, "Failed to mknod %s", buf);
		}
	}

	return 0;
}

static void clean_dev_file(const char *dir, const char *filter)
{
	DIR *dp;
	struct dirent *ep;

	if (dir == NULL)
		return;

	dp = opendir(dir);
	if (dp == NULL)
		return;

	while ((ep = readdir(dp))) {
		if (strstr(ep->d_name, filter))
			unlinkat(dirfd(dp), ep->d_name, 0);
	}
	closedir(dp);
}

void clean_static_dev(const char *filter)
{
	clean_dev_file(get_static_dev_dir(), filter);
}

static int create_devs(struct vzctl_dev_param *devs)
{
	struct vzctl_dev_perm *it;
	list_head_t *head = &devs->dev;

	list_for_each(it, head, list) {
		if (it->name[0] == '\0')
			continue;

		create_static_dev(it->name,
				(it->type & (S_IFBLK | S_IFCHR)) | S_IRUSR | S_IWUSR,
				it->dev);
	}

	return 0;
}

int apply_dev_param(struct vzctl_env_handle *h, struct vzctl_env_param *env, int flags)
{
	struct vzctl_dev_perm *it;
	struct vzctl_dev_param *dev = env->dev;
	list_head_t *head = &dev->dev;
	int ret = 0;
	struct stat st;
	char buf[STR_SIZE];

	if (list_empty(&dev->dev))
		return 0;

	if (!is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_NOT_RUN, 0,
				"Unable to apply devperm: Container is not running");
	logger(0, 0, "Setting devices");
	list_for_each(it, head, list) {
		if (it->name[0] == '\0')
			continue;

		snprintf(buf, sizeof(buf), "/dev/%s", it->name);
		if (stat(buf, &st)) {
			if (errno == ENOENT)
				logger(-1, 0, "Unable to set up the devices:"
						" Incorrect name is specified, or no"
						" such a device (%s) is available", buf);
			else
				logger(-1, errno, "Unable to find"
						" the device %s", buf);
			if (flags & VZCTL_SKIP_CONFIGURE)
				continue;
			return VZCTL_E_SET_DEVICES;
		}
		if (!S_ISCHR(st.st_mode) && !S_ISBLK(st.st_mode))
			return vzctl_err(VZCTL_E_SET_DEVICES, 0, "%s is not a block or"
					" character device", buf);
		it->dev = st.st_rdev;
		it->type = (st.st_mode & (S_IFBLK | S_IFCHR)) | VE_USE_MINOR;
	}

	if (!(flags & VZCTL_SKIP_CONFIGURE))
		vzctl2_env_exec_fn2(h, (execFn) create_devs, (void *)dev, 0, 0);

	list_for_each(it, head, list) {
		if ((ret = get_env_ops()->env_set_devperm(h, it)))
			return ret;
	}
	return 0;
}

struct vzctl_dev_param *alloc_dev_param()
{
	struct vzctl_dev_param *dev;

	dev = malloc(sizeof(struct vzctl_dev_param));
	if (dev == NULL)
		return NULL;
	list_head_init(&dev->dev);
	list_head_init(&dev->dev_del);
	list_head_init(&dev->pci);
	list_head_init(&dev->pci_del);
	return dev;
}

int add_dev_param(list_head_t *head, struct vzctl_dev_perm *perm)
{
	struct vzctl_dev_perm *new;

	new = malloc(sizeof(struct vzctl_dev_perm));
	if (new == NULL)
		return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "add_dev_param");
	memcpy(new, perm, sizeof(struct vzctl_dev_perm));
	list_add_tail(&new->list, head);

	return 0;
}

void free_dev_param(struct vzctl_dev_param *dev)
{
	struct vzctl_dev_perm *tmp, *it;
	list_head_t *head;

	head = &dev->dev;
	list_for_each_safe(it, tmp, head, list) {
		list_del(&it->list);
		free(it);
	}

	head = &dev->dev_del;
	list_for_each_safe(it, tmp, head, list) {
		list_del(&it->list);
		free(it);
	}

	free_str(&dev->pci);
	free_str(&dev->pci_del);

	free(dev);
}

static const char *devperm2str(unsigned int perms, char mask[5])
{
	int i = 0;

	if (perms == 0)
		return "none";

	if (perms & S_IROTH)
		mask[i++] = 'r';
	if (perms & S_IWOTH)
		mask[i++] = 'w';
	if (perms & S_IXGRP)
		mask[i++] = 'q';
	mask[i] = '\0';

	return mask;
}

/*
 * Parse device permission string and set corresponding bits in the permission
 * mask.  The caller is responsible for clearing the mask before the call.
 */
static int parse_dev_perm(const char *str, unsigned int *perms)
{
	const char *ch;

	*perms = 0;
	if (strcmp(str, "none")) {
		for (ch = str; *ch; ch++) {
			if (*ch == 'r')
				*perms |= S_IROTH;
			else if (*ch == 'w')
				*perms |= S_IWOTH;
			else if (*ch == 'q')
				*perms |= S_IXGRP;
			else
				return vzctl_err(VZCTL_E_INVAL, 0,
						"An incorrect permision is specified: %s", str);
		}
	}
	return 0;
}

int parse_devices_str(struct vzctl_dev_perm *perm, const char *str)
{
	int ret;
	unsigned long val, major;
	char type[2];
	char minor[32];
	char mode[6];

	ret = sscanf(str, "%1[^:]:%lu:%16[^:]:%5s", type, &major, minor, mode);
	if (ret != 3 && ret != 4)
		return vzctl_err(VZCTL_E_INVAL, 0, "An incorrect device format: %s", str);
	bzero(perm, sizeof(struct vzctl_dev_perm));
	if (!strcmp(type, "b"))
		perm->type = S_IFBLK;
	else if (!strcmp(type, "c"))
		perm->type = S_IFCHR;
	else
		return vzctl_err(VZCTL_E_INVAL, 0, "An incorrect device type: %s", str);
	if (!strcmp(minor, "all")) {
		perm->use_major = VE_USE_MAJOR;
		perm->type |= VE_USE_MAJOR;
		perm->dev = makedev(major, 0);
	} else {
		perm->type |= VE_USE_MINOR;
		if (parse_ul(minor, &val))
			return vzctl_err(VZCTL_E_INVAL, 0, "An incorrect minor: %s", str);
		perm->dev = makedev(major, val);
	}
	return parse_dev_perm(mode, &perm->mask);
}

int parse_devices(struct vzctl_dev_param *dev, const char *val)
{
	char *buf = NULL;
	char *token;
	int ret = 0;
	struct vzctl_dev_perm perm;
	char *savedptr;

	ret = xstrdup(&buf, val);
	if (ret)
		return ret;
	if ((token = strtok_r(buf, LIST_DELIMITERS, &savedptr)) != NULL) {
		do {
			ret = parse_devices_str(&perm, token);
			if (ret)
				break;
			ret = add_dev_param(&dev->dev, &perm);
			if (ret)
				break;
		} while ((token = strtok_r(NULL, LIST_DELIMITERS, &savedptr)));
	}
	free(buf);
	return ret;
}

int parse_devnodes_str(struct vzctl_dev_perm *perm, const char *str)
{
	char *ch;
	int len;
	char buf[PATH_MAX];
	struct stat st;

	if ((ch = strchr(str, ':')) == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0, "An incorrect device format: %s", str);
	ch++;
	len = ch - str;
	if (len > sizeof(perm->name))
		return VZCTL_E_INVAL;
	bzero(perm, sizeof(struct vzctl_dev_perm));
	snprintf(perm->name, len, "%s", str);
	snprintf(buf, sizeof(buf), "/dev/%s", perm->name);
	if (stat(buf, &st))
		return vzctl_err(VZCTL_E_SET_DEVICES, errno, "An incorrect device name %s", buf);
	if (S_ISCHR(st.st_mode))
		perm->type = S_IFCHR;
	else if (S_ISBLK(st.st_mode))
		perm->type = S_IFBLK;
	else
		return vzctl_err(VZCTL_E_SET_DEVICES, 0, "The %s is not block or character device", buf);
	perm->dev = st.st_rdev;
	perm->type |= VE_USE_MINOR;

	return parse_dev_perm(ch, &perm->mask);
}

int parse_devnodes(struct vzctl_dev_param *dev, const char *val)
{
	char *buf;
	char *token;
	struct vzctl_dev_perm perm;
	int ret = 0;
	char *savedptr;

	buf = strdup(val);
	if ((token = strtok_r(buf, LIST_DELIMITERS, &savedptr)) != NULL) {
		do {
			ret = parse_devnodes_str(&perm, token);
			if (ret)
				break;
			ret = add_dev_param(&dev->dev, &perm);
			if (ret)
				break;
		} while ((token = strtok_r(NULL, LIST_DELIMITERS, &savedptr)));
	}
	free(buf);
	return ret;
}

char *devices2str(struct vzctl_dev_param *dev)
{
	char mask[5];
	int r;
	unsigned int major, minor;
	struct vzctl_dev_perm *it;
	list_head_t *head = &dev->dev;
	char buf[STR_MAX] = "";
	char *sp, *ep;

	if (list_empty(&dev->dev))
		return NULL;
	sp = buf;
	ep = buf + sizeof(buf) - 1;
	list_for_each(it, head, list) {
		if (it->name[0])
			continue;
		major = major(it->dev);
		minor = minor(it->dev);
		if (it->use_major) {
			r = snprintf(sp, ep - sp,"%c:%d:all:%s ",
					S_ISBLK(it->type) ? 'b' : 'c', major,
					devperm2str(it->mask, mask));
		} else {
			r = snprintf(sp, ep - sp,"%c:%d:%d:%s ",
					S_ISBLK(it->type) ? 'b' : 'c', major, minor,
					devperm2str(it->mask, mask));
		}
		sp += r;
		if ((r < 0) || (sp >= ep)) {
			logger(-1, 0, "devices2str: buffer truncation");
			break;
		}
	}
	return strdup(buf);
}

char *devnodes2str(struct vzctl_dev_param *dev)
{
	char mask[3];
	int r;
	struct vzctl_dev_perm *it;
	list_head_t *head = &dev->dev;
	char buf[STR_MAX] = "";
	char *sp, *ep;

	if (list_empty(&dev->dev))
		return NULL;
	sp = buf;
	ep = buf + sizeof(buf) - 1;
	list_for_each(it, head, list) {
		if (it->name[0] == '\0' || it->mask == 0)
			continue;
		r = snprintf(sp, ep - sp,"%s:%s ",
				it->name, devperm2str(it->mask, mask));
		sp += r;
		if ((r < 0) || (sp >= ep)) {
			logger(-1, 0, "devnodes2str: buffer truncation");
			break;
		}
	}
	return strdup(buf);
}

char *pci2str(struct vzctl_dev_param *old, struct vzctl_dev_param *new)
{
	char *str;
	LIST_HEAD(empty);
	LIST_HEAD(merged);
	list_head_t *_old = old == NULL ? &empty : &old->pci;
	list_head_t *_add = new == NULL ? &empty : &new->pci;
	list_head_t *_del = new == NULL ? &empty : &new->pci_del;

	if (list_empty(_add) &&
			list_empty(_del))
		return NULL;

	merge_str_list(_old, _add, _del, 0, &merged);
	str = list2str(NULL, &merged);
	free_str(&merged);

	return str;
}

int parse_pcidev_str(const char *str, char *dev, int size)
{
	int domain, n;
	unsigned int bus, slot, func;

	n = sscanf(str, "%x:%x:%x.%d", &domain, &bus, &slot, &func);
	if (n != 4) {
		domain = 0;
		n = sscanf(str, "%x:%x.%d", &bus, &slot, &func);
		if (n != 3)
			return vzctl_err(VZCTL_E_INVAL, 0,
					"Incorrect pci device syntax: %s", str);
	}
	snprintf(dev, size, "%04x:%02x:%02x.%d",
			domain, bus, slot, func);

	return 0;
}

int parse_pcidev(list_head_t *head, const char *val, int validate, int replace)
{
	char *tmp = NULL;
	char *token, *savedptr;
	char buf[STR_SIZE];
	char path[1024];
	int ret;

	if (replace)
		free_str(head);

	ret = xstrdup(&tmp, val);
	if (ret)
		return ret;

	if ((token = strtok_r(tmp, LIST_DELIMITERS, &savedptr)) == NULL) {
		free(tmp);
		return 0;
	}
	do {
		ret = parse_pcidev_str(token, buf, sizeof(buf));
		if (ret)
			break;
		if (validate) {
			snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s", buf);
			if (stat_file(path) != 1) {
				ret = vzctl_err(VZCTL_E_INVAL, 0,
						"Incorrect PCI device: device '%s' not found", buf);
				break;
			}
		}
		if (!find_str(head, buf))
			add_str_param(head, buf);
	} while ((token = strtok_r(NULL, LIST_DELIMITERS, &savedptr)));
	free(tmp);

	return ret;
}

static int get_root_device(const char *dir, char *buf, int size)
{
	FILE *fp;
	struct mntent *mnt;
	int ret = -1;

	*buf = '\0';
	if ((fp = setmntent( "/proc/1/mounts", "r")) == NULL)
		return vzctl_err(-1, errno, "Unable to open /proc/mounts");

	while ((mnt = getmntent(fp)) != NULL) {
		if (!strcmp(mnt->mnt_type, "rootfs"))
			continue;
		if (!strcmp(mnt->mnt_dir, dir)) {
			snprintf(buf, size, "%s", mnt->mnt_fsname);
			ret = 0;
			break;
		}
	}
	endmntent(fp);
	return ret;
}

int create_root_dev(void *data)
{
	struct stat st;
	char device[STR_SIZE];
	const char *root = "/";

	if (get_root_device(root, device, sizeof(device)))
		return vzctl_err(-1, 0, "Unable to get the root device name");

	logger(10, 0, "Root device: %s", device);
	if (stat(root, &st))
		return vzctl_err(-1, errno, "Failed to stat /");

	remove_tmpfiles_caps();

	return create_static_dev(device, S_IFBLK | S_IRUSR | S_IWUSR, st.st_dev);
}

