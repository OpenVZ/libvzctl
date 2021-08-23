/*
 * Copyright (c) 2015-2017, Parallels International GmbH
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
 */

#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <errno.h>
#include <ploop/libploop.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/vzcalluser.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <dirent.h>

#include "vzerror.h"
#include "image.h"
#include "disk.h"
#include "util.h"
#include "logger.h"
#include "vztypes.h"
#include "exec.h"
#include "cgroup.h"
#include "dev.h"

struct exec_disk_param {
	struct vzctl_env_handle *h;
	struct vzctl_disk *disk;
	int automount;
};

int get_fs_uuid(const char *device, struct vzctl_disk *disk)
{
	struct stat st;
	FILE *fp;
	char *argv[] = {
		"/usr/sbin/blkid",
		(char *)device,
		NULL,
	};
	char buf[512];
	char *p;

	if (stat(argv[0], &st))
		return vzctl_err(-1, errno, "Unable to stat %s", argv[0]);

	fp = vzctl_popen(argv, NULL, 0);
	if (fp == NULL)
		return vzctl_err(-1, errno, "Unable to start %s", argv[0]);

	while (fgets(buf, sizeof(buf), fp)) {
		p = strstr(buf, " UUID=\"");
		if (p == NULL)
			break;
		strncpy(disk->fsuuid, p + 7, sizeof(fsuuid_t) - 1);
		disk->fsuuid[sizeof(fsuuid_t) - 1] = '\0';
		p = strchr(disk->fsuuid, '"');
		if (p != NULL)
			*p = '\0';

		p = strstr(buf, " TYPE=\"");
		if (p == NULL)
			break;
		strncpy(disk->fstype, p + 7, sizeof(fstype_t) - 1);
		disk->fstype[sizeof(fstype_t) - 1] = '\0';
		p = strchr(disk->fstype, '"');
		if (p != NULL)
			*p = '\0';
	}
	fclose(fp);

	if (disk->fsuuid[0] == '\0' || disk->fstype[0] == '\0')
		return vzctl_err(-1, 0, "Unable to get file system uuid dev=%s",
				 device);
	return 0;
}

static int write_fstab_entry(FILE *fp, const char *uuid, const char *mnt, const char *opts)
{
	if (fprintf(fp, "UUID=%s %s ext4 %s 0 0\n", uuid, mnt, opts ? opts : "defaults") == -1)
		return vzctl_err(-1, errno, "Failed to update /etc/fstab");
	return 0;
}

static const char *get_fsuuid(const char *str, char *buf)
{
	return (sscanf(str, "UUID=%38s", buf) == 1) ? buf : NULL;
}

#define SYSTEMD_BIN "systemd"
#define SYSTEMD_DIR "/etc/systemd/system"
#define SYSTEMD_TARGET_DIR "/etc/systemd/system/multi-user.target.wants"
#define SYSTEMD_UNIT_DESC "Description=ploop with UUID="
#define SYSTEMD_MOUNT_UNIT_SUFFIX ".mount"

static int is_systemd(void)
{
	char buf[PATH_MAX];
	char *p;
	int n;

	/* Check for systemd */
	if ((n = readlink("/sbin/init", buf, sizeof(buf) - 1)) > 0) {
		buf[n] = 0;
		if ((p = strrchr(buf, '/')) == NULL)
			p = buf;
		else
			p++;
		if (strncmp(p, SYSTEMD_BIN, sizeof(SYSTEMD_BIN) - 1) == 0)
			return 1;
	}

	return 0;
}

int env_configure_udev_rules(void)
{
	const char *fname = "/lib/udev/rules.d/60-persistent-storage.rules";
	const char *fname_tmp = "/lib/udev/rules.d/60-persistent-storage.rules.tmp";
	const char ptrn[] = "KERNEL!=\"loop*|";
	FILE *rfp = NULL, *wfp;
	struct stat st;
	int err = -1;
	int found = 0;
	char buf[4096];

	rfp = fopen(fname, "r");
	if (rfp == NULL) {
		if (errno == ENOENT)
			return 0;
		return vzctl_err(-1, errno, "Unable to open %s", fname);
	}

	if (fstat(fileno(rfp), &st)) {
		fclose(rfp);
		return vzctl_err(-1, errno, "Failed to stat %s", fname);
	}

	wfp = fopen(fname_tmp, "w+");
	if (wfp == NULL) {
		fclose(rfp);
		return vzctl_err(-1, errno, "Unable to create %s", fname_tmp);
	}

	if (fchmod(fileno(wfp), st.st_mode))
		vzctl_err(-1, errno, "fchmod");
	if (fchown(fileno(wfp), st.st_uid, st.st_gid))
		vzctl_err(-1, errno, "fchown");

	while (!feof(rfp)) {
		const char *p = buf;

		if (fgets(buf, sizeof(buf), rfp) == NULL) {
			if (ferror(rfp)) {
				logger(-1, 0, "Failed to read %s", fname);
				goto err;
			}
			break;
		}

		if (strncmp(ptrn, buf, sizeof(ptrn) - 1) == 0) {
			found = 1;
			if (fprintf(wfp, "KERNEL!=\"ploop*|") == -1)
				goto err;
			p = buf + sizeof("KERNEL!=");
		}

		if (fprintf(wfp, "%s", p) == -1)
			goto err;
	}

	if (!found) {
		err = 0;
		goto err;
	}

	logger(0, 0, "Configure %s", fname);
	if (rename(fname_tmp, fname)) {
		logger(-1, errno, "Failed to rename %s", fname_tmp);
		goto err;
	}

	err = 0;
err:
	fclose(wfp);
	fclose(rfp);
	unlink(fname_tmp);

	return err;
}


static void get_systemd_mount_unit_name(const char *mnt, char *name)
{
	int i;

	// Skip first
	strcpy(name, mnt + 1);

	for (i = 0; i < strlen(name); i++) {
		if (name[i] == '/')
			name[i] = '-';
	}

	strcat(name, SYSTEMD_MOUNT_UNIT_SUFFIX);
}

static int env_configure_systemd_unit(const char *uuid, const char *mnt, const char *opts)
{
	int err = -1;
	char systemd_unit_name[PATH_MAX];
	char systemd_unit_path[PATH_MAX + 32];
	char systemd_link_path[PATH_MAX + 64];
	char options[PATH_MAX] = "";
	FILE *wfp;

	logger(1, 0, "Configure systemd mount unit uuid=%s %s", uuid, mnt);

	// systemd requires that unit name equals mountpoint
	get_systemd_mount_unit_name(mnt, systemd_unit_name);

	snprintf(systemd_unit_path, sizeof(systemd_unit_path),
		SYSTEMD_DIR "/%s", systemd_unit_name);

	wfp = fopen(systemd_unit_path, "w+");
	if (wfp == NULL)
		return vzctl_err(-1, errno, "Unable to create %s", systemd_unit_path);

	if (opts)
		snprintf(options, sizeof(options), "Options=%s\n", opts);

	if (fprintf(wfp, "[Unit]\n" \
SYSTEMD_UNIT_DESC "%s mount unit\n" \
"DefaultDependencies=no\n" \
"Before=vzfifo.service\n" \
"\n" \
"[Mount]\n" \
"What=/dev/disk/by-uuid/%s\n" \
"Where=%s\n" \
"%s" \
"\n" \
"[Install]\n" \
"WantedBy=multi-user.target\n", uuid, uuid, mnt, options) == -1) {
		logger(-1,  errno, "Unable to write to %s", systemd_unit_path);
		goto err;
	}

	snprintf(systemd_link_path, sizeof(systemd_link_path),
		SYSTEMD_TARGET_DIR "/%s", systemd_unit_name);

	unlink(systemd_link_path);
	if (symlink(systemd_unit_path, systemd_link_path))
		logger(-1, errno, "Failed to create link %s", systemd_link_path);

	err = 0;
err:
	fclose(wfp);
	if (err != 0)
		unlink(systemd_unit_path);
	return err;
}

static int env_configure_fstab(const char *uuid, const char *mnt, const char *opts)
{
	FILE *rfp, *wfp;
	struct stat st;
	int err = -1;
	int found = 0;
	char buf[4096];
	char fsuuid[39];

	logger(1, 0, "Configure fstab uuid=%s %s", uuid, mnt);

	rfp = fopen("/etc/fstab", "a+");
	if (rfp == NULL)
		return vzctl_err(-1, errno, "Unable to open /etc/fstab");

	if (fstat(fileno(rfp), &st)) {
		fclose(rfp);
		return vzctl_err(-1, errno, "Failed to stat /etc/fstab");
	}

	wfp = fopen("/etc/fstab.tmp", "w+");
	if (wfp == NULL) {
		fclose(rfp);
		return vzctl_err(-1, errno, "Unable to create /etc/fstab.tmp");
	}

	set_fattr(fileno(wfp), &st);

	while (!feof(rfp)) {
		if (fgets(buf, sizeof(buf), rfp) == NULL) {
			if (ferror(rfp)) {
				logger(-1, 0, "Failed to read /etc/fstab");
				goto err;
			}
			break;
		}

		if (get_fsuuid(buf, fsuuid) && !strcmp(uuid, fsuuid)) {
			if (write_fstab_entry(wfp, uuid, mnt, opts))
				goto err;
			found = 1;
		} else {
			if (fprintf(wfp, "%s", buf) == -1) {
				logger(-1,  errno, "Unable to write to /etc/fstab.tmp");
				goto err;
			}
		}
	}
	if (!found && write_fstab_entry(wfp, uuid, mnt, opts))
		goto err;

	if (rename("/etc/fstab.tmp", "/etc/fstab")) {
		logger(-1, errno, "Failed to rename  /etc/fstab.tmp");
		goto err;
	}

	err = 0;
err:
	fclose(wfp);
	fclose(rfp);
	unlink("/etc/fstab.tmp");

	return err;
}

int send_uevent(const char *part)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "/sys/class/block/%s/uevent",
			get_devname(part));
	return write_data(path, "add");
}

static int read_line(const char *fname, char *out, int size)
{
	int len, fd;

	fd = open(fname, O_RDONLY);
	if (fd == -1)
		return vzctl_err(-1, errno, "Can't open %s", fname);

	len = read(fd, out, size);
	if (len == -1) {
		close(fd);
		return vzctl_err(-1, errno, "Can't read from %s", fname);
	}

	if (len > 0 && out[len -1] == '\n')
		out[len - 1] = '\0';

	close(fd);

	return 0;
}

static int do_mknod(const char *devname, const char *sysname, dev_t dev)
{
	char d[128], f[64], name[64];

	snprintf(f, sizeof(f), "/sys/class/block/%s/dm/name",
			get_devname(devname));
	if (read_line(f, name, sizeof(name)-1) == 0)
		snprintf(d, sizeof(d), "/dev/mapper/%s", name);
	else
		snprintf(d, sizeof(d), "%s", devname);

	if (make_dir(d, 0))
		return -1;

	unlink(d);
	if (mknod(d, S_IFBLK | S_IRUSR | S_IWUSR,dev) && errno != EEXIST)
		return vzctl_err(-1, errno, "mknod %s", d);

	return send_uevent(sysname);
}

static int env_configure_disk(struct exec_disk_param *param)
{
	int ret;
	struct vzctl_disk *disk = param->disk;

	ret = do_mknod(disk->devname, disk->sys_devname, disk->dev);
	if (ret)
		return ret;
	ret = do_mknod(disk->partname, disk->sys_partname, disk->part_dev);
	if (ret)
		return ret;
	if (disk->mnt != NULL && !is_root_disk(disk)) {
		if (access(disk->mnt, F_OK))
			make_dir(disk->mnt, 1);

		ret = is_dm_device(disk->part_dev);
		if (ret == -1)
			return -1;
		else if (ret == 1)
			goto skip_configure;

		if (is_systemd()) {
			// skip unit configure for runing CT #PSBM-33596
			if (param->h->ctx->state == VZCTL_STATE_STARTING &&
			   	 env_configure_systemd_unit(disk->fsuuid,
						disk->mnt, disk->mnt_opts))
				return -1;
		} else {
			if (env_configure_fstab(disk->fsuuid, disk->mnt,
						disk->mnt_opts))
				return -1;
		}

skip_configure:
		if (param->automount || disk->automount) {
			if (mount(disk->partname, disk->mnt, disk->fstype, 0, NULL))
				return vzctl_err(-1, errno, "Failed to mount %s %s",
					disk->partname, disk->mnt);
		}
	}

	return 0;
}

int configure_disk(struct vzctl_env_handle *h, struct vzctl_disk *disk,
		int flags, int automount)
{
	struct exec_disk_param param = {
		.h = h,
		.disk = disk,
		.automount = (flags & VZCTL_RESTORE) ? 0 : automount,
	};

	logger(3, 0, "Configure %s automount=%d", disk->partname, automount);
	if (vzctl_env_exec_fn(h, (execFn) env_configure_disk, &param,
			VZCTL_SCRIPT_EXEC_TIMEOUT))
		return vzctl_err(VZCTL_E_DISK_CONFIGURE, 0, "Failed to configure disk");

	return 0;
}

static struct vzctl_disk *find_disk_by_fsuuid(struct vzctl_env_disk *env_disk, const char *fsuuid)
{
	struct vzctl_disk *disk;

	list_for_each(disk, &env_disk->disks, list)
		if (!strcmp(disk->fsuuid, fsuuid))
			return disk;

	return NULL;
}

static int env_fin_configure_fstab(struct vzctl_env_disk *env_disk)
{
	FILE *rfp = NULL, *wfp;
	struct stat st;
	int err = -1;
	char buf[4096];
	char fsuuid[39];

	rfp = fopen("/etc/fstab", "r");
	if (rfp == NULL)
		return vzctl_err(-1, errno, "Unable to open /etc/fstab");

	if (fstat(fileno(rfp), &st)) {
		fclose(rfp);
		return vzctl_err(-1, errno, "Failed to stat /etc/fstab");
	}

	wfp = fopen("/etc/fstab.tmp", "w+");
	if (wfp == NULL) {
		fclose(rfp);
		return vzctl_err(-1, errno, "Unable to create /etc/fstab.tmp");
	}

	set_fattr(fileno(wfp), &st);

	while (!feof(rfp)) {
		if (fgets(buf, sizeof(buf), rfp) == NULL) {
			if (ferror(rfp)) {
				logger(-1, 0, "Failed to read /etc/fstab");
				goto err;
			}
			break;
		}

		if (get_fsuuid(buf, fsuuid) == NULL ||
				find_disk_by_fsuuid(env_disk, fsuuid) != NULL)
		{
			if (fprintf(wfp, "%s", buf) == -1) {
				logger(-1,  errno, "Unable to write to /etc/fstab.tmp");
				goto err;
			}
		}
	}

	if (rename("/etc/fstab.tmp", "/etc/fstab")) {
		logger(-1, errno, "Failed to rename  /etc/fstab.tmp");
		goto err;
	}

	err = 0;
err:
	fclose(wfp);
	fclose(rfp);
	unlink("/etc/fstab.tmp");

	return err;
}

static int is_ploop_unit(const char *path)
{
	FILE *rfp = NULL;
	char buf[16384];

	rfp = fopen(path, "r");
	if (rfp == NULL)
		return 0;

	while(fgets(buf, sizeof(buf), rfp) != NULL) {
		if (strncmp(SYSTEMD_UNIT_DESC, buf, sizeof(SYSTEMD_UNIT_DESC) - 1) == 0) {
			fclose(rfp);
			return 1;
		}
	}
	fclose(rfp);

	return 0;
}

static int is_existing_ploop(struct vzctl_env_disk *env_disk, const char *dentry)
{
	struct vzctl_disk *disk;
	char unit[PATH_MAX];

	list_for_each(disk, &env_disk->disks, list) {
		if (disk->mnt == NULL)
			continue;
		get_systemd_mount_unit_name(disk->mnt, unit);
		if (!strcmp(unit, dentry))
			return 1;
	}

	return 0;
}

static int env_fin_configure_systemd_unit(struct vzctl_env_disk *env_disk)
{
	int err = 0;
	DIR *dir;
	struct dirent *de;
	char *ext;
	char path[PATH_MAX];
	char unit_link[PATH_MAX + 64];
	struct stat st;

	/* scan directory with systemd units */
	dir = opendir(SYSTEMD_DIR);
	if (!dir) {
		logger(-1, errno, "Failed to open %s dir", SYSTEMD_DIR);
		return -1;
	}

	while (1) {
		errno = 0;
		if (!(de = readdir(dir))) {
			if (errno)
				err = vzctl_err(-1, errno, "readdir(\"%s\") error", SYSTEMD_DIR);
			break;
		}

		/* Is file? */
		snprintf(path, PATH_MAX, SYSTEMD_DIR "/%s", de->d_name);

		if (lstat(path, &st)) {
			err = vzctl_err(-1, errno, "stat(\"%s\") error", path);
			break;
		}

		if (!S_ISREG(st.st_mode))
			continue;

		/* Is our file? */
		ext = strrchr(de->d_name, '.');
		if (ext == NULL || strcmp(ext, SYSTEMD_MOUNT_UNIT_SUFFIX))
			continue;

		// Check for ploop unit
		if (!is_ploop_unit(path))
			continue;

		// Check for existing ploop
		if (is_existing_ploop(env_disk, de->d_name))
			continue;

		// Unlink!
		unlink(path);
		snprintf(unit_link, sizeof(unit_link), SYSTEMD_TARGET_DIR "/%s", de->d_name);
		unlink(unit_link);
	}

	closedir(dir);
	return err;
}

int env_fin_configure_disk(struct vzctl_env_disk *disk)
{
	if (is_systemd()) {
		if (env_fin_configure_systemd_unit(disk))
			return VZCTL_E_DISK_CONFIGURE;
	}

	if (access("/etc/fstab", F_OK) == 0 && env_fin_configure_fstab(disk))
		return VZCTL_E_DISK_CONFIGURE;

	return 0;
}

int fin_configure_disk(struct vzctl_env_handle *h, struct vzctl_env_disk *disk)
{
	if (vzctl_env_exec_fn(h, (execFn) env_fin_configure_disk, disk,
				VZCTL_SCRIPT_EXEC_TIMEOUT))
		return vzctl_err(VZCTL_E_DISK_CONFIGURE, 0,
				"Failed to finalize disk configure");
	return 0;
}
