/*
 * Copyright (c) 2015 Parallels IP Holdings GmbH
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
	const char *fsuuid;
	const char *device;
	const char *part;
	dev_t dev;
	struct vzctl_disk *disk;
	int automount;
};

int get_fs_uuid(const char *device, char *uuid)
{
	struct stat st;
	FILE *fp;
	int n = 0;
	char *argv[] = {
		"/sbin/dumpe2fs",
		"-h",
		(char *)device,
		NULL,
	};
	char buf[512];

	if (stat(argv[0], &st))
		return vzctl_err(-1, errno, "Unable to stat %s", argv[0]);

	fp = vzctl_popen(argv, NULL, 0);
	if (fp == NULL)
		return vzctl_err(-1, errno, "Unable to start %s", argv[0]);

	while (fgets(buf, sizeof(buf), fp)) {
		n = sscanf(buf, "Filesystem UUID: %38s", uuid);
		if (n == 1)
			break;
	}
	fclose(fp);

	if (n != 1)
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

static int check_systemd(void)
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
	char systemd_unit_path[PATH_MAX];
	char systemd_link_path[PATH_MAX];
	char options[PATH_MAX] = "";
	FILE *wfp;

	if (check_systemd() == 0)
		return 0;

	// Check that systemd started: exit if so, see #PSBM-33596
	if (access("/run/systemd", F_OK) == 0)
		return 0;

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

static int env_configure_disk(struct exec_disk_param *param)
{
	struct vzctl_disk *disk = param->disk;
	const char *device = param->device;

	if (create_static_dev(device, S_IFBLK | S_IRUSR | S_IWUSR,
				param->dev))
		return -1;

	if (send_uevent(param->part))
		return -1;

	if (disk->mnt != NULL && param->fsuuid != NULL) {
		if (access(disk->mnt, F_OK))
			make_dir(disk->mnt, 1);

		if (env_configure_fstab(param->fsuuid, disk->mnt, disk->mnt_opts))
			return -1;

		if (env_configure_systemd_unit(param->fsuuid, disk->mnt, disk->mnt_opts))
			return -1;

		if (param->automount && mount(device, disk->mnt, "ext4", 0, NULL))
			return vzctl_err(-1, errno, "Failed to mount %s",  disk->mnt);
	}

	return 0;
}

int configure_disk(struct vzctl_env_handle *h, struct vzctl_disk *disk,
		dev_t dev, const char *device, const char *part,
		int flags, int automount)
{
	struct exec_disk_param param = {
		.fsuuid = disk->fsuuid,
		.device = device,
		.part = part,
		.dev = dev,
		.disk = disk,
		.automount = automount
	};

	if (vzctl2_env_exec_fn2(h, (execFn) env_configure_disk, &param, VZCTL_SCRIPT_EXEC_TIMEOUT,
				(flags & VZCTL_RESTORE ? VE_SKIPLOCK : 0)))
		return vzctl_err(VZCTL_E_DISK_CONFIGURE, 0, "Failed to configure disk");

	return 0;
}

static struct vzctl_disk *find_disk_by_fsuuid(struct vzctl_env_disk *env_disk, const char *fsuuid)
{
	struct vzctl_disk *disk;

	list_for_each(disk, &env_disk->disks, list)
		if (disk->fsuuid != NULL && !strcmp(disk->fsuuid, fsuuid))
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
	int err = -1;
	DIR *dir;
	char dirent_buf[sizeof(struct dirent) + PATH_MAX];
	struct dirent *de = (struct dirent *) dirent_buf;
	struct dirent *result;
	char *ext;
	char path[PATH_MAX];
	char unit_link[PATH_MAX];
	struct stat st;

	if (check_systemd() == 0)
		return 0;

	/* scan directory with systemd units */
	dir = opendir(SYSTEMD_DIR);
	if (!dir) {
		logger(-1, errno, "Failed to open %s dir", SYSTEMD_DIR);
		return -1;
	}

	while (1) {
		if (readdir_r(dir, de, &result) != 0) {
			logger(-1, errno, "readdir_r(\"%s\") error", SYSTEMD_DIR);
			break;
		}

		if (result == NULL) {
			err = 0;
			break;
		}

		/* Is file? */
		snprintf(path, PATH_MAX, SYSTEMD_DIR "/%s", de->d_name);

		if (lstat(path, &st)) {
			logger(-1, errno, "stat(\"%s\") error", path);
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
	int ret = 0;

	if (env_fin_configure_fstab(disk))
		ret = VZCTL_E_DISK_CONFIGURE;

	if (env_fin_configure_systemd_unit(disk))
		ret = VZCTL_E_DISK_CONFIGURE;

	return ret;
}

int fin_configure_disk(struct vzctl_env_handle *h, struct vzctl_env_disk *disk)
{
	if (vzctl2_env_exec_fn2(h, (execFn) env_fin_configure_disk, disk,
				VZCTL_SCRIPT_EXEC_TIMEOUT, 0))
		return vzctl_err(VZCTL_E_DISK_CONFIGURE, 0,
				"Failed to finalize disk configure");
	return 0;
}
