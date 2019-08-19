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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/vfs.h>
#include <uuid/uuid.h>
#include <sys/mount.h>

#include "libvzctl.h"
#include "env.h"
#include "vzerror.h"
#include "logger.h"
#include "util.h"
#include "config.h"
#include "list.h"
#include "create.h"
#include "vztypes.h"
#include "vzctl_param.h"
#include "cleanup.h"
#include "dist.h"
#include "lock.h"
#include "name.h"
#include "destroy.h"
#include "vz.h"
#include "env_config.h"
#include "cluster.h"
#include "image.h"
#include "vztmpl.h"
#include "disk.h"
#include "exec.h"
#include "snapshot.h"
#include "disk.h"

#define REINSTALL_OLD_MNT	"/mnt"
#define CUSTOM_SCRIPT_DIR	"/etc/vz/reinstall.d"
#define VE_OLDDIR		"/old"

struct cp_data {
	char *from;
	char *to;
};

struct pwd_s {
	int status;
	char *user;
	char *pw;
	int id;
	char *other;
};

int vzctl2_get_def_ostemplate_name(char *out, int size)
{
	char x[STR_SIZE];
	char *s = x;
	char *p;

	if (get_global_param("DEF_OSTEMPLATE", x, sizeof(x) - 7))
		return vzctl_err(VZCTL_E_NO_PARAM, 0,
		 			"The ostemplate is not specified");
	if (s[0] == '.')
		s++;

	p = strrchr(s, '-');
	if (p == NULL || (strcmp(p, "-x86_64") && strcmp(p, "-x86")))
		strcat(x, "-x86_64");

	if (strlen(s) >= size)
		return VZCTL_E_INVAL;

	strcpy(out, s);

	return 0;
}

static int is_ploop_cache(const char *name)
{
	return strstr(name, ".plain.ploop") != NULL ? 1 : 0;
}

static int get_def_ve_layout(void)
{
	char buf[STR_SIZE];
	int layout;

	if (get_global_param("VEFSTYPE", buf, sizeof(buf)) == 0) {
		unsigned long long vefstype = vzctl2_name2tech(buf);
		if (vefstype != VZ_T_VZFS3 &&
				vefstype != VZ_T_VZFS4 &&
				vefstype != VZ_T_EXT4 &&
				vefstype != VZ_T_SIMFS)
			goto out;

		return vzctl2_fstype2layout(vefstype);
	}

	if (get_global_param("VELAYOUT", buf, sizeof(buf)) == 0) {
		if (!strcmp(buf, "ploop"))
			return VZCTL_LAYOUT_5;
		if (parse_int(buf, &layout))
			goto out;
		return layout;
	}
out:
        return VZCTL_LAYOUT_5;
}

static int check_cache_layout(const char *cache, const char *private,
		int new_layout)
{
	int ret;
	char *root;

	if (is_ploop_cache(cache)) {
		if (new_layout < VZCTL_LAYOUT_5)
			return vzctl_err(VZCTL_E_INVAL, 0, "The cached package set '%s' is not"
					" compatible with layout %d. Update the cache",
					cache, new_layout);
	} else {
		if (new_layout == VZCTL_LAYOUT_5)
			return vzctl_err(VZCTL_E_INVAL, 0, "The cached package set '%s' is not"
					" compatible with layout %d. Update the cache",
					cache, new_layout);
		/* private is not exist yet */
		root = get_fs_root(private);
		if (root == NULL)
			return vzctl_err(VZCTL_E_INVAL, 0,
					"Unable to find the root fs by %s", private);
		ret = is_pcs(root);
		free(root);
		if (ret == -1)
			return VZCTL_E_SYSTEM;
		if (ret) {
			if (new_layout == VZCTL_LAYOUT_5)
				logger(-1, 0, "The cached package set '%s' is not"
						" compatible with Parallels Cloud Storage",
						cache);
			else
				logger(-1, 0, "VZFS Containers cannot be created in"
						" Parallels Cloud Storage.");
			return VZCTL_E_INVAL;
		}
	}

	return 0;
}

static int post_create(struct vzctl_env_handle *h)
{
	int ret;
	char ve_root[PATH_MAX];
	char *arg[2];
	char *env[] = { ve_root, NULL };

	read_dist_actions(h);
	if (h->dist_actions == NULL ||
			h->dist_actions->post_create == NULL ||
			h->env_param->fs->ve_root == NULL)
		return -1;

	arg[0] = h->dist_actions->post_create;
	arg[1] = NULL;

	snprintf(ve_root, sizeof(ve_root), "VE_ROOT=%s", h->env_param->fs->ve_root);
	ret = vzctl2_wrap_exec_script(arg, env, 0);
	if (ret)
		logger(-1, 0, "Postcreate action failed");
	else
		logger(0, 0, "Postcreate action done");

	return ret;
}

static int inst_app(struct vzctl_env_handle *h, const char *apps, int force)
{
	int ret, run;

	if (apps[0] == '\0')
		return 0;

	run = is_env_run(h);
	if (!run) {
		h->env_param->opts->wait = VZCTL_PARAM_ON;
		if ((ret = vzctl2_env_start(h, 0)))
			return ret;
	}

	ret = vztmpl_install_app(EID(h), apps, force);

	if (!run)
		vzctl2_env_stop(h, ret ? M_KILL : M_HALT, 0);

	return ret;
}

static int update_vztt_param(struct vzctl_env_handle *h)
{
	int ret;
	char buf[PATH_MAX];
	unsigned long long tech = 0;
	const char *ostmpl = h->env_param->tmpl->ostmpl;

	ret = vztmpl_get_technologies(ostmpl, &tech);
	if (ret == 0 && tech)
		vzctl_conf_add_param(h->conf, "TECHNOLOGIES",
				tech2str(tech, buf, sizeof(buf)));

	ret = vztmpl_get_distribution(ostmpl, buf, sizeof(buf));
	if (ret == 0) {
		ret = xstrdup(&h->env_param->tmpl->dist, buf);
		if (ret)
			return ret;
		vzctl_conf_add_param(h->conf, "DISTRIBUTION", buf);
	}

	ret = vztmpl_get_osrelease(ostmpl, buf, sizeof(buf));
	if (ret == 0 && buf[0] != '\0') {
		ret = xstrdup(&h->env_param->tmpl->osrelease, buf);
		if (ret)
			return ret;

		vzctl_conf_add_param(h->conf, "OSRELEASE", buf);
	}

	if (h->env_param->dq->journaled_quota == 0 &&
			!vztmpl_is_jquota_supported(ostmpl))
		vzctl_conf_add_param(h->conf, "JOURNALED_QUOTA", "no");

	return 0;
}

static int update_param(struct vzctl_env_handle *h)
{
	char buf[PATH_MAX];
	struct vzctl_env_param *env = h->env_param;
	char *str;
	int ret;

	ret = set_disk_param(env, 0);
	if (ret)
		return ret;

	/* Store autogenerated parameters to VEID.conf */
	vzctl_conf_add_param(h->conf, "VE_PRIVATE", env->fs->ve_private_orig);
	vzctl_conf_add_param(h->conf, "VE_ROOT", env->fs->ve_root_orig);
	if (env->tmpl->ostmpl != NULL) {
		/* Compatibilit: preserve EZ template sign */
		snprintf(buf, sizeof(buf), "%s%s",
				env->tmpl->ostmpl[0] != '.' ? "." : "",
				env->tmpl->ostmpl);
		vzctl_conf_add_param(h->conf, "OSTEMPLATE", buf);

		if (env->tmpl->ostmpl[0] != '\0') {
			ret = update_vztt_param(h);
			if (ret)
				return ret;
		}
	}

	/* Store autogenerated VETH parameters */
	str = veth2str(env, env->veth, 0);
	if (str != NULL) {
		vzctl_conf_add_param(h->conf, "NETIF", str);
		free(str);
	}

	return 0;
}

static int create_private_ploop(struct vzctl_env_handle *h, const char *dst,
		const char *tarball, int layout, int flags)
{
	char buf[PATH_MAX];
	char script[PATH_MAX];
	char data_root[PATH_MAX];
	char private_template[PATH_MAX];
	char ve_prvt[PATH_MAX];
	int ret;
	char *arg[2];
	char *env[5];
	int i = 0;

	switch (layout) {
	case VZCTL_LAYOUT_5:
		get_root_disk_path(dst, data_root, sizeof(data_root));
		break;
	case VZCTL_LAYOUT_4:
		snprintf(data_root, sizeof(data_root), "%s", dst);
		break;
	default:
		return vzctl_err(VZCTL_E_INVAL, 9, "Unsupported CT layout %d",
				layout);
	}

	ret = make_dir(data_root, 1);
	if (ret)
		return ret;

	arg[0] = get_script_path(VZCTL_CREATE_PRVT, script, sizeof(script));
	arg[1] = NULL;

	snprintf(private_template, sizeof(private_template), "PRIVATE_TEMPLATE=%s", tarball);
	env[i++] = private_template;
	snprintf(ve_prvt, sizeof(ve_prvt), "VE_PRVT=%s", data_root);
	env[i++] = ve_prvt;
	env[i++] = ENV_PATH;
	if ((flags & VZCTL_FORCE) || is_pcs(dst) == 0)
		env[i++] = "RESERVED_DISKSPACE=0";

	env[i] = NULL;
	ret = vzctl2_wrap_exec_script(arg, env, 0);
	if (ret)
		return ret;

	if (layout == VZCTL_LAYOUT_4)
		return 0;

	/* Create compatible symlink templates -> root.hdd/templates */
	snprintf(buf, sizeof(buf), "%s/templates", data_root);
	if (stat_file(buf) == 1) {
		snprintf(buf, sizeof(buf), "%s/templates", dst);
		if (symlink("root.hdd/templates", buf))
			logger(-1, errno, "Unable to create the symlink: %s",
					buf);
	}

	if (h->env_param->dq->diskspace != NULL) {
		unsigned long size = get_disk_size(h->env_param->dq->diskspace->l);
		ret = vzctl2_resize_disk_image(data_root, size, 0);
		if (ret)
			return ret;
		h->env_param->dq->diskspace->b = h->env_param->dq->diskspace->l = size;
	}

	return 0;
}

static int do_create_private(struct vzctl_env_handle *h, const char *dst,
		const char *ostmpl, const char *vzpkg_conf, char **applist,
		int layout, int use_ostmpl, int flags)
{
	int ret;
	char tarball[PATH_MAX];

	if (h->env_param->disk->root == VZCTL_PARAM_OFF ||
			ostmpl[0] == '\0')
		return 0;

	/* vztmpl_get_cache_tarball do call 'vzpkg info' that implicitly
	 * install vz ostemplate
	 */
	ret = vztmpl_get_cache_tarball(vzpkg_conf,
				&h->env_param->tmpl->ostmpl,
				vzctl2_layout2fstype(layout),
				applist, use_ostmpl, tarball,
				sizeof(tarball));
	if (ret)
		return ret;

	logger(5, 0, "Used tarball: %s", tarball);

	ret = check_cache_layout(tarball, dst, layout);
	if (ret)
		return ret;

	logger(0, 0, "Creating Container private area (%s) with applications "
			"from config (%s)", h->env_param->tmpl->ostmpl, vzpkg_conf);
	return create_private_ploop(h, dst, tarball, layout, flags);
}

#define TMP_SFX	".private_temporary"
static int create_env_private(struct vzctl_env_handle *h, const char *ve_private,
		const char *ostmpl, const char *vzpkg_conf, char **applist,
		int layout, struct vzctl_env_create_param *param, int flags)
{
	char lockfile[PATH_MAX];
	char dst_tmp[PATH_MAX];
	int ret, lckfd = -1;

	if ((ret = make_dir(ve_private, 0)))
		return ret;

	/* Lock Container area */
	snprintf(lockfile, sizeof(lockfile), "%s.lck", ve_private);
	lckfd = vzctl2_lock(lockfile, VZCTL_LOCK_EX | VZCTL_LOCK_NB, 0);
	if (lckfd < 0)
		return vzctl_err(VZCTL_E_FS_NEW_VE_PRVT, 0,
				"Unable to lock the Container private area %s",
				ve_private);

	snprintf(dst_tmp, sizeof(dst_tmp), "%s"TMP_SFX, ve_private);

	if (stat_file(dst_tmp) == 1) {
		logger(0, 0, "Warning: temp dir %s already exists, deleting",
				dst_tmp);
		destroydir(dst_tmp);
	}

	ret = vzctl2_create_env_private(dst_tmp, layout);
	if (ret)
		goto err;

	if (param->root_disk == VZCTL_ROOT_DISK_BLANK) {
		char fname[PATH_MAX];
		struct vzctl_create_image_param p = {
			.size = h->env_param->dq->diskspace->l,
			.enc_keyid = param->enc_keyid,
		};

		get_root_disk_path(dst_tmp, fname, sizeof(fname));
		ret = vzctl_create_image(h, fname, &p);
	} else
		ret = do_create_private(h, dst_tmp, ostmpl, vzpkg_conf, applist,
				layout, 0, flags);
	if (ret)
		goto err;

	ret = update_param(h);
	if (ret)
		goto err;

	if (param->enc_keyid != NULL) {
		char path[PATH_MAX];

		get_root_disk_path(dst_tmp, path, sizeof(path));
		ret = vzctl_encrypt_disk_image(path, param->enc_keyid, 0);
		if (ret)
			goto err;
	}

	ret = rename(dst_tmp, ve_private);
	if (ret) {
		ret = vzctl_err(VZCTL_E_FS_NEW_VE_PRVT, errno, "Can't rename %s to %s",
				dst_tmp, ve_private);
		goto err;
	}

err:
	if (ret)
		destroydir(dst_tmp);

	vzctl2_unlock(lckfd, lockfile);

	return ret;
}

static int merge_create_param(struct vzctl_env_handle *h, struct vzctl_env_param *env,
		struct vzctl_env_create_param *param)
{
	int ret = 0;

	if (param->config != NULL && h->env_param->opts->config == NULL)
		xstrdup(&env->opts->config, param->config);

	if (param->ostmpl != NULL)
		ret = xstrdup(&env->tmpl->ostmpl, param->ostmpl);
	else if (env->tmpl->ostmpl != NULL)
		ret = xstrdup(&env->tmpl->ostmpl, env->tmpl->ostmpl);
	else if (h->env_param->tmpl->ostmpl == NULL) {
		char ostmpl[STR_SIZE];
		/* Use DEF_OSTEMPLATE if ostemplate not specified */
		if (get_global_param("DEF_OSTEMPLATE", ostmpl, sizeof(ostmpl)))
			return vzctl_err(VZCTL_E_NO_PARAM, 0, "The ostemplate is not specified");
		ret = xstrdup(&env->tmpl->ostmpl, ostmpl);
	}

	if (ret)
		return ret;

	if (param->ve_private != NULL) {
		ret = xstrdup(&env->fs->ve_private_orig, param->ve_private);
		if (ret)
			return ret;
	}

	if (param->ve_root != NULL) {
		ret = xstrdup(&env->fs->ve_root_orig, param->ve_root);
		if (ret)
			return ret;
	}

	/* check name */
	if (param->name != NULL) {
		ret = xstrdup(&env->name->name, param->name);
		if (ret)
			return ret;
	}

	if ((param->root_disk == VZCTL_ROOT_DISK_SKIP) &&
			find_root_disk(env->disk) == NULL)
		env->disk->root = VZCTL_PARAM_OFF;

	return 0;
}

static void set_fs_uuid(struct vzctl_env_handle *h)
{
	struct vzctl_disk *d;
	char *tune2fs[] = {"/sbin/tune2fs", "-Urandom", NULL, NULL};
	char *sgdisk[] = {"/usr/sbin/sgdisk", "-G", NULL, NULL};

	list_for_each(d, &h->env_param->disk->disks, list) {
		if (d->use_device)
			continue;

		if (is_root_disk(d)) {
			if (umount(h->env_param->fs->ve_root)) {
				logger(-1, errno, "set_fs_uuid: failed to unmount %s",
						h->env_param->fs->ve_root);
				continue;
			}
		}

		tune2fs[2] = (char *)get_fs_partname(d);
		vzctl2_wrap_exec_script(tune2fs, NULL, 0);

		sgdisk[2] = d->devname;
		vzctl2_wrap_exec_script(sgdisk, NULL, 0);
	}
}

int vzctl2_env_create(struct vzctl_env_param *env,
		struct vzctl_env_create_param *param, int flags)
{
	int ret = 0;
	char buf[PATH_MAX];
	struct vzctl_fs_param *fs;
	struct vzctl_env_handle *h;
	char conf[PATH_LEN];
	char src_conf[PATH_MAX];
	char vzpkg_src_conf[STR_SIZE];
	int use_sample = 0;
	int layout = param->layout ?: get_def_ve_layout();
	const char *ostmpl;
	char *applist = NULL;
	struct vzctl_env_status status;
	ctid_t t;
	ctid_t ctid = {};
	ctid_t uuid = {};

	ret = get_cid_uuid_pair(param->ctid, param->uuid, ctid, uuid);
	if (ret)
		return ret;

	ret = vzctl2_get_env_status(ctid, &status, ENV_STATUS_EXISTS);
	if (ret)
		return vzctl_err(ret, 0, "Can't check the CT %s status", ctid);

	if (status.mask & ENV_STATUS_EXISTS)
		return vzctl_err(VZCTL_E_FS_PRVT_AREA_EXIST, 0,
				"Container %s already exists", ctid);

	vzctl2_get_env_conf_path(ctid, conf, sizeof(conf));

	if (param->config != NULL) {
		if (param->config[0] == '/') {
			snprintf(src_conf, sizeof(src_conf), "%s",
					param->config);
			snprintf(vzpkg_src_conf, sizeof(vzpkg_src_conf), "%s",
					strrchr(param->config, '/') + 1);
		} else {
			vzctl2_get_config_full_fname(param->config, src_conf,
					sizeof(src_conf));
			vzctl2_get_config_fname(param->config, vzpkg_src_conf,
					sizeof(vzpkg_src_conf));
		}

		if (stat_file(src_conf) != 1)
			return vzctl_err(VZCTL_E_CP_CONFIG, 0,
					"Sample config file %s not found", src_conf);
		use_sample = 1;
	} else if (stat_file(conf) == 1) {
		/* Use VEID.conf */
		strcpy(src_conf, conf);
		snprintf(vzpkg_src_conf, sizeof(vzpkg_src_conf), "%s.conf", ctid);
		use_sample = 1;
	} else if (get_global_param("CONFIGFILE", buf, sizeof(buf)) == 0) {
		vzctl2_get_config_full_fname(buf, src_conf, sizeof(src_conf));
		vzctl2_get_config_fname(buf, vzpkg_src_conf, sizeof(vzpkg_src_conf));

		if (stat_file(src_conf) == 1) {
			xstrdup(&env->opts->config, buf);
			use_sample = 1;
		}
	}
	if (!use_sample)
		strcpy(src_conf, GLOBAL_CFG);

	h = vzctl2_env_open_conf(ctid, src_conf, 0, &ret);
	if (h == NULL)
		return ret;

	ret = merge_create_param(h, env, param);
	if (ret)
		goto free_conf;

	fs = h->env_param->fs;
	if (fs->ve_private == NULL) {
		ret = vzctl_err(VZCTL_E_INVAL, 0, "VE_PRIVATE is not specified");
		goto free_conf;
	}
	if (stat_file(fs->ve_private)) {
		ret = vzctl_err(VZCTL_E_FS_PRVT_AREA_EXIST, 0,
				"Private area %s already exists",
				fs->ve_private);
		goto free_conf;
	}

	vzctl2_merge_env_param(h, env);

	ret = validate_env_name(h, env->name->name, t);
	if (ret)
		goto free_conf;

	ostmpl = h->env_param->tmpl->ostmpl;
	fs->layout = layout;

	if (stat_file(conf) == 1 && stat_file(fs->ve_private) == 1)
	{
		ret = vzctl_err(VZCTL_E_FS_PRVT_AREA_EXIST, 0,
				"Container %s already exists", EID(h));
		goto free_conf;
	}

	if ((ret = check_var(fs->ve_private, "VE_PRIVATE is not set")) ||
			(ret = check_var(fs->ve_root, "VE_ROOT is not set")))
		goto free_conf;

	if (h->env_param->dq->diskspace == NULL)
	{
		ret = set_max_diskspace(&h->env_param->dq->diskspace);
		if (ret)
			goto free_conf;
	}

	if (h->env_param->tmpl->templates != NULL &&
			h->env_param->tmpl->templates[0] != '\0')
	{
		ret = xstrdup(&applist, h->env_param->tmpl->templates);
		if (ret)
			goto free_conf;
	}

	if ((ret = create_env_private(h, fs->ve_private, ostmpl, vzpkg_src_conf,
				&applist, layout, param, flags)))
		goto err;

	vzctl2_get_env_conf_path_orig(h, conf, sizeof(conf));
	if (use_sample &&
			(ret = cp_file(src_conf, conf)))
		goto err;


	if (param->root_disk != VZCTL_ROOT_DISK_SKIP) {
		ret = vzctl2_env_mount(h, 8);
		if (ret)
			goto err;

		post_create(h);
		if (layout >= VZCTL_LAYOUT_5)
			set_fs_uuid(h);

		vzctl2_env_umount(h, 0);
	}

	if ((ret = vzctl2_env_save_conf(h, conf)))
		goto err;

	/* FIXME: update conf path */
	xstrdup(&h->conf->fname, conf);

	if (layout >= VZCTL_LAYOUT_4) {
		struct vzctl_reg_param reg_param = {
			.uuid = uuid,
			.name = param->name,
		};

		SET_CTID(reg_param.ctid, ctid);

		if (vzctl2_env_register(fs->ve_private, &reg_param,
					VZ_REG_FORCE) == -1)
		{
			ret = VZCTL_E_REGISTER;
			goto err;
		}
	}
	/* Install application templates */
	if (h->env_param->opts->skip_app != VZCTL_PARAM_ON && applist != NULL)
	{
		if ((ret = inst_app(h, applist, 0)))
			goto err;
	}

	if ((ret = vzctl2_set_name(h, param->name)))
		goto err;

err:
	if (ret) {
		if (use_sample) {
			vzctl2_get_env_conf_path(EID(h), conf, sizeof(conf));
			unlink(conf);
		}
		vzctl2_env_destroy(h, 0);
		logger(-1, 0, "Creation of Container private area failed");
	} else {
		/* return ctid to caller */
		SET_CTID(param->ctid, EID(h));
		logger(0, 0, "Container private area %s created",
				fs->ve_private);
	}

free_conf:
	free(applist);
	vzctl2_env_close(h);

	return ret;
}

static int reinstall_check_diskspace(struct vzctl_env_handle *h)
{
	int ret;
	struct statfs fs;
	const char *ve_private = h->env_param->fs->ve_private;
	struct vzctl_mount_param mount_param = {
			.target = h->env_param->fs->ve_root,
			.ro = 1,
		};

	ret = vzctl2_mount_image(ve_private, &mount_param);
	if (ret)
		return ret;

	ret = VZCTL_E_SYSTEM;
	if (statfs(mount_param.target, &fs)) {
		logger(-1, errno, "statfs %s", mount_param.target);
		goto err;
	}

	if (fs.f_blocks - fs.f_bfree >= fs.f_bfree) {
		logger(-1, 0, "Not enough free blocks to store old content");
		goto err;
	}

	if (fs.f_files - fs.f_ffree >= fs.f_ffree) {
		logger(-1, 0, "Not enough free inodes to store old content");
		goto err;
	}
	ret = 0;
err:
	ret = vzctl2_umount_image(ve_private);

	return ret;
}

int check_reinstall_scripts(list_head_t *ve0_list, list_head_t *ve_list,
		list_head_t *scripts)
{
	struct vzctl_str_param *it;

	list_for_each(it, scripts, list) {
		if (find_str(ve0_list, it->str) == NULL &&
				find_str(ve_list, it->str) == NULL)
			return vzctl_err(-1, 0, "Error: Reinstallation script %s"
					" is not found", it->str);
	}
	return 0;
}

static int custom_reinstall(struct vzctl_env_handle *h, char *script_nm,
		char *ve_private, char *ve_private_tmp)
{
	int ret;
	char *const arg[] = {
		script_nm,
		"--veid", EID(h),
		"--ve_private", ve_private,
		"--ve_private_tmp", ve_private_tmp,
		NULL,
	};

	logger(0, 0, "Running custom reinstall script...");
	ret = vzctl2_wrap_exec_script(arg, NULL, 0);
	if (ret && ret != VZCTL_E_CUSTOM_REINSTALL)
		logger(-1, 0, "Custom reinstall script returned an error");

	return ret;
}

int custom_configure(struct vzctl_env_handle *h, const char *script)
{
	int ret;
	char buf[32];
	char *arg[2] = {(char *)script, NULL};
	char *env[2] = {buf, NULL};

	logger(0, 0, "Running custom configuration script");
	snprintf(buf, sizeof(buf), "VEID=%s", EID(h));

	ret = vzctl2_wrap_env_exec_script(h, arg, env, script, 0, 0);
	if (ret)
		logger(-1, 0, "Custom configuration script"
				" returned with error");
	return ret;
}

static void sort_str_list(list_head_t *head)
{
	struct vzctl_str_param *it;
	int changed;
	void *tmp;

	do {
		changed = 0;
		list_for_each(it, head, list) {
			if (it->list.next == (void *)head)
				continue;

			struct vzctl_str_param *next = list_entry(it->list.next, typeof(*it), list);
			if (strcmp(it->str, next->str) <= 0)
				continue;

			tmp = it->str;
			it->str = next->str;
			next->str = tmp;
			changed = 1;
			break;
		}
	} while (changed);
}

int get_reinstall_scripts(char *root, list_head_t *head, list_head_t *filter)
{
	char buf[STR_SIZE];
	char dir[STR_SIZE];
	struct stat st;
	struct dirent *ep;
	DIR *dp;

	snprintf(dir, sizeof(dir), "%s" VZCTL_CUSTOM_SCRIPT_DIR, root);
	if (!(dp = opendir(dir)))
		return 0;

	while ((ep = readdir(dp))) {
		const char *p = strrchr(ep->d_name, '.');
		if (p == NULL || strcmp(p, ".sh"))
			continue;

		snprintf(buf, sizeof(buf), "%s/%s", dir, ep->d_name);
		if (stat(buf, &st)) {
			closedir(dp);
			return vzctl_err(VZCTL_E_SYSTEM, 0, "failed to stat %s", buf);
		}

		if (!S_ISREG(st.st_mode) || !(st.st_mode & S_IXUSR))
			continue;

		if (add_str_param(head, ep->d_name) == NULL) {
			closedir(dp);
			return VZCTL_E_NOMEM;
		}
	}
	sort_str_list(head);

	closedir(dp);

	return 0;
}

int check_credentials(int veid, char *prvt)
{
	char pwdbdir[STR_SIZE];

	snprintf(pwdbdir, sizeof(pwdbdir), "%s/root/etc", prvt);
	if (stat_file(pwdbdir) != 1)
		return vzctl_err(-1, 0, "Error: Unable to preserve the password database;"
				" the directory /etc does not exist. Use the --resetpwdb"
				" option instead.");
	return 0;
}

static void free_pwd_s(struct pwd_s *pwd)
{
	free(pwd->user);
	free(pwd->pw);
	free(pwd->other);
}

static void free_pwd(struct pwd_s *pwd)
{
	int i = 0;

	if (pwd == NULL)
		return;
	while (pwd[i].user != NULL) {
		free_pwd_s(&pwd[i]);
		i++;
	}
	free(pwd);
}

static int parse_pwd(struct pwd_s *pwd, char *buf)
{
	int len;
	char *sp, *ep;
	char tmp[16];

	memset(pwd, 0, sizeof(*pwd));
	/* User */
	sp = buf;
	ep = sp;
	while (*ep != ':' && *ep != 0) ep++;
	if (*ep == 0)
		return 1;
	len = ep - sp;
	pwd->user = malloc(len + 1);
	strncpy(pwd->user, sp, len);
	pwd->user[len] = 0;

	/* Password */
	sp = ++ep;
	while (*ep != ':' && *ep != 0) ep++;
	if (*ep == 0)
		goto err;;
	len = ep - sp;
	pwd->pw = malloc(len + 1);
	strncpy(pwd->pw, sp, len);
	pwd->pw[len] = 0;

	/* ID */
	sp = ++ep;
	while (*ep != ':' && *ep != 0) ep++;
	if (*ep == 0)
		goto err;;
	len = ep - sp;
	if (len == 0)
		goto err;
	if (len >= sizeof(tmp))
		len = sizeof(tmp) - 1;
	strncpy(tmp, sp, len);
	tmp[len] = 0;
	if (parse_int(tmp, &pwd->id))
		goto err;

	/* rest */
	sp = ++ep;
	while (*ep != '\n' && *ep != 0) ep++;
	len = ep - sp;
	pwd->other = malloc(len + 1);
	strncpy(pwd->other, sp, len);
	pwd->other[len] = 0;

	return 0;
err:
	free_pwd_s(pwd);
	return 1;
}

static struct pwd_s *read_pwd(char *file)
{
	FILE *fp;
	char buf[1024];
	struct pwd_s *pwd = NULL;
	struct pwd_s pwd_tmp;
	int i, delta;

	if ((fp = fopen(file, "r")) == NULL) {
		if (errno == ENOENT)
			return calloc(1, sizeof(*pwd));
		return NULL;
	}
	i = 0;
	delta = 256;
	while (!feof(fp)) {
		if (fgets(buf, sizeof(buf) -1, fp) == NULL)
			break;
		if (parse_pwd(&pwd_tmp, buf))
			continue;
		if (!(i % delta)) {
			struct pwd_s *pwd_;

			pwd_ = realloc(pwd, sizeof(*pwd) * (i + delta + 1));
			if (pwd_ == NULL) {
				free_pwd(pwd);
				pwd = NULL;
				break;
			}
			pwd = pwd_;
		}
		memcpy(&pwd[i++], &pwd_tmp, sizeof(pwd_tmp));
	}
	if (pwd != NULL)
		memset(&pwd[i], 0, sizeof(*pwd));
	fclose(fp);
	return pwd;
}

struct pwd_s *find_pwd(struct pwd_s *pwd, char *user)
{
	struct pwd_s *tmp;

	for (tmp = pwd; tmp->user != NULL; tmp++) {
		if (!strcmp(tmp->user, user))
			return tmp;
	}
	return NULL;
}

static int store_pwd(char *file, struct pwd_s *pwd_new, struct pwd_s *pwd_old)
{
	FILE *fp;
	struct pwd_s *pwd_tmp;

	fp = fopen(file, "w");
	if (fp == NULL)
		return -1;
	for (pwd_tmp = pwd_new; pwd_tmp->user != NULL; pwd_tmp++) {
		fprintf(fp, "%s:%s:%d:%s\n",
				pwd_tmp->user, pwd_tmp->pw, pwd_tmp->id,
				pwd_tmp->other != NULL ? pwd_tmp->other : "");
	}
	for (pwd_tmp = pwd_old; pwd_tmp->user != NULL; pwd_tmp++) {
		if (!pwd_tmp->status)
			continue;
		fprintf(fp, "%s:%s:%d:%s\n",
				pwd_tmp->user, pwd_tmp->pw, pwd_tmp->id,
				pwd_tmp->other != NULL ? pwd_tmp->other : "");
	}
	fclose(fp);
	return 0;
}

enum {
	PASSWD_DB,
	SHADOW_DB,
	GROUP_DB,
};

static int merge_pwd(char *src, char *dst, int type)
{
	int changed;
	struct pwd_s *pwd_new, *pwd_old, *pwd, *pwd_tmp_old;

	pwd_old = read_pwd(src);
	if (pwd_old == NULL)
		return 0;
	pwd_new = read_pwd(dst);
	if (pwd_new == NULL) {
		free_pwd(pwd_old);
		return 0;
	}
	changed = 0;
	for (pwd_tmp_old = pwd_old; pwd_tmp_old->user != NULL; pwd_tmp_old++) {
		/* Find old record in new DB */
		pwd = find_pwd(pwd_new, pwd_tmp_old->user);
		if (pwd == NULL) {
			/* add old record */
			pwd_tmp_old->status = 1;
			changed++;
			continue;
		}
		if (type == PASSWD_DB || type == GROUP_DB) {
			/* id conflict, skip */
			if (pwd->id != pwd_tmp_old->id)
				continue;
		}
		if (type == PASSWD_DB || type == SHADOW_DB) {
			if (strcmp(pwd->pw, pwd_tmp_old->pw)) {
				/* password is changed */
				free(pwd->pw);
				pwd->pw = strdup(pwd_tmp_old->pw);
				pwd->id = pwd_tmp_old->id;
				free(pwd->other);
				pwd->other = strdup(pwd_tmp_old->other);
				changed++;
			}
		}
		if (type == GROUP_DB) {
			if (strcmp(pwd->other, pwd_tmp_old->other)) {
				/* user list is changed for groups only */
				free(pwd->other);
				pwd->other = strdup(pwd_tmp_old->other);
				changed++;
			}
		}
	}
	if (changed)
		store_pwd(dst, pwd_new, pwd_old);
	free_pwd(pwd_old);
	free_pwd(pwd_new);
	return 0;
}

static int copy_credentials(struct cp_data *data)
{
	char src[512];
	char dst[512];
	int ret;

	ret = 0;
	mkdir(data->to, 0755);
	snprintf(src, sizeof(src), "%s/passwd", data->from);
	snprintf(dst, sizeof(dst), "%s/passwd", data->to);
	if (stat_file(src))
		merge_pwd(src, dst, PASSWD_DB);
	snprintf(src, sizeof(src), "%s/shadow", data->from);
	snprintf(dst, sizeof(dst), "%s/shadow", data->to);
	if (stat_file(src))
		merge_pwd(src, dst, SHADOW_DB);
	snprintf(src, sizeof(src), "%s/group", data->from);
	snprintf(dst, sizeof(dst), "%s/group", data->to);
	if (stat_file(src))
		merge_pwd(src, dst, SHADOW_DB);

	return ret;
}

static int reinstall_post(struct vzctl_env_handle *h, list_head_t *reinstall_scripts_list,
		list_head_t *scripts_list, list_head_t *ve0_scripts_list, int resetpwdb)
{
	int ret;
	char buf[PATH_MAX];

	if (!resetpwdb) {
		struct cp_data data = {REINSTALL_OLD_MNT "/etc", "/etc"};

		logger(0, 0, "Copying Container credentials...");
		ret = vzctl_env_exec_fn(h, (execFn) copy_credentials, (void *) &data, 0);
		if (ret)
			return vzctl_err(-1, 0, "Failed to copy Container credentials");
	}

	if (!list_empty(scripts_list) || !list_empty(ve0_scripts_list)) {
		struct vzctl_str_param *it;
		char *argv[3];
		char *envp[2] = {"REINSTALL_DATA_ROOT=" REINSTALL_OLD_MNT, NULL};

		logger(0, 0, "Running reinstall configuration scripts:");

		list_for_each(it, scripts_list, list) {
			if (!list_empty(reinstall_scripts_list) &&
					find_str(reinstall_scripts_list, it->str) == NULL)
				continue;

			snprintf(buf, sizeof(buf), REINSTALL_OLD_MNT CUSTOM_SCRIPT_DIR "/%s",
					it->str);
			argv[0] = argv[1] = buf; argv[2] = NULL;
			logger(0, 0, "\t%s", buf);
			ret = vzctl2_env_exec(h, MODE_EXEC,
					argv, envp, NULL, 0, EXEC_LOG_OUTPUT);
			if (ret)
				return -1;
		}

		list_for_each(it, ve0_scripts_list, list) {
			char *script = NULL;

			if (!list_empty(reinstall_scripts_list) &&
					find_str(reinstall_scripts_list, it->str) == NULL)
				continue;

			if (find_str(scripts_list, it->str) != NULL)
				continue;

			snprintf(buf, sizeof(buf), CUSTOM_SCRIPT_DIR "/%s", it->str);
			if (read_script(buf, 0, &script) == -1)
				return -1;

			logger(0, 0, "\t%s", buf);
			ret = vzctl2_env_exec(h, MODE_BASH_NOSTDIN,
					NULL, envp, script, 0, EXEC_LOG_OUTPUT);
			free(script);
			if (ret)
				return -1;
		}
	}
	return 0;
}

static const char *get_ostmpl(struct vzctl_env_handle *h)
{
	const char *s = h->env_param->tmpl->ostmpl;

	/* skip EX template '.' mask */
	return (s && *s == '.') ? s + 1 : s;
}

int vzctl2_env_reinstall(struct vzctl_env_handle *h,
		struct vzctl_reinstall_param *param)
{
	int ret;
	char buf[PATH_MAX];
	char tmp[PATH_MAX];
	char old_disk[PATH_MAX];
	char old_root[PATH_MAX];
	char new_disk[PATH_MAX];
	char new_prvt[PATH_MAX];
	struct vzctl_mount_param mount_param = {};
	char vzpkg_src_conf[STR_SIZE];
	char c_configure_script[PATH_MAX];
	int c_configure = 0, flags;
	struct vzctl_env_param *env = h->env_param;
	char *ve_private = env->fs->ve_private;
	char *ostmpl = param->ostemplate ?: env->tmpl->ostmpl;
	char *root_disk_orig = NULL;
	struct vzctl_disk *root_disk;
	LIST_HEAD(app_list);
	LIST_HEAD(reinstall_scripts_list);
	LIST_HEAD(ve0_scripts_list);
	LIST_HEAD(scripts_list);

	if (env->misc->ve_type == VZCTL_ENV_TYPE_TEMPLATE)
		return vzctl_err(VZCTL_E_INVAL, 0, "This is not a regular Container.");

	if ((ret = check_var(ve_private, "VE_PRIVATE is not set")) ||
	    (ret = check_var(env->fs->ve_root, "VE_ROOT is not set")) ||
	    (ret = check_var(ostmpl, "OSTEMPLATE is not set."
		" Container is not based on ostemplate. Reinstall is not supported.")) ||
	    (ret = check_var(env->dq->diskspace, "DISKSPACE is not set")))
		return ret;

	if (!stat_file(ve_private))
		return vzctl_err(VZCTL_E_NO_PRVT, 0,
				"Container private area does not exist");

	if (is_env_run(h))
		return vzctl_err(VZCTL_E_ENV_RUN, 0,
				"Container is running; stop it before proceeding.");

	if (vzctl2_env_is_mounted(h))
		return vzctl_err(VZCTL_E_FS_MOUNTED, 0,
				"Container is mounted; unmount it before proceeding.");

	if (h->env_param->fs->layout != VZCTL_LAYOUT_5)
		return vzctl_err(VZCTL_E_INVAL, 0,
				"Unsupported CT layout %d", h->env_param->fs->layout);

	if (!param->skipbackup && reinstall_check_diskspace(h))
		return VZCTL_E_REINSTALL;

	root_disk = find_root_disk(h->env_param->disk);
	if (root_disk == NULL)
		return vzctl_err(VZCTL_E_REINSTALL, 0, "Root disk is not configured"); 

	snprintf(old_disk, sizeof(old_disk), "%s", root_disk->path);
	snprintf(new_prvt, sizeof(new_prvt), "%s.reinstall", root_disk->path);
	get_root_disk_path(new_prvt, new_disk, sizeof(new_disk));
	if (stat_file(new_prvt) == 1) {
		logger(1, 0, "Temporary Container private area %s already"
				" exists and will be deleted.", new_disk);
		ret = vzctl2_umount_disk_image(new_disk);
		if (ret)
			return ret;

		destroydir(new_prvt);
	}

	/* Custom reinstall */
	get_script_path(VZCTL_REINSTALL_SCRIPT, buf, sizeof(buf));
	if (stat_file(buf)) {
		ret = custom_reinstall(h, buf, old_disk, new_disk);
		if (ret == 0) {
			if (stat_file(new_prvt) == 0) {
				logger(-1, 0, "Unable to continue reinstallation;"
						" the private area is not created");
				return VZCTL_E_CUSTOM_REINSTALL;
			}

			get_script_path(VZCTL_CONFIGURE_SCRIPT, c_configure_script,
					sizeof(c_configure_script));
			c_configure = stat_file(c_configure_script) == 1;
			goto skip_create;
		} else if (ret != VZCTL_E_CUSTOM_REINSTALL) {
			logger(-1, 0, "The %s failed", VZCTL_REINSTALL_SCRIPT);
			return VZCTL_E_CUSTOM_REINSTALL;
		}
	}

	// Create new Container
	snprintf(vzpkg_src_conf, sizeof(vzpkg_src_conf), "%s.conf", EID(h));
	ret = vztmpl_get_applist(EID(h), &app_list, get_ostmpl(h));
	if (ret)
		goto err;

	ret = do_create_private(h, new_prvt, ostmpl, vzpkg_src_conf, NULL,
			h->env_param->fs->layout, 1, 0);
	if (ret)
		goto err;

skip_create:
	root_disk_orig = root_disk->path;
	root_disk->path = new_disk;
	ret = vzctl2_env_mount(h, 0); 
	if (ret)
		goto err;

	post_create(h);

	/* Mount old root.hdd under VE_ROOT/VEID/mnt */
	snprintf(old_root, sizeof(old_root), "%s" REINSTALL_OLD_MNT,
			h->env_param->fs->ve_root);
	if (make_dir(old_root, 1))
		goto err;

	mount_param.target = old_root;
	ret = vzctl2_mount_disk_image(old_disk, &mount_param);
	if (ret)
		goto err;

	/* Start Container */
	if (!param->resetpwdb || c_configure || !list_empty(&app_list)) {
		flags = VZCTL_SKIP_MOUNT | (list_empty(&app_list) ?
					VZCTL_SKIP_CONFIGURE : VZCTL_WAIT);
		ret = vzctl2_env_start(h, flags);
		if (ret)
			goto err;
	}

	if (param->reinstall_scripts) {
		ret = parse_str_param(&reinstall_scripts_list, param->reinstall_scripts);
		if (ret)
			goto err;
	}

	if (!param->skipscripts) {
		/* get VE0 reinstall scripts */
		ret = get_reinstall_scripts("", &ve0_scripts_list, &reinstall_scripts_list);
		if (ret)
			goto err;
		/* get CT reinstall scripts */
		ret = get_reinstall_scripts(old_root, &scripts_list, &reinstall_scripts_list);
		if (ret)
			goto err;

		if (check_reinstall_scripts(&ve0_scripts_list, &scripts_list, &reinstall_scripts_list)) {
			ret = VZCTL_E_REINSTALL;
			goto err;
		}
	}

	if (!list_empty(&app_list)) {
		char *apps = list2str("", &app_list);

		vzctl2_env_set_param(h, "TEMPLATES", NULL);
		vzctl2_env_save(h);

		ret = inst_app(h, apps, /* FIXME: param->reinstall_opts */ 0);

		free(apps);
		if (ret)
			goto err;
	}

	/* Post create actions */
	if (c_configure && (ret = custom_configure(h, c_configure_script)))
		goto err;

	ret = reinstall_post(h, &reinstall_scripts_list, &scripts_list,
			&ve0_scripts_list, param->resetpwdb);
	if (ret)
		goto err;

	if (!param->skipbackup) {
		char *arg[] = {"/bin/cp", "-ax", old_root, buf, NULL};

		snprintf(buf, sizeof(buf), "%s" VE_OLDDIR,
			 h->env_param->fs->ve_root);
		logger(0, 0, "Copying old file system content under %s...", buf);
		ret = vzctl2_wrap_exec_script(arg, NULL, 0);
		if (ret)
			goto err;
	}

	if (is_env_run(h)) {
		ret = vzctl2_env_stop(h, M_HALT, 0);
		if (ret)
			goto err;
	}

	if (vzctl2_is_image_mounted(old_disk))
		vzctl2_umount_disk_image(old_disk);

	if (vzctl2_is_image_mounted(new_disk))
		vzctl2_umount_disk_image(new_disk);

	// Move VEID/root.hdd -> VEID/root.hdd.tmp
	snprintf(tmp, sizeof(tmp), "%s.tmp", old_disk);
	if (stat_file(tmp))
		destroydir(tmp);
	logger(5, 0, "%s -> %s", old_disk, tmp);
	if (rename(old_disk, tmp)) {
		logger(-1, errno, "rename %s -> %s", old_disk, tmp);
		goto err1;
	}

	logger(5, 0, "%s -> %s", new_disk, old_disk);
	if (rename(new_disk, old_disk)) {
		logger(-1, errno, "rename %s -> %s", new_disk, old_disk);
		if (rename(tmp, old_disk))
			logger(-1, errno, "rolback failed %s -> %s", tmp, old_disk);
		goto err1;
	}

	destroydir(new_prvt);
	destroydir(tmp);
	/* Remove snapshots */
	snprintf(tmp, sizeof(tmp), "%s/"VZCTL_VE_DUMP_DIR, ve_private);
	destroydir(tmp);
	snprintf(tmp, sizeof(tmp), "%s/"SNAPSHOT_XML, ve_private);
	unlink(tmp);
	logger(0, 0, "Container was successfully reinstalled");

	free_str(&app_list);
	free_str(&reinstall_scripts_list);
	free_str(&ve0_scripts_list);
	free_str(&scripts_list);

	root_disk->path = root_disk_orig;

	return 0;

err:
	if (is_env_run(h))
		vzctl2_env_stop(h, M_HALT, 0);
	if (vzctl2_is_image_mounted(old_disk))
		vzctl2_umount_disk_image(old_disk);
	if (vzctl2_is_image_mounted(new_disk))
		vzctl2_umount_disk_image(new_disk);
err1:
	destroydir(new_prvt);

	free_str(&app_list);
	free_str(&reinstall_scripts_list);
	free_str(&ve0_scripts_list);
	free_str(&scripts_list);

	if (root_disk_orig != NULL)
		root_disk->path = root_disk_orig;

	logger(-1, 0, "Container reinstall failed");
	return VZCTL_E_REINSTALL;
}
