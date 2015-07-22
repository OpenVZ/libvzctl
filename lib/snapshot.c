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
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <wait.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <linux/vzcalluser.h>
#include <linux/cpt_ioctl.h>
#include <ploop/libploop.h>

#include "libvzctl.h"
#include "vzerror.h"
#include "vz.h"
#include "util.h"
#include "cpt.h"
#include "fs.h"
#include "env.h"
#include "env_config.h"
#include "fs.h"
#include "image.h"
#include "snapshot.h"
#include "config.h"
#include "disk.h"

#define GET_SNAPSHOT_XML_TMP(buf, ve_private) \
	snprintf(buf, sizeof(buf), "%s/" SNAPSHOT_XML ".tmp", ve_private);


static void remove_data_from_array(void **array, int nelem, int id)
{
	int i;

	for (i = id; i < nelem - 1; i++)
		array[i] = array[i + 1];
}

static void free_snapshot_data(struct vzctl_snapshot_data *data)
{
	free(data->guid);
	free(data->parent_guid);
	free(data->name);
	free(data->date);
	free(data->desc);
	free(data);
}

static void vzctl_free_snapshot_tree(struct vzctl_snapshot_tree *tree)
{
	int i;

	for (i = 0; i < tree->nsnapshots; i++)
		free_snapshot_data(tree->snapshots[i]);
	free(tree->snapshots);
	free(tree);
}

static struct vzctl_snapshot_tree *vzctl_alloc_snapshot_tree(void)
{
	return calloc(1, sizeof(struct vzctl_snapshot_tree));
}


void vzctl2_close_snapshot_tree(struct vzctl_snapshot_tree *tree)
{
	return vzctl_free_snapshot_tree(tree);
}

struct vzctl_snapshot_tree *vzctl2_open_snapshot_tree(const char *fname, int *err)
{
	struct vzctl_snapshot_tree *tree;

	tree = vzctl_alloc_snapshot_tree();
	if (tree == NULL) {
		*err = VZCTL_E_NOMEM;
		return NULL;
	}

	*err = vzctl_read_snapshot_tree(fname, tree);
	if (*err) {
		vzctl_free_snapshot_tree(tree);
		return NULL;
	}
	return tree;
}

int vzctl2_find_snapshot_by_guid(struct vzctl_snapshot_tree *tree, const char *guid)
{
	int i;

	for (i = 0; i < tree->nsnapshots; i++)
		if (strcmp(tree->snapshots[i]->guid, guid) == 0)
			return i;
	return -1;
}

static int find_snapshot_current(struct vzctl_snapshot_tree *tree)
{
	int i;

	for (i = 0; i < tree->nsnapshots; i++)
		if (tree->snapshots[i]->current)
			return i;
	return -1;
}

static void vzctl_snapshot_tree_set_current(struct vzctl_snapshot_tree *tree, const char *guid)
{
	int i;

	for (i = 0; i < tree->nsnapshots; i++) {
		tree->snapshots[i]->current = 0;
		if (strcmp(tree->snapshots[i]->guid, guid) == 0)
			tree->snapshots[i]->current = 1;
	}
}

static void vzctl_del_snapshot_tree_entry(struct vzctl_snapshot_tree *tree, const char *guid)
{
	int id, i;
	struct vzctl_snapshot_data *snap;

	id = vzctl2_find_snapshot_by_guid(tree, guid);
	if (id == -1)
		return;
	snap = tree->snapshots[id];

	for (i = 0; i < tree->nsnapshots; i++) {
		// set new current
		if (snap->current && strcmp(tree->snapshots[i]->guid, snap->parent_guid) == 0)
			tree->snapshots[i]->current = 1;

		// update parent
		if (strcmp(tree->snapshots[i]->parent_guid, guid) == 0)
			strcpy(tree->snapshots[i]->parent_guid, snap->parent_guid);
	}

	free_snapshot_data(snap);
	remove_data_from_array((void**)tree->snapshots, tree->nsnapshots, id);
	tree->nsnapshots--;
}

int vzctl_add_snapshot_tree_entry(struct vzctl_snapshot_tree *tree, int current, const char *guid,
		const char *parent_guid, const char *name, const char *date,
		const char *desc)
{
	struct vzctl_snapshot_data **tmp;
	struct vzctl_snapshot_data *data;

	if (vzctl2_find_snapshot_by_guid(tree, guid) != -1)
		return vzctl_err(VZCTL_E_INVAL, 0, "Invalid guid %s is specified: already exist",
				guid);
	data = calloc(1, sizeof(struct vzctl_snapshot_data));
	if (data == NULL)
		return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "calloc failed");

	tmp = realloc(tree->snapshots, sizeof(struct vzctl_snapshot_data *) * (tree->nsnapshots+1));
	if (tmp == NULL) {
		free(data);
		return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "realloc failed");
	}
	tree->snapshots = tmp;
	data->guid = strdup(guid);
	data->parent_guid = strdup(parent_guid);
	data->name = strdup(name ? name : "");
	data->date = strdup(date ? date : "");
	data->desc = strdup(desc ? desc : "");

	if (data->guid == NULL || data->parent_guid == NULL) {
		free_snapshot_data(data);
		return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "strdup failed");
	}
	if (current) {
		int i;
		// set new current
		for (i = 0; i < tree->nsnapshots; i++)
			tree->snapshots[i]->current = 0;
		data->current = 1;
	}

	tree->snapshots[tree->nsnapshots] = data;
	tree->nsnapshots++;

	return 0;
}

static const char *get_date(char *buf, int len)
{
	struct tm *p_tm_time;
	time_t ptime;

	ptime = time(NULL);
	p_tm_time = localtime(&ptime);
	strftime(buf, len, "%F %T", p_tm_time);

	return buf;
}

int vzctl_add_snapshot(struct vzctl_snapshot_tree *tree, const char *guid,
		struct vzctl_snapshot_param *param)
{
	int i;
	char *parent_guid = "";
	char buf[64];

	i = find_snapshot_current(tree);
	if (i != -1)
		parent_guid = tree->snapshots[i]->guid;

	return vzctl_add_snapshot_tree_entry(tree, 1, guid, parent_guid,
			param->name, get_date(buf, sizeof(buf)), param->desc);
}

static void vzctl_get_snapshot_dumpfile(const char *private, const char *guid,
		char *buf, int len)
{
	snprintf(buf, len, "%s" VZCTL_VE_DUMP_DIR "/%s", private, guid);
}

static void vzctl_get_snapshot_ve_conf(const char *private, const char *guid,
		char *buf, int len)
{
	snprintf(buf, len, "%s" VZCTL_VE_DUMP_DIR "/%s." VZCTL_VE_CONF,
			private, guid);
}

static int is_snapshot_supported(char *ve_private)
{
	int layout;

	layout = vzctl2_env_layout_version(ve_private);
	if (layout != VZCTL_LAYOUT_5) {
		logger(-1, 0,"Snapshot supported for ploop based Container only");
		return 0;
	}
	return 1;
}

static int copy_snapshot_config(struct vzctl_env_handle *h, const char *from, const char *to)
{
	int res;
	struct vzctl_disk *disk, *tmp;
	struct vzctl_env_handle *snap_h;

	res = cp_file(from, to);
	if (res)
		return res;

	snap_h = vzctl2_env_open_conf(EID(h), to, 0, &res);
	if (h == NULL)
		return res;

	/* XXX: using *_safe here because vzctl2_env_detach_disk() internally calls list_del() */
	list_for_each_safe(disk, tmp, &h->env_param->disk->disks, list) {
		if (is_permanent_disk(disk))
			continue;

		res = vzctl2_env_detach_disk(snap_h, disk->uuid);
		if (res)
			break;
	}

	vzctl2_env_close(snap_h);

	return res;
}

int vzctl2_env_create_snapshot(struct vzctl_env_handle *h, struct vzctl_snapshot_param *param)
{
	int ret, run = 0;
	char guid[39];
	char fname[MAXPATHLEN];
	char tmp[MAXPATHLEN] = "";
	char snap_ve_conf[MAXPATHLEN] = "";
	struct vzctl_snapshot_tree *tree = NULL;
	char *ve_private = h->env_param->fs->ve_private;
	struct vzctl_cpt_param cpt = {};

	if (!is_snapshot_supported(ve_private))
		return VZCTL_E_CREATE_SNAPSHOT;

	if (param->guid == NULL) {
		if (ploop_uuid_generate(guid, sizeof(guid)))
			return vzctl_err(VZCTL_E_CREATE_SNAPSHOT, 0, "ploop_uuid_generate: %s",
					ploop_get_last_error());
	} else
		snprintf(guid, sizeof(guid), "%s", param->guid);

	logger(0, 0, "Creating snapshot %s", guid);
	tree = vzctl_alloc_snapshot_tree();
	if (tree == NULL)
		return VZCTL_E_NOMEM;

	GET_SNAPSHOT_XML(fname, ve_private)
	if (stat_file(fname)) {
		ret = vzctl_read_snapshot_tree(fname, tree);
		if (ret) {
			logger(-1, 0, "Failed to read %s", fname);
			goto err;
		}
	}
	// Store snapshot.xml
	ret = vzctl_add_snapshot(tree, guid, param);
	if (ret)
		goto err;
	GET_SNAPSHOT_XML_TMP(tmp, ve_private);
	ret = vzctl_store_snapshot_tree(tmp, tree);
	if (ret) {
		logger(-1, 0, "Failed to store %s", tmp);
		goto err;
	}
	// Store ve.conf
	snprintf(fname, sizeof(fname), "%s/"VZCTL_VE_CONF, ve_private);
	vzctl_get_snapshot_ve_conf(ve_private, guid, snap_ve_conf, sizeof(snap_ve_conf));
	make_dir(snap_ve_conf, 0);
	if (copy_snapshot_config(h, fname, snap_ve_conf))
		goto err1;

	run = is_env_run(h);
	if (run == -1)
		goto err1;

	/* 1 freeze */
	if (run) {
		/* TODO: implement stages for in criu */
		int cmd = param->flags & VZCTL_SNAPSHOT_SKIP_DUMP ?
				VZCTL_CMD_SUSPEND : VZCTL_CMD_CHKPNT;
		vzctl_get_snapshot_dumpfile(ve_private, guid, fname,
				sizeof(fname));
		cpt.dumpfile = fname;
		ret = vzctl2_env_chkpnt(h, cmd, &cpt, 0);
		if (ret)
			goto err1;
	}
	/* 2 create snapshot with specified guid */
	ret = vzctl2_env_create_disk_snapshot(h, guid);
	if (ret)
		goto err1;

	/* 3 store dump & continue */
	if (run) {
		cpt.cmd = param->flags & VZCTL_SNAPSHOT_SKIP_DUMP ?
				VZCTL_CMD_RESUME : VZCTL_CMD_RESTORE;
		if (vzctl2_env_restore(h, &cpt, 0))
			logger(-1, 0, "Failed to resume Container");
	}
	// move snapshot.xml to its place
	GET_SNAPSHOT_XML(fname, ve_private);
	if (rename(tmp, fname))
		logger(-1, errno, "Failed to rename %s -> %s", tmp, fname);

	logger(0, 0, "Snapshot %s has been successfully created",
			guid);
	return 0;

#if 0
err2:
	// merge top_delta
	vzctl2_delete_snapshot(h, guid);
	if (run) {
		cpt.cmd = param->flags & VZCTL_SNAPSHOT_SKIP_DUMP ?
				VZCTL_CMD_RESUME : VZCTL_CMD_RESTORE;
		vzctl2_env_restore(h, &cpt, 0);
	}
#endif

err1:
	unlink(tmp);
	unlink(snap_ve_conf);

err:
	logger(-1, 0, "Failed to create snapshot");
	if (tree != NULL)
		vzctl_free_snapshot_tree(tree);

	return VZCTL_E_CREATE_SNAPSHOT;
}

/* Compatibility to support old 'struct vzctl_tsnapshot_param' with single filed
 */
int vzctl2_env_create_tsnapshot(struct vzctl_env_handle *h, const char *guid,
		struct vzctl_tsnapshot_param *tsnap, struct vzctl_snap_holder *holder)
{
	struct vzctl_tsnapshot_param _tsnap = {.component_name = tsnap->component_name};

	return vzctl2_env_create_temporary_snapshot(h, guid, &_tsnap, holder);
}

static int private_param_filter(const char *name)
{
	static char *param[] = {
		"VE_ROOT", "VE_PRIVATE", "VEID", "UUID", "NAME",
		NULL,
	};

	return (find_ar_str(param, name) != NULL);
}

static int restore_env_config(struct vzctl_env_handle *h, const char *guid,
		const char *ve_conf_tmp, struct vzctl_env_handle **h_snap)
{
	int err;
	char fname[MAXPATHLEN];

	/* Parse CT snapshot configuration file */
	vzctl_get_snapshot_ve_conf(h->env_param->fs->ve_private, guid,
			fname, sizeof(fname));
	if (stat_file(fname) != 1)
		return vzctl_err(-1, 0, "Container configuration file %s is not found",
				fname);

	if (cp_file(fname, ve_conf_tmp))
		return -1;

	*h_snap = vzctl2_alloc_env_handle();
	if (*h_snap == NULL)
		return -1;

	/* Preserve private data */
	vzctl2_env_set_param(*h_snap, "VEID", EID(h));

	if (merge_env_param(*h_snap, h->env_param, private_param_filter))
		return -1;

	if (vzctl2_env_save_conf(*h_snap, ve_conf_tmp))
		return -1;

	vzctl2_env_close(*h_snap);

	*h_snap = vzctl2_env_open_conf(EID(h), ve_conf_tmp,
			VZCTL_CONF_SKIP_GLOBAL, &err);
	if (*h_snap == NULL)
		return vzctl_err(-1, 0, "Failed to parse Container configuration file %s",
				fname);

	return 0;
}

int vzctl2_env_switch_snapshot(struct vzctl_env_handle *h,
		struct vzctl_switch_snapshot_param *param)
{
	int ret, run;
	char fname[MAXPATHLEN];
	char snap_xml_tmp[MAXPATHLEN];
	char ve_conf_tmp[MAXPATHLEN] = "";
	char dumpfile[MAXPATHLEN];
	struct vzctl_snapshot_tree *tree = NULL;
	char guid_buf[39];
	const char *guid_tmp = NULL;
	struct vzctl_env_handle *h_env_snap = NULL;
	char *ve_private = h->env_param->fs->ve_private;
	struct vzctl_cpt_param cpt = {};
	struct vzctl_env_disk *env_disk = h->env_param->disk;
	const char *guid = param->guid;

	if (guid == NULL)
		return vzctl_err(VZCTL_E_INVAL, 0, "Snapshot guid is not specified");

	if (!is_snapshot_supported(ve_private))
		return VZCTL_E_SWITCH_SNAPSHOT;

	GET_SNAPSHOT_XML(fname, ve_private)
	if (stat_file(fname) != 1)
		return vzctl_err(VZCTL_E_SWITCH_SNAPSHOT, 0,
				"Unable to find snapshot by uuid %s", guid);

	run = is_env_run(h);
	if (run == -1)
		return VZCTL_E_SWITCH_SNAPSHOT;

	if (run || !list_empty(&env_disk->disks)) {
		/* preserve current top delta with 'guid_tmp' for rollback purposes */
		if (ploop_uuid_generate(guid_buf, sizeof(guid_buf)))
			return vzctl_err(VZCTL_E_SWITCH_SNAPSHOT, 0, "ploop_uuid_generate: %s",
					ploop_get_last_error());
		guid_tmp = guid_buf;
	}

	tree = vzctl_alloc_snapshot_tree();
	if (tree == NULL)
		return vzctl_err(VZCTL_E_SWITCH_SNAPSHOT, ENOMEM,
				"vzctl_alloc_snapshot_tree");

	ret = vzctl_read_snapshot_tree(fname, tree);
	if (ret) {
		logger(-1, 0, "Failed to read %s", fname);
		goto err;
	}
	if (vzctl2_find_snapshot_by_guid(tree, guid) == -1) {
		logger(-1, 0, "Unable to find snapshot by uuid %s", guid);
		goto err;
	}

	logger(0, 0, "Switching to snapshot %s", guid);
	vzctl_snapshot_tree_set_current(tree, guid);
	GET_SNAPSHOT_XML_TMP(snap_xml_tmp, ve_private);
	ret = vzctl_store_snapshot_tree(snap_xml_tmp, tree);
	if (ret) {
		logger(-1, 0, "Failed to store %s", snap_xml_tmp);
		goto err;
	}

	snprintf(ve_conf_tmp, sizeof(ve_conf_tmp), "%s/%s.tmp",
			ve_private, VZCTL_VE_CONF);
	if (restore_env_config(h, guid, ve_conf_tmp, &h_env_snap))
		goto err1;

	/* freeze */
	if (run) {
		ret = vzctl2_env_chkpnt(h, VZCTL_CMD_SUSPEND, &cpt, 0);
		if (ret)
			goto err1;
	} else if (vzctl2_env_is_mounted(h)) {
		if (vzctl2_env_umount(h, 0))
			goto err1;
	}

	/* switch snapshot */
	ret = vzctl2_switch_snapshot(h_env_snap, guid, guid_tmp);
	if (ret)
		goto err2;

	/* stop Ct */
	if (run) {
		ret = vzctl2_cpt_cmd(h, VZCTL_CMD_CHKPNT, VZCTL_CMD_KILL, &cpt, 0);
		if (ret)
			goto err3;
		if (vzctl2_env_umount(h, 0))
			goto err3;
	}

	snprintf(fname, sizeof(fname), "%s/"VZCTL_VE_CONF, ve_private);
	if (rename(ve_conf_tmp, fname))
		logger(-1, errno, "Failed to rename %s -> %s",
					ve_conf_tmp, fname);

	/* resume CT in case dump file exists (no rollback, ignore error) */
	vzctl_get_snapshot_dumpfile(ve_private, guid, dumpfile, sizeof(dumpfile));
	if (!(param->flags & VZCTL_SNAPSHOT_SKIP_RESUME) && stat_file(dumpfile)) {
		struct vzctl_cpt_param rst = {
			.dumpfile = dumpfile,
			.cmd = VZCTL_CMD_RESTORE,
		};
		if (vzctl2_env_restore(h_env_snap, &rst, 0))
			logger(-1, 0, "Failed to resume Container");
	}
	GET_SNAPSHOT_XML(fname, ve_private);
	if (rename(snap_xml_tmp, fname))
		logger(-1, errno, "Failed to rename %s %s", snap_xml_tmp, fname);

	/* remove temporary snapshot */
	if (guid_tmp != NULL)
		vzctl2_delete_snapshot(h_env_snap, guid_tmp);

	vzctl2_env_close(h_env_snap);
	logger(0, 0, "Container has been successfully switched "
			"to %s snapshot", guid);
	return 0;

err3:
	/* rollback snapshot switch */
	if (guid_tmp != NULL) {
		struct vzctl_disk *disk;
		list_for_each(disk, &env_disk->disks, list) {
			vzctl2_switch_disk_snapshot(disk->path, guid_tmp, NULL,
				PLOOP_SNAP_SKIP_TOPDELTA_CREATE);
		}
	}

err2:
	if (run && vzctl2_cpt_cmd(h, VZCTL_CMD_CHKPNT, VZCTL_CMD_RESUME, &cpt, 0))
		logger(-1, 0, "Failed to resume Container on error");

err1:
	vzctl2_env_close(h_env_snap);
	unlink(snap_xml_tmp);
	unlink(ve_conf_tmp);

err:
	logger(-1, 0, "Failed to switch to snapshot %s", guid);
	if (tree != NULL)
		vzctl_free_snapshot_tree(tree);

	return VZCTL_E_SWITCH_SNAPSHOT;
}

int vzctl2_env_delete_snapshot(struct vzctl_env_handle *h, const char *guid)
{
	int ret;
	char fname[MAXPATHLEN];
	char tmp[MAXPATHLEN];
	struct vzctl_snapshot_tree *tree = NULL;
	char *ve_private = h->env_param->fs->ve_private;

	if (guid == NULL)
		return VZCTL_E_INVAL;

	if (!is_snapshot_supported(ve_private))
		return VZCTL_E_DELETE_SNAPSHOT;

	GET_SNAPSHOT_XML(fname, ve_private)
	if (stat_file(fname) != 1)
		return vzctl_err(VZCTL_E_DELETE_SNAPSHOT, 0,
				"Unable to find snapshot by uuid %s", guid);
	tree = vzctl_alloc_snapshot_tree();
	if (tree == NULL)
		return VZCTL_E_DELETE_SNAPSHOT;

	ret = vzctl_read_snapshot_tree(fname, tree);
	if (ret) {
		logger(-1, 0, "Failed to read %s", fname);
		goto err;
	}
	if (vzctl2_find_snapshot_by_guid(tree, guid) == -1) {
		logger(-1, 0, "Unable to find snapshot by uuid %s", guid);
		goto err;
	}
	logger(0, 0, "Deleting snapshot %s", guid);
	vzctl_del_snapshot_tree_entry(tree, guid);
	GET_SNAPSHOT_XML_TMP(tmp, ve_private);
	ret = vzctl_store_snapshot_tree(tmp, tree);
	if (ret) {
		logger(-1, 0, "Failed to store %s", tmp);
		goto err;
	}

	ret = vzctl2_delete_snapshot(h, guid);
	if (ret)
		goto err1;

	vzctl_get_snapshot_dumpfile(ve_private, guid, fname, sizeof(fname));
	if (stat_file(fname)) {
		logger(1, 0, "Deleting CT dump %s", fname);
		if (unlink(fname))
			logger(-1, errno, "Failed to delete dump %s",
					fname);
	}
	/* delete ve.conf */
	vzctl_get_snapshot_ve_conf(ve_private, guid, fname, sizeof(fname));
	if (stat_file(fname) && unlink(fname))
		logger(-1, errno, "Failed to delete ve.conf %s", fname);
	// move snapshot.xml on place
	GET_SNAPSHOT_XML(fname, ve_private);
	if (rename(tmp, fname))
		logger(-1, errno, "Failed to rename %s %s", tmp, fname);

	logger(0, 0, "Snapshot %s has been successfully deleted", guid);
	vzctl_free_snapshot_tree(tree);
	return 0;
err1:
	unlink(tmp);
err:
	logger(-1, 0, "Failed to delete snapshot %s", guid);
	vzctl_free_snapshot_tree(tree);
	return VZCTL_E_DELETE_SNAPSHOT;
}

int vzctl2_env_delete_tsnapshot(struct vzctl_env_handle *h, const char *guid,
		struct vzctl_snap_holder *holder)
{
	int ret;

	vzctl2_release_snap_holder(holder);

	ret = vzctl2_delete_snapshot(h, guid);
	if (ret)
		return ret;

	logger(0, 0, "Temporary snapshot %s has been successfully deleted", guid);

	return 0;
}

int vzctl2_env_mount_snapshot(struct vzctl_env_handle *h, const char *mnt, const char *guid)
{
	int ret;
	char fname[MAXPATHLEN];
	struct vzctl_snapshot_tree *tree = NULL;
	char *ve_private = h->env_param->fs->ve_private;

	if (guid == NULL)
		return vzctl_err(VZCTL_E_NOT_ENOUGH_PARAMS, 0,
				"Failed to mount snapshot: snapshot uuid is not specified");
	if (ve_private == NULL)
		return vzctl_err(VZCTL_E_NOT_ENOUGH_PARAMS, 0,
				"Failed to mount snapshot:  CT private is not specified");

	if (!is_snapshot_supported(ve_private))
		return VZCTL_E_MOUNT_SNAPSHOT;

	GET_SNAPSHOT_XML(fname, ve_private)
	if (stat_file(fname) != 1)
		return vzctl_err(VZCTL_E_MOUNT_SNAPSHOT, 0,
				"Unable to find snapshot by uuid %s: no such file %s",
				guid, fname);
	tree = vzctl_alloc_snapshot_tree();
	if (tree == NULL)
		return VZCTL_E_NOMEM;

	ret = vzctl_read_snapshot_tree(fname, tree);
	if (ret) {
		logger(-1, 0, "Failed to read %s", fname);
		goto err;
	}
	if (vzctl2_find_snapshot_by_guid(tree, guid) == -1) {
		logger(-1, 0, "Unable to find snapshot by uuid %s", guid);
		goto err;
	}
	logger(0, 0, "Mount snapshot %s", guid);

	ret = vzctl2_mount_snap(h, mnt, guid, NULL);
	if (ret)
		goto err;

	vzctl_free_snapshot_tree(tree);
	return 0;
err:
	vzctl_free_snapshot_tree(tree);
	return VZCTL_E_MOUNT_SNAPSHOT;
}

int vzctl2_env_umount_snapshot(struct vzctl_env_handle *h, const char *guid)
{
	char *ve_private = h->env_param->fs->ve_private;

	if (guid == NULL)
		return vzctl_err(VZCTL_E_NOT_ENOUGH_PARAMS, 0,
				"Failed to umount snapshot: snapshot uuid is not specified");
	if (ve_private == NULL)
		return vzctl_err(VZCTL_E_NOT_ENOUGH_PARAMS, 0,
				"Failed to umount snapshot:  CT private is not specified");

	if (!is_snapshot_supported(ve_private))
		return VZCTL_E_UMOUNT_SNAPSHOT;

	logger(0, 0, "Umount snapshot %s", guid);

	if (vzctl2_umount_snapshot(h, guid, NULL))
		return VZCTL_E_UMOUNT_SNAPSHOT;

	return 0;
}
