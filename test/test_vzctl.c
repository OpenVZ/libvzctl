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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "vzctl.h"
#include "disk.h"
#include "vzerror.h"
#include "test.h"
#include "exec.h"
#include "util.h"
#include "env.h"
#include "libvzctl.h"
#include <ploop/libploop.h>

static const char *id = "100";
static unsigned veid = 100;
extern ctid_t ctid;

void test_misc()
{
	char buf[64];
	TEST()

	CHECK_RET(vzctl2_get_normalized_guid("043ec956-6fea-4c45-911c-18991d6ffa93", buf, sizeof(buf)))
	CHECK_RET(vzctl2_get_normalized_guid("{043ec956-6fea-4c45-911c-18991d6ffa93}", buf, sizeof(buf)))
	CHECK_RET(!vzctl2_get_normalized_guid("", buf, sizeof(buf)))

	CHECK_RET(vzctl2_get_normalized_uuid("043ec956-6fea-4c45-911c-18991d6ffa93", buf, sizeof(buf)))
	CHECK_RET(vzctl2_get_normalized_uuid("{043ec956-6fea-4c45-911c-18991d6ffa93}", buf, sizeof(buf)))
	CHECK_RET(!vzctl2_get_normalized_uuid("{}", buf, sizeof(buf)))
	CHECK_RET(!vzctl2_get_normalized_uuid("", buf, 1))
}

void test_lock()
{
	int fd, tmp, err;
	struct vzctl_env_handle *h;

	TEST()
	CHECK_PTR(h, vzctl2_env_open(ctid, 0, &err))
	fd = vzctl2_env_lock(h, "lock");
	if (fd < 0) {
		TEST_VZERR("vzctl2_env_lock")
		return;
	}

	tmp = vzctl2_env_lock(h, "lock");
	if (tmp != -2) {
		TEST_VZERR("vzctl2_env_lock")
		return;
	}
	vzctl2_env_unlock(h, fd);
}

void test_cpustat()
{
	int err;
	struct vzctl_cpustat cpustat = {};
	struct vzctl_env_handle *h;

	TEST()

	CHECK_PTR(h, vzctl2_env_open(ctid, 0, &err))
	printf("\n(info) test_cpustat\n");
	CHECK_RET(vzctl2_env_cpustat(h, &cpustat, sizeof(struct vzctl_cpustat)))
	printf("cpustat uptime=%f user=%f nice=%f system=%f idel=%f\n",
		cpustat.uptime, cpustat.user, cpustat.nice, cpustat.system, cpustat.idle);
}

void test_iostat()
{
	struct vzctl_iostat stat = {};

	TEST()
	printf("\n(info) test_iostat\n");
	CHECK_RET(vzctl2_get_env_iostat(ctid, &stat, sizeof(stat)))
	printf("iostat read=%llu write=%llu\n",
		stat.read, stat.write);
}

void test_set_userpasswd()
{
	int ret, err;
	struct vzctl_env_handle *h;

	TEST()

	CHECK_PTR(h, vzctl2_env_open(ctid, 0, &err))
	CHECK_RET(vzctl2_env_set_userpasswd(h, "root", "1", 0))
	CHECK_RET(vzctl2_env_auth(h, "root", "1", -1, 0))
	CHECK_RET(vzctl2_env_auth(h, "root", "1", 0, 0))
	ret = vzctl2_env_auth(h, "root", "2", 0, 0);
	if (ret == 0)
		TEST_VZERR("vzctl2_env_auth");

	CHECK_RET(vzctl2_env_set_userpasswd(h, "test", "1", 0))
	CHECK_RET(vzctl2_env_auth(h, "test", "1", -1, 0))
	ret = vzctl2_env_auth(h, "test", "2", -1, 0);
	if (ret == 0)
		TEST_VZERR("vzctl2_env_auth");
}

void test_env_register()
{
	int err;
	const char *path;
	struct vzctl_env_handle *h;
	struct vzctl_reg_param p = {};

	SET_CTID(p.ctid, ctid);

	TEST()

	CHECK_PTR(h, vzctl2_env_open(ctid, 0, &err))
	vzctl2_env_get_ve_private_path(vzctl2_get_env_param(h), &path);

	vzctl2_env_unregister(NULL, ctid, 0);
	printf("register at %s\n", path);
	CHECK_RET(vzctl2_env_register(path, &p, 0))

	vzctl2_env_close(h);
}

static int stdredir(int rdfd, int wrfd)
{
	int lenr, lenw, lentotal, lenremain, n;
	char buf[10240];
	char *p;
	fd_set wr_set;

	lenr = read(rdfd, buf, sizeof(buf)-1);
	if (lenr > 0) {
		lentotal = 0;
		lenremain = lenr;
		p = buf;
		while (lentotal < lenr) {
			while ((lenw = write(wrfd, p, lenremain)) < 0) {
				switch (errno) {
				case EINTR:
					continue;
				case EAGAIN:
					FD_ZERO(&wr_set);
					FD_SET(wrfd, &wr_set);
					n = select(FD_SETSIZE, NULL, &wr_set,
								NULL, NULL);
					if (n < 1)
						return -1;
					break;
				default:
					return -1;
				}
			}
			lentotal += lenw;
			lenremain -= lenw;
			p += lenw;
		}
	} else if (lenr == 0) {
		return -1;
	} else {
		if (errno == EAGAIN)
			return 1;
		else if (errno != EINTR)
			return -1;
	}
	return 0;
}

static int process_std(int stdoutfd[2], int stderrfd[2])
{
	int n, maxfd;
	struct timeval tv;

	tv.tv_sec = 60;
	tv.tv_usec = 0;

	close(stdoutfd[1]);
	close(stderrfd[1]);

	maxfd = stdoutfd[0];
	if (stderrfd[0] > maxfd)
		maxfd = stderrfd[0];
	maxfd += 1;
	while (1) {
		fd_set rd_set;
		// Fds are closed
		if (stdoutfd[0] == -1 && stderrfd[0] == -1)
			break;
		FD_ZERO(&rd_set);
		if (stdoutfd[0] != -1)
			FD_SET(stdoutfd[0], &rd_set);
		if (stderrfd[0] != -1)
			FD_SET(stderrfd[0], &rd_set);

		n = select(maxfd, &rd_set, NULL, NULL, &tv);
		if (n > 0) {
			if (stdoutfd[0] != -1 && FD_ISSET(stdoutfd[0], &rd_set)) {
				if (stdredir(stdoutfd[0], STDOUT_FILENO) < 0) {
					close(stdoutfd[0]);
					stdoutfd[0] = -1;
				}
			}
			if (stderrfd[0] != -1 && FD_ISSET(stderrfd[0], &rd_set)) {
				if (stdredir(stderrfd[0], STDOUT_FILENO) < 0) {
					close(stderrfd[0]);
					stderrfd[0] = -1;
				}
			}
		} else if (n < 0 && errno != EINTR) {
			printf("select(): %s\n", strerror(errno));
			return -1;
		}
	}
	return 0;
}

int test_env_exec_async(char **argv, char **envp, int stdfd)
{
	int err, pid, ret;
	vzctl_env_handle_ptr h;
	int fds[3];
	int stdoutfd[2] = {-1, -1};
	int stderrfd[2] = {-1, -1};

	h = vzctl2_env_open(ctid, 0, &err);
	if (h == NULL) {
		return -1;
	}
	if (stdfd) {
		pipe(stdoutfd);
		pipe(stderrfd);
		fds[0] = -1;
		fds[1] = stdoutfd[1];
		fds[2] = stderrfd[1];
	}

	printf("* test_env_exec_async RUN: %s %s\n", argv[0], stdfd ? "redirect" : "" );
	pid = vzctl2_env_exec_async(h, MODE_EXEC, argv, envp, NULL, 0, 0,
			stdfd ? fds : NULL, &ret);
	if (pid == -1) {
		ret = err;
		printf("vzctl2_env_exec_async: pid=-1\n");
		goto err;
	}

	if (stdfd)
		process_std(stdoutfd, stderrfd);

	err = vzctl2_env_exec_wait(pid, &ret);
	if (ret)
		printf("vzctl2_env_exec_async: %s ret=%d\n",
				vzctl2_get_last_error(), ret);

	close(stdoutfd[0]);
	close(stderrfd[0]);

err:
	vzctl2_env_close(h);
	return ret;
}

int test_env_exec(char **argv, char **envp)
{
	int err, ret;
	vzctl_env_handle_ptr h;

	h = vzctl2_env_open(ctid, 0, &err);
	if (h == NULL) {
		return -1;
	}

	printf("* test_env_exec RUN: %s\n", argv[0]);
	ret = vzctl2_env_exec(h, MODE_EXEC, argv, envp, NULL, 0, 0);
	if (ret) {
		return ret;
	}

	vzctl2_env_close(h);
	return ret;
}

static int exec_fn(void *data)
{
	char *fname = (char *) data;
	int fd;

	printf("Create %s\n", fname);
	fd = open(fname, O_CREAT, 0600);
	if (fd == -1)
		return 1;
	close(fd);
	return 0;
}

int test_env_exec_fn(execFn fn,  char *fname)
{
	int err, pid, ret;
	vzctl_env_handle_ptr h;

	h = vzctl2_env_open(ctid, 0, &err);
	if (h == NULL) {
		return -1;
	}

	printf("* test_env_exec_fn\n");
	pid = vzctl2_env_exec_fn_async(h, fn, (void *) fname, NULL, 0, 0, &err);
	if (pid == -1) {
		ret = err;
		goto err;
	}

	err = vzctl2_env_exec_wait(pid, &ret);

err:
	vzctl2_env_close(h);

	return ret;
}

void test_exec()
{
	int ret, i;

	TEST()
	test_env_exec_fn(exec_fn, "/test.XXX");

	for (i = 0; i < 2; i++) {
		{
			char *argv[] = {"printenv", NULL};
			char *envp[] = {"TEST=test",  NULL};
			CHECK_RET(test_env_exec_async(argv, envp, i))
		}

		{
			char *argv[] = {"xx", NULL};
			CHECK_RET(!test_env_exec_async(argv, NULL, i))

		}

		{
			char *argv[] = {"ps", NULL};
			CHECK_RET(test_env_exec_async(argv, NULL, i))
		}

		{
			char *argv[] = {"ls", "/proc",  NULL};
			CHECK_RET(test_env_exec_async(argv, NULL, i))
		}


		{
			char *argv[] = {"false", NULL};
			ret = test_env_exec_async(argv, NULL, i);
			if (ret != 1) {
				printf("ret=%d\n", ret);
				TEST_ERR("vzctl_env_exec: false != 1");
			}
		}

		{
			char *argv[] = {"true", NULL};
			CHECK_RET(test_env_exec_async(argv, NULL, i))
		}
	}

	{
		char *argv[] = {"ls", NULL};
		CHECK_RET(test_env_exec(argv, NULL))
	}
}

void test_env_stop()
{
	int err, ret, i;
	vzctl_env_handle_ptr h;
	int modes[] = {M_HALT, M_REBOOT, M_KILL};

	TEST()
	CHECK_PTR(h, vzctl2_env_open(ctid, 0, &err))
	for (i = 0; i < sizeof(modes)/sizeof(modes[0]); i++) {
		ret = vzctl2_env_start(h, VZCTL_WAIT);
		if (ret && ret != VZCTL_E_ENV_RUN)
			TEST_VZERR("vzctl2_env_start ret")

		printf("Stop CT mode=%d\n", modes[i]);
		CHECK_RET(vzctl2_env_stop(h, modes[i], 0))
	}
	vzctl2_env_close(h);
}

void test_vzlimits()
{
	TEST()
	CHECK_RET(vzctl2_set_vzlimits("VZ_TOOLS"))
}

void test_mount()
{
	int err;
	vzctl_env_handle_ptr h;

	TEST()

	CHECK_PTR(h, vzctl2_env_open(ctid, 0, &err))
	CHECK_RET(vzctl2_env_mount(h, 0))
	CHECK_RET(vzctl2_env_umount(h, 0))

	vzctl2_env_close(h);
}

int check_disk_param(vzctl_env_handle_ptr h, struct vzctl_disk_param *param)
{
	struct vzctl_disk_param disk_param;
	struct vzctl_disk *it = NULL;

	while ((it = vzctl2_env_get_disk(vzctl2_get_env_param(h), it)) != NULL) {
		vzctl2_env_get_disk_param(it, &disk_param, sizeof(disk_param));
		if (memcmp(param->uuid, disk_param.uuid, sizeof(param->uuid)) == 0) {
			if (param->size && disk_param.size != param->size) {
				fprintf(stderr, "disk->size %lu != param->size %lu\n",
						disk_param.size, param->size);
				return 1;
			}
			if (disk_param.enabled != param->enabled) {
				fprintf(stderr, "disk->enabled %d != param->enabled %d\n",
						disk_param.enabled, param->enabled);
				return 1;
			}
			return 0;
		}
	}
	fprintf(stderr, "disk not found uuid=%s\n", param->uuid);
	return -1;
}

void test_disk_add(vzctl_env_handle_ptr h, struct vzctl_disk_param *param)
{
	int i;

	TEST()
	printf("(info) test_disk_add %s\n",  param->path);
	param->uuid[0] = '\0';
	/* 1 - create under VE_PRIVATE */
	CHECK_RET(vzctl2_env_add_disk(h, param, 0))
	CHECK_RET(check_disk_param(h, param))

	/* 2 - resize */
	param->size *= 2;
	CHECK_RET(vzctl2_env_resize_disk(h, param->uuid, param->size, 0))
	CHECK_RET(check_disk_param(h, param))

	/* 3 enable/disable */
	for (i = 0; i < 1; i++) {
		param->path = NULL;
		param->size = 0;
		param->enabled = i;
		CHECK_RET(vzctl2_env_set_disk(h, param))
		CHECK_RET(check_disk_param(h, param))
	}

	/* 3 delete */
	CHECK_RET(vzctl2_env_del_disk(h, param->uuid, 0))
}

void test_disk()
{
	int err;
	vzctl_env_handle_ptr h;
	char path[4096];
	struct vzctl_disk_param param = {};

	TEST()

	CHECK_PTR(h, vzctl2_env_open(ctid, 0, &err))

	/* 1 - create under VE_PRIVATE */
	path[0] = '\0';
	param.size = 1024000;
	param.path = "disk1.hdd";
	test_disk_add(h, &param);
	/* 2 - create under custom path */
	param.size = 1024000;
	sprintf(path, "/tmp/%s", id);
	param.path = path;
	test_disk_add(h, &param);

	vzctl2_env_close(h);
}

void test_meminfo()
{
	struct vzctl_meminfo meminfo;

	TEST()
	CHECK_RET(vzctl2_get_env_meminfo(ctid, &meminfo, sizeof(struct vzctl_meminfo)))

	printf("Total : %llu Free: %llu Cached: %llu\n",
			meminfo.total, meminfo.free, meminfo.cached);
}

void test_snapshot()
{
	int err;
	vzctl_env_handle_ptr h;
	char guid[64];

	TEST()
	ploop_uuid_generate(guid, sizeof(guid));
	CHECK_PTR(h, vzctl2_env_open(ctid, 0, &err))

	printf("\n(info) Creating snapshot %s\n", guid);
	CHECK_RET(vzctl2_create_snapshot(h, guid))

	printf("\n(info) Deleting snapshot %s\n", guid);
	CHECK_RET(vzctl2_delete_snapshot(h, guid))

	vzctl2_env_close(h);
}

void test_tsnapshot()
{
	int err;
	vzctl_env_handle_ptr h;
	char guid[64];

	TEST()
	ploop_uuid_generate(guid, sizeof(guid));
	CHECK_PTR(h, vzctl2_env_open(ctid, 0, &err))

	printf("\n(info) Creating temporary snapshot %s\n", guid);
	struct vzctl_tsnapshot_param tsnap = {
		.component_name = "test",
	};
	struct vzctl_snap_holder holder = {};

	CHECK_RET(vzctl2_env_create_temporary_snapshot(h, guid, &tsnap, &holder));
	vzctl2_release_snap_holder(&holder);
	CHECK_RET(vzctl2_delete_snapshot(h, guid))

	vzctl2_env_close(h);
}

void test_get_total_meminfo()
{
	unsigned long limit, usage;

	TEST()
	CHECK_RET(vzctl2_get_env_total_meminfo(&limit, &usage));

	printf("Toral mem limit: %lu usage: %lu\n", limit, usage);
}

static void do_env_destroy(ctid_t ctid)
{
	int err;

	vzctl_env_handle_ptr h;

	CHECK_PTR(h, vzctl2_env_open(ctid, 0, &err))

	CHECK_RET(vzctl2_env_destroy(h, 0));

	vzctl2_env_close(h);
}

static void do_env_create(struct vzctl_env_param *env,
		struct vzctl_env_create_param *param)
{

	CHECK_RET(vzctl2_env_create(env, param, 0));
	do_env_destroy(param->ctid);
}

void test_create()
{
	struct vzctl_env_create_param param = {};
	struct vzctl_env_param *env = vzctl2_alloc_env_param();

	TEST()
	bzero(param.ctid, sizeof(ctid_t));
	do_env_create(env, &param);

	param.layout = 4;
	do_env_create(env, &param);

	param.layout = 5;
	do_env_create(env, &param);

	param.ostmpl = "centos-6";
	strcpy(param.ctid, "e92f5f04-2906-41cb-8ee2-fac51e59d8c5");
	param.config = "vswap.512MB";
	do_env_create(env, &param);

	vzctl2_env_add_ipaddress(env, "1.1.1.100");
	vzctl2_env_add_nameserver(env, "1.1.1.1");
	vzctl2_env_add_nameserver(env, "1.1.1.2");
	vzctl2_env_add_searchdomain(env, "resr.ru");

	struct vzctl_veth_dev_param dev = {.dev_name_ve = "eth0"};
	vzctl2_env_add_veth(env, vzctl2_create_veth_dev(&dev, sizeof(dev)));
	do_env_create(env, &param);

	param.name = "test-create";
	do_env_create(env, &param);

	param.ve_private = "/tmp/$VEID";
	do_env_create(env, &param);

	param.ve_private = "/tmp/200";
	do_env_create(env, &param);

	param.layout = 5;
	param.ve_private = NULL;
	param.no_root_disk = 1;
	do_env_create(env, &param);


	vzctl2_free_env_param(env);
}

int cleanup(void)
{
	vzctl_env_handle_ptr h;
	vzctl_env_status_t status;
	int err;

	h = vzctl2_env_open(ctid, 0, &err);
	if (h == NULL)
		return 0;
	vzctl2_get_env_status_info(h, &status, ENV_STATUS_ALL);

	if (!(status.mask & ENV_STATUS_EXISTS))
		return 0;

	if (status.mask & ENV_STATUS_RUNNING)
		vzctl2_env_stop(h, M_KILL, 0);
	else if (status.mask & ENV_STATUS_MOUNTED)
		vzctl2_env_umount(h, 0);

	vzctl2_env_destroy(h, 0);

	vzctl2_env_close(h);

	return 0;
}

void test_reinstall()
{
	int err;
	char cmd[1024];
	vzctl_env_handle_ptr h;
	struct vzctl_env_param *env = vzctl2_alloc_env_param();
	struct vzctl_env_create_param create_param = {
	};
	struct vzctl_reinstall_param reinstall_param = {
		.skipbackup = 1,
	};

	TEST()
	cleanup();
	CHECK_RET(vzctl2_env_create(env, &create_param, 0))
	vzctl2_free_env_param(env);
	CHECK_PTR(h, vzctl2_env_open(ctid, 0, &err))
	/* Install app template */
	CHECK_RET(vzctl2_env_start(h, VZCTL_WAIT))
	snprintf(cmd, sizeof(cmd), "vzpkg install %d mysql", veid);
	system(cmd);
	snprintf(cmd, sizeof(cmd), "vzctl exec %d useradd test", veid);
	system(cmd);
	vzctl2_env_stop(h, M_HALT, 0);

	CHECK_RET(vzctl2_env_reinstall(h, &reinstall_param))

	vzctl2_env_close(h);
}

void test_ctid()
{
	int i;
	char buf[40];
	char valid[][40] = {{"{fff05e2d-48d7-40c1-a2ce-9c33c0dfc9e1}"},
			{"fff05e2d-48d7-40c1-a2ce-9c33c0dfc9e1"},
			{"fff05e2d48d740c1a2ce9c33c0dfc9e1"}};


	char invalid[][40] = {{"{vff05e2d-48d7-40c1-a2ce-9c33c0dfc9e1}"},
			{"fff05e2d8-4d7-40c1-a2ce-9c33c0dfc9e1"},
			{"fff05e2d48d740c1a2ce0dfc9e1"},
			{"fff05e2d48d740c1a2ce9c33c0dfc9e1asdf"}};

	TEST()

	for (i = 0; i < sizeof(valid)/sizeof(valid[0]); i++) {
		CHECK_RET(vzctl2_get_normalized_guid(valid[i], buf, sizeof(buf)))
		if (strcmp(buf, valid[0])) {
			printf("\t src=%s out=%s != %s\n", valid[i], buf, valid[0]);
			CHECK_RET(1)
		}

		CHECK_RET(vzctl2_get_normalized_uuid(valid[i], buf, sizeof(buf)))
		if (strcmp(buf, valid[1])) {
			printf("\t src=%s out=%s != %s\n", valid[i], buf, valid[1]);
			CHECK_RET(1)
		}

		CHECK_RET(vzctl2_get_normalized_ctid(valid[i], buf, sizeof(buf)))
		if (strcmp(buf, valid[2])) {
			printf("\t src=%s out=%s != %s\n", valid[i], buf, valid[2]);
			CHECK_RET(1)
		}
	}
	for (i = 0; i < sizeof(invalid)/sizeof(invalid[0]); i++) {
		CHECK_RET(!vzctl2_get_normalized_guid(invalid[i], buf, sizeof(buf)))
		CHECK_RET(!vzctl2_get_normalized_uuid(invalid[i], buf, sizeof(buf)))
		CHECK_RET(!vzctl2_get_normalized_ctid(invalid[i], buf, sizeof(buf)))
	}
}

void test_vzctl()
{
        int err;
        vzctl_env_handle_ptr h;
	struct vzctl_env_param *env = vzctl2_alloc_env_param();
        struct vzctl_env_create_param param = {};
	SET_CTID(param.ctid, ctid)

	test_ctid();
	test_misc();

	/* CREATE TEST CT */
	CHECK_RET(vzctl2_env_create(env, &param, 0));

//	test_create();
	test_get_total_meminfo();
	test_lock();
	test_vzlimits();
	test_mount();
	test_disk();
	test_snapshot();
	test_tsnapshot();

	/* TEST ON RUNNING CT */
	CHECK_PTR(h, vzctl2_env_open(ctid, 0, &err))
	CHECK_RET(vzctl2_env_start(h, 0))
	vzctl2_env_close(h);

	test_cpustat();
	test_iostat();
	test_set_userpasswd();
	test_exec();
	test_meminfo();

	test_env_stop();
	test_env_register();
//	test_reinstall();
}
