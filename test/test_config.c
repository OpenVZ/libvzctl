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

#include <limits.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "vzctl_param.h"
#include "test.h"
#include "cap.h"
#include "vzerror.h"


extern ctid_t ctid;

struct vzctl_cpulimit_param cpulimit;
struct vzctl_2UL_res ul_res;
unsigned long ul;

unsigned long rand_ul()
{
	unsigned long rnd = time(0);
	int fd;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd >= 0) {
		read(fd, &rnd, sizeof(rnd));
		close(fd);
	}

	srand(rnd);
	rnd = rand() & 0xfff;
	return rnd;
}

void test_config_CPULIMIT(vzctl_env_handle_ptr h)
{
	vzctl_env_handle_ptr h_res = NULL;
	vzctl_env_param_ptr new_param;
	struct vzctl_cpulimit_param res;
	int  err;

	TEST()
	CHECK_PTR(new_param, vzctl2_alloc_env_param())

	// VZCTL_CPULIMIT_MHZ
	cpulimit.limit = 1000;
	cpulimit.type = VZCTL_CPULIMIT_MHZ;
	printf("(info) vzctl2_env_set_cpulimit VZCTL_CPULIMIT_MHZ limit=%lu type=%d\n",
			cpulimit.limit, cpulimit.type);

	CHECK_RET(vzctl2_env_set_cpulimit(new_param, &cpulimit))
	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))
	CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))

	CHECK_RET(vzctl2_env_get_cpulimit(vzctl2_get_env_param(h_res), &res))
	if (res.type != cpulimit.type || res.limit != cpulimit.limit) {
		printf("\t(err) limit=%lu type=%d\n", res.limit, res.type);
		TEST_ERR("vzctl2_env_get_cpulimit VZCTL_CPULIMIT_MHZ")
	}
	vzctl2_env_close(h_res);

	// VZCTL_CPULIMIT_PCT
	cpulimit.limit = 50;
	cpulimit.type = VZCTL_CPULIMIT_PCT;
	printf("(info) vzctl2_env_set_cpulimit VZCTL_CPULIMIT_PCT limit=%lu type=%d\n",
			cpulimit.limit, cpulimit.type);
	CHECK_RET(vzctl2_env_set_cpulimit(new_param, &cpulimit))
	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))
	CHECK_RET(vzctl2_env_get_cpulimit(vzctl2_get_env_param(h), &res))
	if (res.type != cpulimit.type || res.limit != cpulimit.limit) {
		printf("\t(err) limit=%lu type=%d\n", res.limit, res.type);
		TEST_ERR("vzctl2_env_get_cpulimit VZCTL_CPULIMIT_PCT")
	}

	vzctl2_free_env_param(new_param);

	CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))
	CHECK_RET(vzctl2_env_get_cpulimit(vzctl2_get_env_param(h_res), &res))
	if (res.type != cpulimit.type || res.limit != cpulimit.limit) {
		printf("\t(err) limit=%lu/%lu type=%d/%d\n",
			cpulimit.limit, res.limit,
			cpulimit.type, res.type);
		TEST_ERR("vzctl2_env_get_cpulimit after save VZCTL_CPULIMIT_PCT")
	}

	vzctl2_env_close(h_res);
}

void test_config_CPUUNITS(vzctl_env_handle_ptr h)
{
	int err;
	vzctl_env_handle_ptr h_res = NULL;
	vzctl_env_param_ptr new_param;
	unsigned long res;

	TEST()
	CHECK_PTR(new_param, vzctl2_alloc_env_param())
	ul = rand_ul();
	printf("(info) vzctl2_env_set_cpuunits units=%lu\n", ul);
	CHECK_RET(vzctl2_env_set_cpuunits(new_param, ul))
	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))
	CHECK_RET(vzctl2_env_get_cpuunits(vzctl2_get_env_param(h), &res))
	if (res != ul)
		TEST_ERR("vzctl2_env_get_cpuunits")

	vzctl2_free_env_param(new_param);

	CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))

	CHECK_RET(vzctl2_env_get_cpuunits(vzctl2_get_env_param(h_res), &res))
	if (res != ul) {
		printf("\t(err) units=%lu/%lu\n", ul, res);
		TEST_ERR("vzctl2_env_get_cpuunits after save")
	}

	vzctl2_env_close(h_res);
}

void test_config_CPUMASK(vzctl_env_handle_ptr h)
{
	int err, i;
	vzctl_env_handle_ptr h_res = NULL;
	vzctl_env_param_ptr new_param, env;
	const char *str = "0,3,5-100,4095";
	const char *bad[] = {"abc", "1-sdc", "0-1024000", NULL};
	char data[1024];

	TEST()
	CHECK_PTR(new_param, vzctl2_alloc_env_param())

	printf("(info) test_config_CPUMASK incorrect\n");
	for (i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
		if (vzctl2_env_set_cpumask(new_param, bad[i]) == 0)
			TEST_ERR("vzctl2_env_set_cpumask");
	}

	printf("(info) test_config_CPUMASK=%s\n", str);
	CHECK_VZRET(vzctl2_env_set_cpumask(new_param, str))
	CHECK_VZRET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

	env = new_param;
	for (i = 0; i < 2; i++) {
		CHECK_RET(vzctl2_env_get_cpumask(env, data, sizeof(data)))
		if (strcmp(data, str)) {
			printf("\t(err) %s != %s\n", str, data);
			TEST_ERR("vzctl2_env_get_cpumask");
		}

		vzctl2_env_close(h_res);
		CHECK_PTR(h_res, vzctl2_env_open(ctid, 0, &err))
		env = vzctl2_get_env_param(h_res);
	}

	vzctl2_env_close(h_res);
	h_res = NULL;
	vzctl2_free_env_param(new_param);

	printf("(info) test_config_CPUMASK=all\n");
	CHECK_PTR(new_param, vzctl2_alloc_env_param())
	CHECK_RET(vzctl2_env_set_cpumask(new_param, "all"))
	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

	env = new_param;
	for (i = 0; i < 2; i++) {
		CHECK_RET(vzctl2_env_get_cpumask(vzctl2_get_env_param(h), data, sizeof(data)))
		if (strcmp(data, "")) {
			printf("\t(err) "" != %s\n", data);
			TEST_ERR("vzctl2_env_get_cpumask");
		}

		vzctl2_env_close(h_res);
		CHECK_PTR(h_res, vzctl2_env_open(ctid, 0, &err))
		env = vzctl2_get_env_param(h_res);
	}

	vzctl2_env_close(h_res);
	vzctl2_free_env_param(new_param);
}

void test_config_NODEMASK(vzctl_env_handle_ptr h)
{
	int ret, err, i;
	vzctl_env_handle_ptr h_res = NULL;
	vzctl_env_param_ptr new_param, env;
	const char *str = "0,3,5-100,4095";
	const char *bad[] = {"abc", "1-sdc", "0-1024000", NULL};
	char data[1024];

	TEST()
	CHECK_PTR(new_param, vzctl2_alloc_env_param())

	printf("(info) test_config_NODEMASK incorrect\n");
	for (i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
		ret = vzctl2_env_set_nodemask(new_param, bad[i]);
		if (ret == 0)
			TEST_ERR("vzctl2_env_set_nodemask");
	}

	printf("(info) test_config_NODEMASK=%s\n", str);
	CHECK_RET(vzctl2_env_set_nodemask(new_param, str))
	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

	env = new_param;
	for (i = 0; i < 2; i++) {
		CHECK_RET(vzctl2_env_get_nodemask(env, data, sizeof(data)))
		if (strcmp(data, str)) {
			printf("\t(err) %s != %s\n", str, data);
			TEST_ERR("vzctl2_env_get_nodemask");
		}

		vzctl2_env_close(h_res);
		CHECK_PTR(h_res, vzctl2_env_open(ctid, 0,&err))
		env = vzctl2_get_env_param(h_res);
	}

	vzctl2_env_close(h_res);
	h_res = NULL;
	vzctl2_free_env_param(new_param);
	printf("(info) test_config_NODEMASK=all\n");
	CHECK_PTR(new_param, vzctl2_alloc_env_param())
	CHECK_RET(vzctl2_env_set_nodemask(new_param, "all"))
	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

	env = new_param;
	for (i = 0; i < 2; i++) {
		CHECK_RET(vzctl2_env_get_nodemask(env, data, sizeof(data)))
		if (strcmp(data, "")) {
			printf("\t(err) "" != %s\n", data);
			TEST_ERR("vzctl2_env_get_nodemask");
		}

		vzctl2_env_close(h_res);
		CHECK_PTR(h_res, vzctl2_env_open(ctid, 0, &err))
		env = vzctl2_get_env_param(h_res);
	}

	vzctl2_env_close(h_res);
	vzctl2_free_env_param(new_param);
}

void test_config_DISK(vzctl_env_handle_ptr h)
{
	int err, i;
	vzctl_env_handle_ptr h_res = NULL;
	vzctl_env_param_ptr new_param, env;
	struct vzctl_2UL_res res;
	unsigned long limit;

	TEST()
	CHECK_PTR(new_param, vzctl2_alloc_env_param())

	ul_res.b = rand_ul() * 10000;
	ul_res.l = rand_ul() * 10000;
	limit = rand_ul();
	printf("(info) vzctl2_env_set_diskspace %lu:%lu qgidlimit: %lu\n",
			ul_res.b, ul_res.l, limit);
	CHECK_RET(vzctl2_env_set_diskspace(new_param, &ul_res))
	CHECK_RET(vzctl2_env_set_diskinodes(new_param, &ul_res))
	CHECK_RET(vzctl2_env_set_quotaugidlimit(new_param, limit))
	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

	env = vzctl2_get_env_param(h);
	for (i = 0; i < 2; i++) {
		CHECK_RET(vzctl2_env_get_diskspace(env, &res))
		if (res.b != ul_res.b || res.l != ul_res.l) {
			printf("\t(err) %lu:%lu %lu:%lu\n",
					ul_res.b, ul_res.l, res.b, res.l);
			TEST_ERR("vzctl2_env_get_diskspace")
		}

		CHECK_RET(vzctl2_env_get_diskinodes(env, &res))
		if (res.b != ul_res.b || res.l != ul_res.l) {
			printf("\t(err) %lu:%lu %lu:%lu\n",
					ul_res.b, ul_res.l, res.b, res.l);
			TEST_ERR("vzctl2_env_get_diskinodes")
		}

		unsigned long _limit;
		CHECK_RET(vzctl2_env_get_quotaugidlimit(env, &_limit))
		if (limit != _limit) {
			printf("\t(err) %lu %lu\n", limit, _limit);
			TEST_ERR("vzctl2_env_get_quotaugidlimit")
		}

		vzctl2_env_close(h_res);
		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))
		env = vzctl2_get_env_param(h_res);
	}
	vzctl2_env_close(h_res);
	vzctl2_free_env_param(new_param);
}

void test_config_UB(vzctl_env_handle_ptr h)
{
	int err, i, j;
	vzctl_env_handle_ptr h_res = NULL;
	vzctl_env_param_ptr new_param, env;
	struct vzctl_2UL_res res;

	TEST()
	CHECK_PTR(new_param, vzctl2_alloc_env_param())

	ul_res.b = rand_ul() * 10000;
	ul_res.l = rand_ul() * 10000;
	printf("(info) vzctl2_env_set_ub_resource %lu:%lu\n",
			ul_res.b, ul_res.l);

	for (i = 0; i < 2; i++) {
		for (i = VZCTL_PARAM_LOCKEDPAGES; i <= VZCTL_PARAM_SWAPPAGES; i++) {
			err = vzctl2_env_set_ub_resource(new_param, i, &ul_res);
			if (err == VZCTL_E_INVAL)
				continue;
		}
	}
	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

	env = new_param;
	for (i = 0; i < 2; i++) {
		for (j = VZCTL_PARAM_LOCKEDPAGES; j <= VZCTL_PARAM_SWAPPAGES; j++) {
			err = vzctl2_env_get_ub_resource(env, j, &res);
			if (err == VZCTL_E_INVAL)
				continue;

			if (res.b != ul_res.b || res.l != ul_res.l) {
				printf("\t(err) resid %d %lu:%lu %lu:%lud\n",
					j, ul_res.b, ul_res.l, res.b, res.l);
				TEST_ERR("vzctl2_env_get_ub_resource ")
			}
		}

		vzctl2_env_close(h_res);
		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))
		env = vzctl2_get_env_param(h_res);
	}
	vzctl2_env_close(h_res);
	vzctl2_free_env_param(new_param);
}

void test_config_IO(vzctl_env_handle_ptr h)
{
	int err, i;
	vzctl_env_handle_ptr h_res = NULL;
	vzctl_env_param_ptr new_param, env;
	unsigned int res;

	TEST()
	CHECK_PTR(new_param, vzctl2_alloc_env_param())

	ul = rand_ul() * 1000 ;
	printf("(info) io limit %lu\n", ul);

	CHECK_RET(vzctl2_env_set_iolimit(new_param, ul))
	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

	env = new_param;
	for (i = 0; i < 2; i++) {
		CHECK_RET(vzctl2_env_get_iolimit(env, &res))
		if (ul != res) {
			printf("\t(err) %lu/%d\n", ul, res);
			TEST_ERR("vzctl2_env_get_iolimit")
		}


		vzctl2_env_close(h_res);
		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))
		env = vzctl2_get_env_param(h_res);
	}
	vzctl2_env_close(h_res);
	h_res = NULL;
	vzctl2_free_env_param(new_param);

	CHECK_PTR(new_param, vzctl2_alloc_env_param())
	ul = rand_ul();
	printf("(info) IOPS limit %lu\n", ul);

	CHECK_RET(vzctl2_env_set_iopslimit(new_param, ul))
	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

	env = new_param;
	for (i = 0; i < 2; i++) {
		CHECK_RET(vzctl2_env_get_iopslimit(env, &res))
		if (ul != res) {
			printf("\t(err) %lu/%d\n", ul, res);
			TEST_ERR("vzctl2_env_get_iopslimit")
		}

		vzctl2_env_close(h_res);
		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))
		env = vzctl2_get_env_param(h_res);
	}
	vzctl2_env_close(h_res);
	h_res = NULL;
	vzctl2_free_env_param(new_param);

	CHECK_PTR(new_param, vzctl2_alloc_env_param())
	ul = rand_ul() % 7;
	printf("(info) IOPRIO %lu\n", ul);

	CHECK_RET(vzctl2_env_set_ioprio(new_param, ul))
	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

	env = new_param;
	for (i = 0; i < 2; i++) {
		int i;
		CHECK_RET(vzctl2_env_get_ioprio(env, &i))
		if (ul != i) {
			printf("\t(err) %lu != %d\n", ul, i);
			TEST_ERR("vzctl2_env_get_ioprio")
		}

		vzctl2_env_close(h_res);
		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))
		env = vzctl2_get_env_param(h_res);
	}
	vzctl2_env_close(h_res);
	vzctl2_free_env_param(new_param);
}

void test_config_IP(vzctl_env_handle_ptr h)
{
	int err, i;
	vzctl_env_handle_ptr h_res = NULL;
	vzctl_env_param_ptr new_param, env;
	vzctl_ip_iterator it;
	int cnt, total;
	char buf[128];
	char *ipstr = "1.1.1.%d/24";
	char *ip6str = "facc::%d/64";

	TEST()
	CHECK_PTR(new_param, vzctl2_alloc_env_param())

	printf("(info) vzctl_env_set_ipaddress %s\n", ipstr);
	total = 0;
	for (cnt = 0; cnt < 5; cnt++, total++) {
		sprintf(buf, ipstr, cnt + 1);
		CHECK_RET( vzctl2_env_add_ipaddress(new_param, buf))
	}

	for (cnt = 0; cnt < 5; cnt++, total++) {
		sprintf(buf, ip6str, cnt + 1);
		CHECK_RET(vzctl2_env_add_ipaddress(new_param, buf))
	}

	CHECK_RET(vzctl2_env_del_ipaddress(new_param, "all"))
	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

	env = new_param;
	for (i = 0; i < 2; i++) {
		cnt = 0;
		it = NULL;
		while ((it = vzctl2_env_get_ipaddress(env, it)) != NULL) {
			vzctl2_env_get_ipstr(it, buf, sizeof(buf));
			cnt++;
		}
		if (cnt != total)
			TEST_ERR("\t vzctl2_env_get_ipaddress: cnt != total");


		vzctl2_env_close(h_res);
		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))
		env = vzctl2_get_env_param(h_res);
	}

	vzctl2_free_env_param(new_param);
	// TEST DELALL
	CHECK_PTR(new_param, vzctl2_alloc_env_param())

	printf("(info) vzctl2_env_add_ipaddress(delall)\n");

	CHECK_RET(vzctl2_env_del_ipaddress(new_param, "all"))
	CHECK_RET(vzctl2_apply_param(h_res, new_param, VZCTL_SAVE))

	vzctl2_free_env_param(new_param);

	vzctl2_env_close(h_res);
}

static int check_str_val(const char *set, const char *res)
{
	if (set == NULL || *set == 0) {
		if (res == NULL || *res == 0)
			return 0;
		return 1;
	} else if (res == NULL || *res == 0)
		return 1;
	else
		return strcmp(set, res);
	return 0;
}

void test_config_VETH_dev(vzctl_env_handle_ptr h, int allow_mac_spoof, int allow_ip_spoof)
{
	int i, err;
	vzctl_env_handle_ptr h_res = NULL;
	vzctl_env_param_ptr new_param, env;
	vzctl_veth_dev_iterator it_dev;
	struct vzctl_veth_dev_param dev = {};
	char dev_name[64];
	const char *p = NULL;

	TEST()
	snprintf(dev_name, sizeof(dev_name), "xeth.%c.0", ctid[0]);

	CHECK_PTR(new_param, vzctl2_alloc_env_param())
	dev.dev_name_ve = "eth0";
	dev.dev_name = dev_name;
	dev.allow_mac_spoof = allow_mac_spoof;
	dev.allow_ip_spoof = allow_ip_spoof;

	printf("(info) test_config_VETH_dev dev_name=%s allow_mac_spoof=%d allow_ip_spoof=%d\n",
			dev_name, dev.allow_mac_spoof, dev.allow_ip_spoof);

	CHECK_PTR(it_dev, vzctl2_create_veth_dev(&dev, sizeof(struct vzctl_veth_dev_param)))

	CHECK_RET(vzctl2_env_del_veth(new_param, "all"))
	CHECK_RET(vzctl2_env_add_veth(new_param, it_dev))

	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

	env = new_param;
	for (i = 0; i < 2; i++) {
		it_dev = NULL;
		while ((it_dev = vzctl2_env_get_veth(env, it_dev)) != NULL) {
			struct vzctl_veth_dev_param _p;
			vzctl2_env_get_veth_param(it_dev, &_p, sizeof(_p));
			if (strcmp(dev.dev_name, _p.dev_name)) {
				printf("failed to set dev_name: dev_name=%s != new dev_name=%s\n",
						dev.dev_name, _p.dev_name);
				TEST_ERR("dev_name != new dev_name");
			}

			if (_p.allow_mac_spoof != dev.allow_mac_spoof) {
				printf("_p.allow_mac_spoof %d != dev.allow_mac_spoof %d\n",
						_p.allow_mac_spoof, dev.allow_mac_spoof);
				TEST_ERR("_p.allow_mac_spoof != dev.allow_mac_spoof")
			}

			if (_p.allow_ip_spoof != dev.allow_ip_spoof) {
				printf("_p.allow_ip_spoof %d != dev.allow_ip_spoof %d\n",
						_p.allow_ip_spoof, dev.allow_ip_spoof);
				TEST_ERR("_p.allow_ip_spoof != dev.allow_ip_spoof")
			}
		}

		vzctl2_env_close(h_res);
		CHECK_PTR(h_res, vzctl2_env_open(ctid, 0, &err))

		p = NULL;
		vzctl2_env_get_param(h_res, "NETIF", &p);
		printf("\tNETIF=%s\n", p);

		env = vzctl2_get_env_param(h_res);
	}

	vzctl2_env_get_param(h_res, "NETIF", &p);
	printf("\tNETIF=%s\n", p);

	vzctl2_env_close(h_res);
	vzctl2_free_env_param(new_param);
}

void test_config_VETH_gw(vzctl_env_handle_ptr h, const char *gw, const char *gw6)
{
	int err, i;
	vzctl_env_handle_ptr h_res = NULL;
	vzctl_env_param_ptr new_param, env;
	vzctl_veth_dev_iterator it_dev;
	struct vzctl_veth_dev_param dev = {};
	const char *p;

	TEST()
	printf("(info) test_config_VETH_gw gw=%s gw6=%s\n", gw, gw6);
	CHECK_PTR(new_param, vzctl2_alloc_env_param())

	dev.dev_name_ve = "eth0";
	dev.gw = gw;
	dev.gw6 = gw6;

	CHECK_PTR(it_dev, vzctl2_create_veth_dev(&dev, sizeof(struct vzctl_veth_dev_param)))

	CHECK_RET(vzctl2_env_del_veth(new_param, "all"))
	CHECK_RET(vzctl2_env_add_veth(new_param, it_dev))

	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

	env = new_param;
	for (i = 0; i < 2; i++) {
		it_dev = NULL;
		while ((it_dev = vzctl2_env_get_veth(env, it_dev)) != NULL) {
			struct vzctl_veth_dev_param _p;

			vzctl2_env_get_veth_param(it_dev, &_p, sizeof(struct vzctl_veth_dev_param));
			if (check_str_val(gw, _p.gw)) {
				TEST_VZERR("vzctl2_env_get_veth_param");
				printf("failed to set gw: gw=%s != param_gw=%s\n",
						_p.gw, gw);
			}
			if (check_str_val(gw6, _p.gw6)) {
				TEST_VZERR("vzctl2_env_get_veth_param");
				printf("failed to set gw6: gw6=%s != param_gw6=%s\n",
						_p.gw6, gw6);
			}
		}

		vzctl2_env_close(h_res);
		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))

		p = NULL;
		vzctl2_env_get_param(h_res, "NETIF", &p);
		printf("\tNETIF=%s\n", p);

		env = vzctl2_get_env_param(h_res);
	}

	vzctl2_env_close(h_res);
	vzctl2_free_env_param(new_param);
}

void test_config_VETH_dhcp(vzctl_env_handle_ptr h, int dhcp, int dhcp6)
{
	int err, i;
	vzctl_env_handle_ptr h_res = NULL;
	vzctl_env_param_ptr new_param, env;
	vzctl_veth_dev_iterator it_dev;
	struct vzctl_veth_dev_param dev = {};
	const char *p;

	TEST()
	printf("(info) test_config_VETH_dhcp dhcp=%s dhcp6=%s \n",
			dhcp ? "yes": "no", dhcp6 ? "yes": "no");
	CHECK_PTR(new_param, vzctl2_alloc_env_param())

	dev.dev_name_ve = "eth0";
	dev.dhcp = dhcp;
	dev.dhcp6 = dhcp6;

	CHECK_PTR(it_dev, vzctl2_create_veth_dev(&dev, sizeof(struct vzctl_veth_dev_param)))

	CHECK_RET(vzctl2_env_del_veth(new_param, "all"))
	CHECK_RET(vzctl2_env_add_veth(new_param, it_dev))

	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

	env = new_param;
	for (i = 0; i < 2; i++) {
		it_dev = NULL;
		while ((it_dev = vzctl2_env_get_veth(env, it_dev)) != NULL) {
			struct vzctl_veth_dev_param _p;
			vzctl2_env_get_veth_param(it_dev, &_p, sizeof(struct vzctl_veth_dev_param));
			if (_p.dhcp != dhcp) {
				printf("failed to set dhcp: dhcp=%d != param_dhcp=%d\n",
						dhcp, _p.dhcp);
				TEST_ERR("vzctl2_env_get_veth_param");
			}
			if (_p.dhcp6 != dhcp6) {
				printf("failed to set dhcp6: dhcp6=%d != param_dhcp6=%d\n",
						dhcp6, _p.dhcp6);
				TEST_ERR("vzctl2_env_get_veth_param");
			}
		}
		if (i == 1)
			break;

		vzctl2_env_close(h_res);
		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))

		p = NULL;
		vzctl2_env_get_param(h_res, "NETIF", &p);
		printf("\tNETIF=%s\n", p);

		env = vzctl2_get_env_param(h_res);
	}

	vzctl2_env_close(h_res);
	vzctl2_free_env_param(new_param);
}


void test_config_VETH_ip(vzctl_env_handle_ptr h)
{
	int err, i;
	vzctl_env_handle_ptr h_res = NULL;
	vzctl_env_param_ptr new_param, env;
	vzctl_env_param_ptr param;
	vzctl_ip_iterator it_ip;
	vzctl_veth_dev_iterator it_dev;
	struct vzctl_veth_dev_param dev = {};
	int cnt;
	char buf[128];
	char *ipstr = "1.1.1.%d/24";
	char *ip6str = "fa00::%d/64";
	const char *p;

	TEST()
	CHECK_PTR(new_param, vzctl2_alloc_env_param())

	dev.dev_name_ve = "eth0";
	dev.gw = "1.1.1.1";
	dev.network = "bridged";
	dev.mac = "00C4B2010000";
	dev.mac_ve = "001851A38559";

	CHECK_PTR(it_dev, vzctl2_create_veth_dev(&dev, sizeof(struct vzctl_veth_dev_param)))

	for (cnt = 1; cnt < 3; cnt++) {
		sprintf(buf, ipstr, cnt);
		CHECK_RET(vzctl2_env_add_veth_ipaddress(it_dev, buf))
	}

	for (cnt = 1; cnt < 4; cnt++) {
		sprintf(buf, ip6str, cnt);
		CHECK_RET(vzctl2_env_add_veth_ipaddress(it_dev, buf))
	}

	CHECK_RET(vzctl2_env_del_veth(new_param, "all"))
	CHECK_RET(vzctl2_env_add_veth(new_param, it_dev))

	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

	env = new_param;
	for (i = 0; i < 2; i++) {
		it_dev = NULL;
		while ((it_dev = vzctl2_env_get_veth(env, it_dev)) != NULL) {
			struct vzctl_veth_dev_param _p;
			vzctl2_env_get_veth_param(it_dev, &_p, sizeof(struct vzctl_veth_dev_param));
			printf("\t host_mac=%s mac=%s\n",
				_p.mac, _p.mac_ve);
			it_ip = NULL;
			while ((it_ip = vzctl2_env_get_veth_ipaddress(it_dev, it_ip)) != NULL) {

				vzctl2_env_get_ipstr(it_ip, buf, sizeof(buf));
				printf("%s\n", buf);
				cnt++;
			}
		}

		vzctl2_env_close(h_res);
		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))

		p = NULL;
		CHECK_RET(vzctl2_env_get_param(h_res, "NETIF", &p))
		printf("\tNETIF=%s\n", p);

		env = vzctl2_get_env_param(h_res);
	}

	vzctl2_env_close(h_res);
	h_res = NULL;
	vzctl2_free_env_param(new_param);

	// Del ip all
	dev.ip_apply_mode = 1;
	CHECK_PTR(new_param, vzctl2_alloc_env_param())
	CHECK_PTR(it_dev, vzctl2_create_veth_dev(&dev, sizeof(struct vzctl_veth_dev_param)))

	CHECK_RET(vzctl2_env_add_veth(new_param, it_dev))
	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

	vzctl2_free_env_param(new_param);

	// DEL
	printf("(info) test_config_VETH_ip <del>\n");

	CHECK_PTR(new_param, vzctl2_alloc_env_param())
	CHECK_RET(vzctl2_env_del_veth(new_param, "eth0"))
	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

	it_dev = NULL;
	it_dev = vzctl2_env_get_veth(new_param, it_dev);

	CHECK_RET(vzctl2_env_save(h))
	CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))
	CHECK_PTR(param, vzctl2_get_env_param(h_res))

	p = NULL;
	CHECK_RET(vzctl2_env_get_param(h_res, "NETIF", &p))
	printf("\tNETIF=%s\n", p);
	it_dev = NULL;
	it_dev = vzctl2_env_get_veth(param, it_dev);
	if (it_dev != NULL)
		TEST_VZERR("vzctl2_env_del_veth del after save");

	vzctl2_free_env_param(new_param);
	vzctl2_env_close(h_res);

	// DELALL
	printf("(info) test_config_VETH_ip <delall>\n");
	CHECK_PTR(new_param, vzctl2_alloc_env_param())
	CHECK_RET(vzctl2_env_del_veth(new_param, "*"))

	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

	it_dev = NULL;
	it_dev = vzctl2_env_get_veth(new_param, it_dev);
	if (it_dev != NULL)
		TEST_VZERR("vzctl2_env_del_veth delall");

	CHECK_RET(vzctl2_env_save(h))
	CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))

	it_dev = NULL;
	vzctl2_env_get_param(h_res, "NETIF", &p);
	printf("\tNETIF=%s\n", p);

	CHECK_PTR(param, vzctl2_get_env_param(h_res))
	it_dev = NULL;
	it_dev = vzctl2_env_get_veth(param, it_dev);
	if (it_dev != NULL)
		TEST_VZERR("vzctl2_env_del_veth delall after save");

	vzctl2_free_env_param(new_param);
	vzctl2_env_close(h_res);
}

void test_config_VETH_configure(vzctl_env_handle_ptr h, int mode)
{
	int err, i;
	vzctl_env_handle_ptr h_res = NULL;
	vzctl_env_param_ptr new_param, env;
	vzctl_veth_dev_iterator it_dev;
	struct vzctl_veth_dev_param dev = {};
	const char *p;

	TEST()
	printf("(info) test_config_VETH_configure mode=%x\n", mode);

	CHECK_PTR(new_param, vzctl2_alloc_env_param())

	dev.dev_name_ve = "eth0";
	dev.configure_mode = mode;

	CHECK_PTR(it_dev, vzctl2_create_veth_dev(&dev, sizeof(struct vzctl_veth_dev_param)))

	CHECK_RET(vzctl2_env_del_veth(new_param, "all"))
	CHECK_RET(vzctl2_env_add_veth(new_param, it_dev))

	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

	env = new_param;
	for (i = 0; i < 2; i++) {
		it_dev = NULL;
		while ((it_dev = vzctl2_env_get_veth(env, it_dev)) != NULL) {
			struct vzctl_veth_dev_param _p;
			vzctl2_env_get_veth_param(it_dev, &_p, sizeof(struct vzctl_veth_dev_param));
			if (_p.configure_mode != mode) {
				printf("failed to set configure_mode: set=%x != get=%x\n",
						mode, _p.configure_mode);
				TEST_ERR("vzctl2_env_get_veth_param");
			}
		}

		vzctl2_env_close(h_res);
		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))

		p = NULL;
		vzctl2_env_get_param(h_res, "NETIF", &p);
		printf("\tNETIF=%s\n", p);

		env = vzctl2_get_env_param(h_res);
	}

	vzctl2_env_close(h_res);
	vzctl2_free_env_param(new_param);
}

void test_config_VETH(vzctl_env_handle_ptr h)
{
	test_config_VETH_ip(h);

	test_config_VETH_dhcp(h, 1, 0);
	test_config_VETH_dhcp(h, 1, 1);
	test_config_VETH_dhcp(h, 0, 1);
	test_config_VETH_dhcp(h, 0, 0);

	test_config_VETH_gw(h, "1.10.1.1", "fd00::1");
	test_config_VETH_gw(h, "1.10.1.2", "");
	test_config_VETH_gw(h, "", "fd00::3");
	test_config_VETH_gw(h, "", "");

	test_config_VETH_configure(h, VZCTL_VETH_CONFIGURE_NONE);
	test_config_VETH_configure(h, VZCTL_VETH_CONFIGURE_ALL);

	test_config_VETH_dev(h, 0, 0);
	test_config_VETH_dev(h, 1, 1);
	test_config_VETH_dev(h, 1, 0);
	test_config_VETH_dev(h, 0, 1);
}

void test_config_UPTIME(vzctl_env_handle_ptr h)
{
	unsigned long long uptime, start_date;
	unsigned long long uptime2, start_date2;
	time_t now, expected_uptime;

	TEST()
	printf("(info) test_config_UPTIME\n");
	now = time(NULL);
	CHECK_RET(vzctl2_env_reset_uptime(h))
	CHECK_RET(vzctl2_env_get_uptime(h, &uptime, &start_date))
	if (start_date < now || start_date - now > 10 || uptime)
		TEST_ERR("Uptime reset works incorrectly\n");

	now = time(NULL);
	CHECK_RET(vzctl2_env_sync_uptime(h))
	CHECK_RET(vzctl2_env_get_uptime(h, &uptime2, &start_date2))
	if (uptime2 != uptime || start_date != start_date2)
		TEST_ERR("Uptime sync works incorrectly for stopped Container\n");

	now = time(NULL);
	CHECK_RET(vzctl2_env_start(h, 0))
	sleep(60);
	expected_uptime = time(NULL) - now;
	CHECK_RET(vzctl2_env_sync_uptime(h))
	CHECK_RET(vzctl2_env_get_uptime(h, &uptime2, &start_date2))
	if (uptime2 < expected_uptime || uptime2 - expected_uptime > 10 ||
		start_date != start_date2) {
		char msg[256];
		snprintf(msg, sizeof(msg), "Uptime sync works incorrectly for"
			" running Container, uptime = %llu, expected = %lu\n",
			uptime2, expected_uptime);
		TEST_ERR(msg);
	}
	CHECK_RET(vzctl2_env_stop(h, 0, 0))
}

void test_config_NAME(vzctl_env_handle_ptr h)
{
	int ret, err, i;
	const char *res;
	char name[256];
	vzctl_env_handle_ptr h_res = NULL;

	TEST()
	sprintf(name, "test-%s", ctid);

	for (i = 0; i < 2; i++) {
		printf("test_config_NAME: '%s'\n", name);
		CHECK_RET(vzctl2_set_name(h, name))
		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))

		ret = vzctl2_get_name(h_res, &res);
		if (name[0] == '\0') {
			if (ret == 0)
				TEST_VZERR("vzctl2_get_name");
		} else {
			if (ret != 0 || strcmp(res, name) != 0) {
				TEST_ERR("test_config_NAME");
			} else if (strcmp(res, name) != 0) {
				printf("%s != %s", res, name);
				TEST_ERR("test_config_NAME");
			}
		}

		vzctl2_env_close(h_res);
		name[0] = '\0';
	}
}

void test_config_MISC(vzctl_env_handle_ptr h)
{
	int err, i, cnt;
	const char *res = NULL;
	char *desc = "12434\n";
	const char *hostname = "tets.ru";
	char *uuid = "00000000-0000-0000-0000-000000001030";
	char buf[256];
	vzctl_env_handle_ptr h_res = NULL;
	vzctl_env_param_ptr new_param, env;

	TEST()
	CHECK_PTR(new_param, vzctl2_alloc_env_param())

	printf("test_config DESCRIPTION: '%s' HOSTNAME '%s'\n", desc, hostname);
	CHECK_RET(vzctl2_env_set_description(new_param, desc))
	CHECK_RET(vzctl2_env_set_hostname(new_param, hostname))
	for (i = 1; i < 4; i++) {

		snprintf(buf, sizeof(buf), "1.1.1.%d", i);
		CHECK_RET(vzctl2_env_add_nameserver(new_param, buf))

		snprintf(buf, sizeof(buf), "%d.ns.ru", i);
		CHECK_RET(vzctl2_env_add_searchdomain(new_param, buf))
	}

	printf("test_config UUID: %s\n", uuid);
	CHECK_RET(vzctl2_env_set_uuid(new_param, uuid))
	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

	env = new_param;
	for (i = 0; i < 2; i++) {
		vzctl_str_iterator it;

		CHECK_RET(vzctl2_env_get_description(env, &res))
		if (strcmp(res, desc) != 0) {
			printf("\t %s != %s\n", desc, res);
			TEST_ERR("vzctl_env_get_decription")
		}
		CHECK_RET(vzctl2_env_get_hostname(env, &res))
		if (strcmp(res, hostname) != 0) {
			printf("\t %s != %s\n", hostname, res);
			TEST_ERR("vzctl2_env_get_hostname")
		}
		it = NULL;
		cnt = 0;
		while ((it = vzctl2_env_get_nameserver(env, it)) != NULL) {
			cnt++;
		}
		if (cnt != 3) {
			printf("\t nameserver cnt==%d\n", cnt);
			TEST_ERR("vzctl2_env_get_nameserver")
		}

		it = NULL;
		cnt = 0;
		while ((it = vzctl2_env_get_searchdomain(env, it)) != NULL) {
			cnt++;
		}
		if (cnt != 3) {
			printf("\t earchdomain nt==%d\n", cnt);
			TEST_ERR("vzctl2_env_get_searchdomain")
		}
		CHECK_RET(vzctl2_env_get_uuid(env, &res))
		if (strcmp(res, uuid) != 0) {
			printf("\t %s != %s\n", uuid, res);
			TEST_ERR("vzctl2_env_get_uuid")
		}

		vzctl2_env_close(h_res);
		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))
		env = vzctl2_get_env_param(h_res);
	}
	vzctl2_env_close(h_res);
	vzctl2_free_env_param(new_param);
}

void test_config_RATE(vzctl_env_handle_ptr h)
{
	int err, i;
	vzctl_env_handle_ptr h_res = NULL;
	vzctl_env_param_ptr new_param;
	vzctl_env_param_ptr param;
	struct vzctl_rate_param rate_param = {};
	vzctl_rate_iterator it;
	int cnt;
	const char *p;
	int orig_rb = rand_ul() & 1;

	TEST()
	printf("(info) test_config_RATE ratebounr=%d\n", orig_rb);
	p = NULL;
	vzctl2_env_get_param(h, "RATE", &p);
	printf("\tstart RATE=%s\n", p);

	CHECK_PTR(new_param, vzctl2_alloc_env_param())

	for (i = 1; i < 3; i++) {
		rate_param.dev = "*";
		rate_param.net_class = i;
		rate_param.rate = (int) rand_ul() ;

		CHECK_PTR(it, vzctl2_create_rate(&rate_param))
		CHECK_RET(vzctl2_env_add_rate(new_param, it))
		CHECK_RET(vzctl2_env_set_ratebound(new_param, orig_rb))
	}

	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

	p = NULL;
	vzctl2_env_get_param(h, "RATE", &p);
	printf("\tapply RATE=%s\n", p);

	CHECK_PTR(param, vzctl2_get_env_param(h))
	vzctl2_free_env_param(new_param);

	for (i = 0; i < 2; i++) {
		it = NULL;
		while ((it = vzctl2_env_get_rate(param, it)) != NULL) {
			vzctl2_env_get_rate_param(it, &rate_param);
			cnt++;
		}

		int rb;
		CHECK_RET(vzctl2_env_get_ratebound(param, &rb))
		if (rb != orig_rb) {
			TEST_ERR("(rb != orig_rb")
		}

		vzctl2_env_close(h_res);
		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))

		p = NULL;
		vzctl2_env_get_param(h_res, "RATE", &p);
		printf("\tsaved RATE=%s\n", p);

		param =  vzctl2_get_env_param(h);
	}

	vzctl2_env_close(h_res);
}

void test_open()
{
	int i, err, cnt;
	vzctl_ids_t *ids;
	vzctl_env_handle_ptr *h;

	TEST()
	printf("(info) test_open\n");
	CHECK_PTR(ids, vzctl2_alloc_env_ids())
	cnt = vzctl2_get_env_ids_by_state(ids, ENV_STATUS_EXISTS);
	if (cnt < 0) {
		vzctl2_free_env_ids(ids);
		TEST_VZERR("vzctl2_get_env_ids_by_state")
	}
	if (cnt == 0) {
		vzctl2_free_env_ids(ids);
		return;
	}

	h = malloc(sizeof(vzctl_env_handle_ptr) * cnt);
	for (i = 0; i < cnt; i++) {
		struct vzctl_env_status status;

		CHECK_RET(vzctl2_get_env_status(ids->ids[i], &status, ENV_STATUS_ALL))

		printf("(info) test_open: %s status=%d\n",
				ids->ids[i], status.mask);
		h[i] = vzctl2_env_open(ids->ids[i], 0, &err);
		vzctl2_env_close(h[i]);
	}
	free(h);

	vzctl2_free_env_ids(ids);
}

void test_config_sample()
{
	int err;
	char *sample = "/etc/vz/conf/ve-basic.conf-sample";
	int flags;
	vzctl_env_handle_ptr hSample;
	vzctl_env_handle_ptr h;

	TEST()
	flags = VZCTL_CONF_SKIP_GLOBAL;
	CHECK_PTR(hSample, vzctl2_env_open_conf(0, sample, flags, &err))

	flags = VZCTL_SKIP_SETUP | VZCTL_SAVE;
	CHECK_PTR(h, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))
	CHECK_RET(vzctl2_apply_param(h, vzctl2_get_env_param(hSample), flags))
	vzctl2_env_close(hSample);
	vzctl2_env_close(h);
}

void test_config_TYPE()
{
	int err, i;
	vzctl_env_param_ptr new_param;
	vzctl_env_handle_ptr h;
	vzctl_env_type type;
	int types[] = {VZCTL_ENV_TYPE_TEMPORARY, VZCTL_ENV_TYPE_TEMPLATE, VZCTL_ENV_TYPE_REGULAR,};

	TEST()
	for (i = 0; i < sizeof(types)/sizeof(types[0]); i++) {
		CHECK_PTR(h, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))

		if (i > 0) {
			CHECK_RET(vzctl2_env_get_type(vzctl2_get_env_param(h), &type))
			if (type != types[i-1]) {
				printf("vzctl_env_get_template_mode read=%d != set=%d\n",
						type, types[i-1]);
				TEST_ERR("type != types[i-1]");
			}
		}

		CHECK_PTR(new_param, vzctl2_alloc_env_param())

		CHECK_RET(vzctl2_env_set_type(new_param, types[i]))
		CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))
		vzctl2_free_env_param(new_param);
		vzctl2_env_close(h);
	}
}

void test_config_ramsize(vzctl_env_handle_ptr h)
{
	int err;
	vzctl_env_handle_ptr h_res = NULL;
	vzctl_env_param_ptr new_param, env;
	int i;
	unsigned long size, new_size;

	TEST()
	size = rand_ul() * 1024;
	printf("(info) test_config_ramsize: %lu\n", size);
	CHECK_PTR(new_param, vzctl2_alloc_env_param())
	CHECK_RET(vzctl2_env_set_ramsize(new_param, size))
	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

	env = new_param;
	for (i = 0; i < 2; i++) {
		CHECK_RET(vzctl2_env_get_ramsize(env, &new_size))
		if (size != new_size) {
			printf("\t(err) %lu != %lu\n", size, new_size);
			TEST_ERR("vzctl2_env_get_ramsize");
		}


		vzctl2_env_close(h_res);
		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))
		env = vzctl2_get_env_param(h_res);
	}

	vzctl2_env_close(h_res);
	vzctl2_free_env_param(new_param);
}

void test_config_memguarantee(vzctl_env_handle_ptr h)
{
	int err;
	vzctl_env_handle_ptr h_res = NULL;
	vzctl_env_param_ptr new_param;
	int i;
	struct vzctl_mem_guarantee x;

	TEST()
	x.type = VZCTL_MEM_GUARANTEE_AUTO;
	x.value = 0;
	for (i = 0; i < 2; i++) {
		struct vzctl_mem_guarantee res = {
				.type = -1,
				.value = UINT_MAX,
		};

		printf("(info) test_config_memguarantee: %d:%lu\n",
				x.type, x.value);
		CHECK_PTR(new_param, vzctl2_alloc_env_param())
		CHECK_RET(vzctl2_env_set_memguarantee(new_param, &x))
		CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

		CHECK_RET(vzctl2_env_get_memguarantee(vzctl2_get_env_param(h), &res))
		if (x.type != res.type) {
			printf("\t(err) type: %d != %d\n", x.type, res.type);
			TEST_ERR("vzctl2_env_get_memguarantee");
		}


		vzctl2_env_close(h_res);
		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))
		vzctl2_free_env_param(new_param);
		CHECK_PTR(new_param, vzctl2_get_env_param(h_res))

		x.type = VZCTL_MEM_GUARANTEE_PCT;
		x.value = rand_ul() % 100;
	}

	vzctl2_env_close(h_res);
}

void test_config_layout(vzctl_env_handle_ptr h)
{
	int layout;

	TEST()
	CHECK_RET(vzctl2_env_get_layout(vzctl2_get_env_param(h), &layout))
	if (layout == 0)
		ERR("vzctl2_env_get_layout");
}

void test_config_APPLY_IPONLY(vzctl_env_handle_ptr h)
{
	int err;
	vzctl_env_handle_ptr h_res = NULL;
	vzctl_env_param_ptr new_param;
	int res, i;

	TEST()
	for (i = 1; i >= 0; i--) {
		CHECK_PTR(new_param, vzctl2_alloc_env_param())

		printf("(info) vzctl2_env_set_apply_iponly: %d\n", i);
		CHECK_RET(vzctl2_env_set_apply_iponly(new_param, i))
		CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))
		CHECK_RET(vzctl2_env_get_apply_iponly(vzctl2_get_env_param(h), &res))
		if (res != i) {
			printf("\t(err) %d/%d\n",
					i, res);
			TEST_ERR("vzctl2_env_get_apply_iponly after apply")
		}

		vzctl2_free_env_param(new_param);

		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))
		CHECK_RET(vzctl2_env_get_apply_iponly(vzctl2_get_env_param(h_res), &res))
		if (res != i) {
			printf("\t(err) %d/%d\n",
					i, res);
			TEST_ERR("vzctl2_env_get_apply_iponly after save")
		}
		vzctl2_env_close(h_res);
	}
}

void test_config_CAPABILITY(vzctl_env_handle_ptr h)
{
	int err, i;
	vzctl_env_param_ptr new_param;
	vzctl_env_handle_ptr h_res = NULL;
	const char *p = NULL;

	TEST()
	for (i = 0; i < 4; i++) {
		unsigned long capmask = 0, old_capmask = 0, setted_capmask = 0;
		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))
		CHECK_RET(vzctl2_env_get_cap(vzctl2_get_env_param(h_res), &old_capmask))
		CHECK_RET(vzctl2_env_get_param(h_res, "CAPABILITY", &p))

		if (i == 0)
			capmask = 0;
		else if (i == 1)
			capmask = i;
		else if (i == 2)
			capmask = rand_ul();
		else
			capmask = vzctl2_get_default_capmask();


		printf("Set capmask=%lx current cap mask=%lx CAPABILITY=%s\n",
				capmask, old_capmask, p);
		CHECK_PTR(new_param, vzctl2_alloc_env_param())
		CHECK_RET(vzctl2_env_set_cap(h_res, new_param, capmask))
		CHECK_RET(vzctl2_apply_param(h_res, new_param, VZCTL_SAVE))

		vzctl2_free_env_param(new_param);
		vzctl2_env_close(h_res);

		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))
		CHECK_RET(vzctl2_env_get_cap(vzctl2_get_env_param(h_res), &setted_capmask))
		if (capmask != setted_capmask) {
			printf("\t(err) cap mask=%lx, setted cap mask=%lx\n",
				capmask, setted_capmask);
			TEST_ERR("vzctl2_env_get_cap")
		}
		vzctl2_env_close(h_res);
	}
}

void test_config_FEATURES(vzctl_env_handle_ptr h)
{
	int err, i;
	vzctl_env_param_ptr new_param;
	vzctl_env_handle_ptr h_res = NULL;
	const char *p = NULL;
	unsigned long feature_mask = (VZ_FEATURE_NFSD - 1) & ~(1UL<<2);

	TEST()
	for (i = 0; i < 3; i++) {
		struct vzctl_feature_param new = {};
		struct vzctl_feature_param cur = {};

		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))
		CHECK_RET(vzctl2_env_get_features(vzctl2_get_env_param(h_res), &cur))
		CHECK_RET(vzctl2_env_get_param(h_res, "FEATURES", &p))

		new.on = rand_ul() & feature_mask;
		new.off = rand_ul() & feature_mask;
		new.off = new.off & ~new.on;

		printf("current features on=%#llx off=%#llx FEATURES=%s new_on=%#llx new_off=%#llx\n",
				cur.on, cur.off, p, new.on, new.off);

		CHECK_PTR(new_param, vzctl2_alloc_env_param())
		CHECK_RET(vzctl2_env_set_features(new_param, &new))
		CHECK_RET(vzctl2_apply_param(h_res, new_param, VZCTL_SAVE))

		vzctl2_free_env_param(new_param);
		vzctl2_env_close(h_res);

		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))
		CHECK_RET(vzctl2_env_get_features(vzctl2_get_env_param(h_res), &cur))
		if (cur.on != new.on || cur.off != new.off) {
			TEST_VZERR("vzctl2_env_get_features")
			printf("\t(err) new_on=%#llx on=%#llx new_off=%#llx off=%#llx\n",
				new.on, cur.on, new.off, cur.off);
		}
		vzctl2_env_close(h_res);
	}
}

void test_config_high_availability(vzctl_env_handle_ptr h)
{
	int err;
	vzctl_env_handle_ptr h_res = NULL;
	vzctl_env_param_ptr new_param;
	int res, i;
	unsigned long prio;

	TEST()
	for (i = 1; i >= 0; i--) {
		CHECK_PTR(new_param, vzctl2_alloc_env_param())

		printf("(info) vzctl2_env_set_ha_enable: %d\n", i);
		CHECK_RET(vzctl2_env_set_ha_enable(new_param, i))
		CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))
		CHECK_RET(vzctl2_env_get_ha_enable(vzctl2_get_env_param(h), &res))
		if (res != i) {
			printf("\t(err) %d/%d \n", i, res);
			TEST_ERR("vzctl2_env_get_ha_enable after apply")
		}

		vzctl2_free_env_param(new_param);

		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))
		CHECK_RET(vzctl2_env_get_ha_enable(vzctl2_get_env_param(h_res), &res))
		if (res != i) {
			printf("\t(err) %d/%d\n", i, res);
			TEST_ERR("vzctl2_env_get_ha_enable after save")
		}

		vzctl2_env_close(h_res);
	}

	CHECK_PTR(new_param, vzctl2_alloc_env_param())

	ul = rand_ul() % UINT_MAX;
	printf("(info) vzctl2_env_set_ha_prio prio=%lu\n", ul);
	CHECK_RET(vzctl2_env_set_ha_prio(new_param, ul))
	CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))
	CHECK_RET(vzctl2_env_get_ha_prio(vzctl2_get_env_param(h), &prio))
	if (prio != ul)
		TEST_ERR("vzctl2_env_get_ha_prio")

	vzctl2_free_env_param(new_param);

	CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))
	CHECK_RET(vzctl2_env_get_ha_prio(vzctl2_get_env_param(h_res), &prio))
	if (prio != ul) {
		printf("\t(err) prio=%lu/%lu\n", ul, prio);
		TEST_ERR("vzctl2_env_get_ha_prio after save")
	}

	vzctl2_env_close(h_res);
}

void test_config_netfilter(vzctl_env_handle_ptr h)
{
	int err;
	vzctl_env_handle_ptr h_res = NULL;
	vzctl_env_param_ptr new_param;
	int i;
	unsigned res;

	TEST()
	for (i = VZCTL_NF_DISABLED; i <= VZCTL_NF_FULL; i++) {
		CHECK_PTR(new_param, vzctl2_alloc_env_param())

		printf("(info) set netfilter: %d\n", i);
		CHECK_RET(vzctl2_env_set_netfilter(new_param, i))
		CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

		vzctl2_free_env_param(new_param);

		vzctl2_env_close(h_res);
		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))
		CHECK_RET(vzctl2_env_get_netfilter(vzctl2_get_env_param(h_res), &res))
		if (res != i) {
			printf("\t(err) %d/%d\n",
					i, res);
			TEST_ERR("vzctl2_env_get_netfilter after save")
		}
	}

	vzctl2_env_close(h_res);
}

void test_config_autocompact(vzctl_env_handle_ptr h)
{
	int err;
	vzctl_env_handle_ptr h_res = NULL;
	vzctl_env_param_ptr new_param;
	int res, i;

	TEST()
	for (i = 0; i <= 1; i++) {
		CHECK_PTR(new_param, vzctl2_alloc_env_param())

		printf("(info) set autocompact: %d\n", i);
		CHECK_RET(vzctl2_env_set_autocompact(new_param, i))
		CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))

		vzctl2_free_env_param(new_param);

		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))
		CHECK_RET(vzctl2_env_get_autocompact(vzctl2_get_env_param(h_res), &res))
		if (res != i) {
			printf("\t(err) %d/%d\n", i, res);
			TEST_ERR("vzctl2_env_get_autocompact after save")
		}
		vzctl2_env_close(h_res);
	}
}

void test_config_bootorder(vzctl_env_handle_ptr h)
{
	int err;
	vzctl_env_handle_ptr h_res = NULL;
	vzctl_env_param_ptr new_param;
	int i;
	unsigned long res;

	TEST()
	for (i = 3; i >= 0; i--) {
		CHECK_PTR(new_param, vzctl2_alloc_env_param())

		printf("(info) set bootorder: %d\n", i);
		CHECK_RET(vzctl2_env_set_bootorder(new_param, i))
		CHECK_RET(vzctl2_apply_param(h, new_param, VZCTL_SAVE))
		vzctl2_free_env_param(new_param);

		CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))
		CHECK_RET(vzctl2_env_get_bootorder(vzctl2_get_env_param(h_res), &res))
		if (res != i) {
			printf("\t(err) %d/%lu\n", i, res);
			TEST_ERR("vzctl2_env_get_bootorder after save")
		}
		vzctl2_env_close(h_res);
	}
}

void test_config_del_param(vzctl_env_handle_ptr h)
{
	int err;
	const char *data = NULL;
	struct vzctl_env_handle *h_res;
	struct vzctl_env_param *env;
	int ids[] = {VZCTL_PARAM_KMEMSIZE};
	const char *values[] = {"1022435"};
	const char *names[] = {"KMEMSIZE"};
	int i;

	TEST()
	CHECK_PTR(env, vzctl2_alloc_env_param())
	for (i = 0; i < sizeof(ids)/sizeof(ids[0]); i++)
		vzctl2_add_env_param_by_id(env, ids[i], values[i]);

	vzctl2_apply_param(h, env, VZCTL_SAVE);
	vzctl2_free_env_param(env);

	CHECK_PTR(env, vzctl2_alloc_env_param())
	for (i = 0; i < sizeof(ids)/sizeof(ids[0]); i++) {
		printf ("(Info) delete %s\n", names[i]);
		vzctl2_del_param_by_id(h, ids[i]);
	}
	vzctl2_apply_param(h, env, VZCTL_SAVE);
	vzctl2_free_env_param(env);

	CHECK_PTR(h_res, vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err))

	for(i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		CHECK_RET(vzctl2_env_get_param(h_res, names[i], &data))
		if (data != NULL) {
			printf("env_get_param %s\n", names[i]);
			TEST_ERR("vzctl2_env_get_param")
		}
	}
	vzctl2_env_close(h_res);
}

void test_config()
{
	int err;
	vzctl_env_handle_ptr h;

	h = vzctl2_env_open(ctid, VZCTL_CONF_SKIP_NON_EXISTS, &err);
	if (h == NULL)
		TEST_ERR("vzctl2_env_open2")

#if 0
	test_config_DISK(h);
	test_config_CAPABILITY(h);
	test_config_UPTIME(h);
#endif

	test_open();
	test_config_CPUUNITS(h);
	test_config_CPUMASK(h);
	test_config_CPULIMIT(h);
	test_config_UB(h);
	test_config_NODEMASK(h);
	test_config_IO(h);
	test_config_IP(h);
	test_config_RATE(h);
	test_config_TYPE();
	test_config_VETH(h);
	test_config_MISC(h);
	test_config_ramsize(h);
	test_config_memguarantee(h);
	test_config_layout(h);
	test_config_APPLY_IPONLY(h);
	test_config_FEATURES(h);
	test_config_netfilter(h);
	test_config_NAME(h);
	test_config_high_availability(h);
	test_config_autocompact(h);
	test_config_bootorder(h);
	test_config_del_param(h);
	test_config_sample();

	vzctl2_env_close(h);
}
