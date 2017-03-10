/*
 * Copyright (c) 2015-2017, Parallels International GmbH
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
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "test.h"

static int _nfailed;
static int _ntest;
ctid_t ctid = {"0ef21de0-2f96-4bd4-ae9c-5e423cfb78dd"};

void inc_failed()
{
	_nfailed++;
}

void inc_test()
{
	_ntest++;
}

void usage()
{
	printf("test [vzctl|config]\n");
	exit(1);
}

int main(int argc, char **argv)
{
	int mode = 0x3;

	vzctl2_init_log("test");
	vzctl2_lib_init();
	//vzctl2_set_log_verbose(0x10000);

	vzctl2_lib_init();

	if (argc == 2) {
		if (!strcmp(argv[1], "vzctl"))
			mode = 0x1;
		else if (!strcmp(argv[1], "config"))
			mode = 0x2;
		else
			usage();
	}

	if (create(ctid))
		return -1;

	if (mode & 0x1)
		test_vzctl();
	if (mode & 0x2)
		test_config();

	vzctl2_lib_close();

	if (_nfailed)
		printf("FAILED:%d test:%d\n", _nfailed, _ntest);
	else
		printf("OK test:%d\n", _ntest);

	return (_nfailed != 0);
}
