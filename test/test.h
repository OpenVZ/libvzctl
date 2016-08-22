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

#ifndef _TEST_H_
#define _TEST_H_

#include "vzctl.h"

#define TEST_VZERR(msg) \
do { \
	fprintf(stdout, "FAILED %s in %s at %d err: %s\n", msg, __func__, __LINE__, vzctl2_get_last_error()); \
	inc_failed(); \
	return; \
} while(0);

#define TEST_ERR(msg) \
do { \
	fprintf(stdout, "FAILED %s in %s at %d\n", msg, __func__, __LINE__); \
	inc_failed(); \
	return; \
} while(0);


#define ERR(msg) \
do { \
	fprintf(stdout, "FAILED %s in %s at %d\n", msg, __func__, __LINE__); \
} while(0);


#define CHECK_RET(func) \
do { \
	if (func) TEST_ERR(#func)   \
} while (0);

#define CHECK_VZRET(func) \
do { \
	if (func) TEST_VZERR(#func)   \
} while (0);


#define CHECK_PTR(res, func) \
do { \
	if ((res = (func)) == NULL) TEST_ERR(#func) \
} while (0);

#define TEST() \
do { \
	fprintf(stdout, "\n*[TEST] %s\n", __func__); \
	inc_test(); \
} while(0);


void test_vzctl();
void test_config();
void inc_failed();
void inc_test();
int cleanup(void);
int create(ctid_t ctid);

#endif
