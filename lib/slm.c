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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <assert.h>

#include "slm.h"
#include "config.h"
#include "ub.h"
#include "env.h"
#include "util.h"
#include "vzerror.h"
#include "logger.h"

struct name2id_s {
	char *name;
	int id;
};

static struct name2id_s _slm_modes[] = {
	{"ubc", VZCTL_MODE_UBC},
	{"slm", VZCTL_MODE_SLM},
	{"all", VZCTL_MODE_ALL},
	{NULL, -1}
};

static int name2id(const struct name2id_s *data, const char *name)
{
	int i;

	for (i = 0; data[i].name != NULL; i++)
		if (!strcmp(data[i].name, name))
			return data[i].id;
	return -1;
}

static const char *id2name(const struct name2id_s *data, int id)
{
	int i;

	for (i = 0; data[i].name != NULL; i++)
		if (data[i].id == id)
			return data[i].name;
	return NULL;
}

void free_slm_param(struct vzctl_slm_param *slm)
{
	xfree(slm->memorylimit);
	free(slm);
}

int slm_mode2id(const char *name)
{
	return name2id(_slm_modes, name);
}

const char *slm_id2mode(int id)
{
	return id2name(_slm_modes, id);
}

struct vzctl_slm_param *alloc_slm_param()
{
	return calloc(1, sizeof(struct vzctl_slm_param));
}
