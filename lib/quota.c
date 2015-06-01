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
#include <string.h>
#include <assert.h>

#include "vzerror.h"
#include "util.h"
#include "env.h"
#include "logger.h"

int add_dq_param(struct vzctl_2UL_res **addr, struct vzctl_2UL_res *res)
{
	struct vzctl_2UL_res *new = NULL;

	if (*addr == NULL) {
		if ((new = xmalloc(sizeof(struct vzctl_2UL_res))) == NULL)
			return VZCTL_E_NOMEM;
		memcpy(new, res, sizeof(*new));
		*addr = new;
	} else {
		 memcpy(*addr, res, sizeof(*new));
	}
	return 0;
}

void free_dq_param(struct vzctl_dq_param *dq)
{
	if (dq == NULL)
		return;
	xfree(dq->diskspace);
	xfree(dq->diskinodes);
	xfree(dq->exptime);
	xfree(dq->ugidlimit);
	free(dq);
}

char **fill_dq_args(char **arg, const struct vzctl_dq_param *dq)
{
	char buf[64];

	if (dq->diskspace != NULL) {
		*arg++ = strdup("-b");
		snprintf(buf, sizeof(buf), "%lu", dq->diskspace->b);
		*arg++ = strdup(buf);
		*arg++ = strdup("-B");
		snprintf(buf, sizeof(buf), "%lu", dq->diskspace->l);
		*arg++ = strdup(buf);
	}
	if (dq->diskinodes != NULL) {
		*arg++ = strdup("-i");
		snprintf(buf, sizeof(buf), "%lu", dq->diskinodes->b);
		*arg++ = strdup(buf);
		*arg++ = strdup("-I");
		snprintf(buf, sizeof(buf), "%lu", dq->diskinodes->l);
		*arg++ = strdup(buf);
	}
	if (dq->exptime != NULL) {
		*arg++ = strdup("-e");
		snprintf(buf, sizeof(buf), "%lu", dq->exptime[0]);
		*arg++ = strdup(buf);
		*arg++ = strdup("-n");
		snprintf(buf, sizeof(buf), "%lu", dq->exptime[0]);
		*arg++ = strdup(buf);
	}
	/* Set ugid limit */
	*arg++ = strdup("-s");
	if (dq->ugidlimit != NULL && *dq->ugidlimit) {
		*arg++ = strdup("1");
		*arg++ = strdup("-u");
		snprintf(buf, sizeof(buf), "%lu", *dq->ugidlimit);
		*arg++ = strdup(buf);
	} else {
		*arg++ = strdup("0");
	}
	*arg = NULL;
	return arg;
}


