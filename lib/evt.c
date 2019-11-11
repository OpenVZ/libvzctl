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

#include "vzctl.h"
#include "evt.h"

int vzctl2_register_evt(vzevt_handle_t **h)
{
#ifdef USE_VZEVENT
	return vzevt_register(h);
#else
	return 0;
#endif
}

void vzctl2_unregister_evt(vzevt_handle_t *h)
{

#ifdef USE_VZEVENT
	vzevt_unregister(h);
#endif
}

int vzctl2_get_evt_fd(vzevt_handle_t *h)
{
	return h->sock;
}

int vzctl2_get_state_evt(vzevt_handle_t *h, struct vzctl_state_evt *evt, int size)
{
#ifdef USE_VZEVENT
	vzevt_t *e;
	int ret;
	struct vzctl_state_evt state_evt;

	ret = vzevt_recv(h, &e);
	if (ret != 1)
		return -1;

	if (e->type != VZEVENT_VZCTL_EVENT_TYPE) {
		vzevt_free(e);
		return -1;
	}
	memcpy(&state_evt, e->buffer, sizeof(struct vzctl_state_evt));
	vzevt_free(e);

	if (state_evt.type != VZCTL_STATE_EVT)
		return -1;

	memcpy(evt, &state_evt, size);
#endif
	return 0;
}

int vzctl2_send_state_evt(const ctid_t ctid, int state)
{
#ifdef USE_VZEVENT
	int ret;
	struct vzctl_state_evt evt = {};

	if (vzctl2_get_flags() & VZCTL_FLAG_DONT_SEND_EVT)
		return 0;

	evt.type = VZCTL_STATE_EVT;
	memcpy(evt.ctid, ctid, sizeof(ctid_t));
	evt.state = state;

	ret = vzevt_send(NULL, VZEVENT_VZCTL_EVENT_TYPE,
			sizeof(struct vzctl_state_evt), &evt);
	if (ret)
		return ret;
#endif
	return 0;
}

int vzctl2_send_umount_evt(const ctid_t ctid, dev_t dev)
{
#ifdef USE_VZEVENT
	int ret;
	struct vzctl_state_evt evt = {};

	evt.type = VZCTL_STATE_EVT;
	memcpy(evt.ctid, ctid, sizeof(ctid_t));
	evt.state = VZCTL_ENV_UMOUNT;
	evt.dev = dev;

	ret = vzevt_send(NULL, VZEVENT_VZCTL_EVENT_TYPE,
			sizeof(struct vzctl_state_evt), &evt);
	if (ret)
		return ret;
#endif
	return 0;
}
