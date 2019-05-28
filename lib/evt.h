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

#ifndef _EVNT_H_
#define _EVNT_H_
#include <vz/vzevent.h>

enum {
	VZCTL_STATE_EVT = 1,
};

int vzctl2_register_evt(vzevt_handle_t **h);
void vzctl2_unregister_evt(vzevt_handle_t *h);
int vzctl2_get_state_evt(vzevt_handle_t *h, struct vzctl_state_evt *evt, int size);
int vzctl2_send_state_evt(const ctid_t ctid, int state);
int vzctl2_send_umount_evt(const ctid_t ctid, dev_t dev);
int vzctl2_get_evt_fd(vzevt_handle_t *h);


#endif
