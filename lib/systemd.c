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
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <dbus/dbus.h>
#include <limits.h>

#include "env.h"
#include "vzerror.h"
#include "logger.h"
#include "vztypes.h"

static DBusConnection *get_connection(DBusBusType type)
{
	DBusConnection *conn;
	DBusError error;

	dbus_error_init(&error);
	conn = dbus_bus_get(type, &error);
	if (dbus_error_is_set(&error)) {
		vzctl_err(-1, errno, "dbus error: %s\n", error.message);
		dbus_error_free(&error);
		return NULL;
	}

	return conn;
}

static DBusMessage *dbus_send_message(DBusConnection *conn, DBusMessage *msg)
{
	DBusMessage *reply;
	DBusError error;

	dbus_error_init(&error);
	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &error);
	if (dbus_error_is_set (&error)) {
		vzctl_err(-1, errno, "dbus error: %s\n", error.message);
		dbus_error_free(&error);
		return NULL;
	}

	dbus_connection_flush(conn);
	return reply;
}

static int set_property(DBusMessageIter *props, const char *key, int type,
		const void *value)
{
	const char type_str[] = { type, '\0' };
	DBusMessageIter s0, s1;

	if (!dbus_message_iter_open_container(props, DBUS_TYPE_STRUCT, NULL, &s0) ||
	    !dbus_message_iter_append_basic(&s0, DBUS_TYPE_STRING, &key) ||
	    !dbus_message_iter_open_container(&s0, DBUS_TYPE_VARIANT, type_str, &s1) ||
	    !dbus_message_iter_append_basic(&s1, type, value) ||
	    !dbus_message_iter_close_container(&s0, &s1) ||
	    !dbus_message_iter_close_container(props, &s0))
		return vzctl_err(-1, ENOMEM, "set_property");

	return 0;
}

static int set_pid(DBusMessageIter *props, pid_t pid)
{
	const dbus_int32_t p = pid;
	const char *key = "PIDs";
	DBusMessageIter s0, s1, s2;

	if (!dbus_message_iter_open_container(props, DBUS_TYPE_STRUCT, NULL, &s0) ||
	    !dbus_message_iter_append_basic(&s0, DBUS_TYPE_STRING, &key) ||
	    !dbus_message_iter_open_container(&s0, DBUS_TYPE_VARIANT, "au", &s1) ||
	    !dbus_message_iter_open_container(&s1, DBUS_TYPE_ARRAY, "u", &s2) ||
	    !dbus_message_iter_append_basic(&s2, DBUS_TYPE_UINT32, &p) ||
	    !dbus_message_iter_close_container(&s1, &s2) ||
	    !dbus_message_iter_close_container(&s0, &s1) ||
	    !dbus_message_iter_close_container(props, &s0))
		return vzctl_err(-1, ENOMEM, "set_pid");

	return 0;
}

int systemd_start_ve_scope(struct vzctl_env_handle *h, pid_t pid)
{
	static const char *mode = "fail";
	static const char *slice = "-.slice";
	char unit_name[PATH_MAX], *name = unit_name;
	char desc[1024], *pdesc = desc;
	dbus_bool_t yes = false;
	DBusConnection *conn;
	DBusMessage *msg, *reply = NULL;
	DBusMessageIter iter, props; // aux;
	int ret = -1;

	logger(3, 0, "Start CT slice");
	snprintf(unit_name, sizeof(unit_name), SYSTEMD_CTID_SCOPE_FMT, EID(h));
	snprintf(desc, sizeof(desc), "Container %s", EID(h));

	msg = dbus_message_new_method_call("org.freedesktop.systemd1",
					   "/org/freedesktop/systemd1",
					   "org.freedesktop.systemd1.Manager",
					   "StartTransientUnit");
	if (msg == NULL) {
		vzctl_err(-1, errno, "Can't allocate new method call");
		goto err;
	}

	dbus_message_iter_init_append(msg, &iter);

	if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &name) ||
	    !dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &mode) ||
	    !dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(sv)", &props))
	{
		vzctl_err(-1, ENOMEM, "dbus_message");
		goto err;
	}

	if (set_property(&props, "Description", DBUS_TYPE_STRING, &pdesc) ||
	    set_property(&props, "Slice", DBUS_TYPE_STRING, &slice) ||
	    set_property(&props, "MemoryAccounting", DBUS_TYPE_BOOLEAN, &yes) ||
	    set_property(&props, "CPUAccounting", DBUS_TYPE_BOOLEAN, &yes) ||
	    set_property(&props, "BlockIOAccounting", DBUS_TYPE_BOOLEAN, &yes) ||
	    set_pid(&props, pid))
	{
		goto err;
	}

	dbus_message_iter_close_container(&iter, &props);

//	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(sa(sv))", &aux);
//	dbus_message_iter_close_container(&iter, &aux);

	conn = get_connection(DBUS_BUS_SYSTEM);
	if (conn == NULL)
		goto err;

	reply = dbus_send_message(conn, msg);
	if (reply == NULL) {
		vzctl_err(-1, errno, "Can't send message to host systemd");
		goto err;
	}
	ret = 0;

err:
	if (reply)
		dbus_message_unref(reply);

	dbus_message_unref(msg);

	return ret;
}
