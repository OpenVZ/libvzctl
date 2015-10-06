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

static void set_property(DBusMessageIter *props, const char *key, int type,
		const void *value)
{
	const char type_str[] = { type, '\0' };
	DBusMessageIter prop, var;

	dbus_message_iter_open_container(props, 'r', NULL, &prop);
	dbus_message_iter_append_basic(&prop, 's', &key);
	dbus_message_iter_open_container(&prop, 'v', type_str, &var);
	dbus_message_iter_append_basic(&var, type, value);
	dbus_message_iter_close_container(&prop, &var);
	dbus_message_iter_close_container(props, &prop);
}

static void set_pid(DBusMessageIter *props, pid_t pid)
{
	const dbus_int32_t pids[] = { pid };
	const dbus_int32_t *p = pids;
	const char *type_str = "au";
	const char *key = "PIDs";
	DBusMessageIter t, a, v;

	dbus_message_iter_open_container(props, DBUS_TYPE_STRUCT, NULL, &t);
	dbus_message_iter_append_basic(&t, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(&t, 'v', type_str, &v);
	dbus_message_iter_open_container(&v, 'a', "u", &a);
	dbus_message_iter_append_fixed_array(&a, 'u', &p, 1);
	dbus_message_iter_close_container(&v, &a);
	dbus_message_iter_close_container(&t, &v);

	dbus_message_iter_close_container(props, &t);
}

int systemd_start_ve_scope(struct vzctl_env_handle *h, pid_t pid)
{
	static const char *mode = "fail";
	char unit_name[PATH_MAX], *name = unit_name;
	char desc[1024], *pdesc = desc;
	dbus_bool_t yes = true;

	logger(3, 0, "Start CT slice");

	DBusConnection *conn;
	DBusMessage *msg, *reply;
	DBusMessageIter args, props, aux;

	snprintf(unit_name, sizeof(unit_name), SYSTEMD_CTID_SCOPE_FMT, EID(h));
	snprintf(desc, sizeof(desc), "Container %s", EID(h));

	msg = dbus_message_new_method_call("org.freedesktop.systemd1",
					   "/org/freedesktop/systemd1",
					   "org.freedesktop.systemd1.Manager",
					   "StartTransientUnit");
	if (!msg)
		return vzctl_err(-1, errno, "Can't allocate new method call");

	dbus_message_append_args(msg, 's', &name, 's', &mode, 0);

	dbus_message_iter_init_append(msg, &args);

	dbus_message_iter_open_container(&args, 'a', "(sv)", &props);
	set_property(&props, "Description", 's', &pdesc);

	set_property(&props, "MemoryAccounting", 'b', &yes);
	set_property(&props, "CPUAccounting", 'b', &yes);
	set_property(&props, "BlockIOAccounting", 'b', &yes);

	set_pid(&props, pid);
	dbus_message_iter_close_container(&args, &props);

	dbus_message_iter_open_container(&args, 'a', "(sa(sv))", &aux);
	dbus_message_iter_close_container(&args, &aux);

	conn = get_connection(DBUS_BUS_SYSTEM);
	if (conn == NULL)
		return vzctl_err(-1, 0, "Can't obtain system DBus");

	reply = dbus_send_message(conn, msg);
	dbus_message_unref(msg);
	if (reply == NULL)
		return vzctl_err(-1, errno, "Can't send message to host systemd");

	dbus_message_unref(reply);
	return 0;
}
