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
#ifndef	__DIST_H__
#define	__DIST_H__

#define DIST_CONF_DEF		"default"
#define	DIST_FUNC		"functions"
#define	DIST_SCRIPTS		"scripts"

enum {
        TM_EZ,
        TM_ST,
};

struct vzctl_tmpl_param {
	char *ostmpl;
	char *templates;
	char *dist;
	char *osrelease;
};

/* Data structure for distribution specific action scripts.
 */
struct vzctl_dist_actions {
	char *add_ip;		/**< setup ip address. */
	char *del_ip;		/**< delete ip address. */
	char *set_hostname;	/**< setup hostname. */
	char *set_dns;		/**< setup dns rescords. */
	char *set_userpass;	/**< setup user password. */
	char *set_ugid_quota;	/**< setup 2level quota. */
	char *post_create;	/**< postcreate actions. */
	char *netif_add;
	char *netif_del;
	char *set_console;
};

struct vzctl_env_handle;

int read_dist_actions(struct vzctl_env_handle *h);
void free_dist_action(struct vzctl_dist_actions *dist_actions);
const char *get_dist_action_script(struct vzctl_dist_actions *dist_actions,
		const char *name);
#endif /* _DIST_H_ */
