/*
 *  Copyright (c) 1999-2017, Parallels International GmbH
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
 *
 */

#ifndef __CREATE_H__
#define __CREATE_H__

struct vzctl_create_param {
	char *ostemplate;
	char *config;
	char *ve_private;
	char *ve_root;
	char *hostname;
	int fs_layout;
};

#ifdef __cplusplus
extern "C" {
#endif

int vzctl_env_create(unsigned veid, struct vzctl_env_param *param, int flags);
char *get_distribution(const char *ostmpl);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _CREATE_H_ */
