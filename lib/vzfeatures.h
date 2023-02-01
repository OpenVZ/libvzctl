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
#ifndef _VZFEATURES_H_
#define _VZFEATURES_H_

struct vzctl_features_param {
	unsigned long ipt_mask;
	unsigned long long mask;
	unsigned long long known;
	unsigned long long tech;
};

#ifdef __cplusplus
extern "C" {
#endif

int parse_features(struct vzctl_features_param *features, const char *str);
void features_mask2str(struct vzctl_features_param *features, char *buf, int len);

int parse_technologies(unsigned long long *tech, const char *str);
const char *tech2str(unsigned long long mask, char *buf, int len);
unsigned long long tech2features(unsigned long long tech);

#ifdef __cplusplus
}
#endif
#endif //_VZFEATURES_H_

