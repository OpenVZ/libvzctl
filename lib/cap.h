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

#ifndef _CAP_H_
#define _CAP_H_

#include <linux/types.h>

typedef __u32 cap_t;

#ifndef CAP_TO_MASK
#define CAP_TO_MASK(x) (1 << (x) & 31)
#endif
#undef cap_raise
#define cap_raise(c, flag) (c |= CAP_TO_MASK(flag))
#undef cap_lower
#define cap_lower(c, flag) (c &= ~CAP_TO_MASK(flag))

struct vzctl_features_param;

/* Data structure for capability mask see /usr/include/linux/capability.h
 */
struct vzctl_cap_param {
	unsigned long on;
	unsigned long off;
};

/** Add capability name to capability mask.
 *
 * @param name		capability name.
 * @param mask		capability mask.
 * @return		0 on success.
 */
int get_cap_mask(char *name, unsigned long *mask);

/** Apply capability mask to VE.
 *
 * @param cap		capability mask.
 * @return		0 on success.
 */
int env_set_cap(struct vzctl_cap_param *cap);

/** Merge capabilities and return in string format.
 *
 * @param new		new capability mask.
 * @param old		old capamility mask.
 * @param buf		merged capabilities in string format.
 * @return
 */
void build_cap_str(struct vzctl_cap_param *dst, char *buf, int len);

int parse_cap(struct vzctl_cap_param *cap, const char *str, int replace);

unsigned long vzctl2_get_default_capmask(void);

#endif
