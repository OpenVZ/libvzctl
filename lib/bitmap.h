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

#ifndef _BITMASK_H_
#define _BITMASK_H_

int test_bit(int nr, const unsigned long *map);
void bitmap_set_bit(int nr, unsigned long *map);
int bitmap_and(unsigned long *dst, const unsigned long *map1,
		const unsigned long *map2, int size);
int bitmap_all_bit_set(const unsigned long *map, int size);
int bitmap_snprintf(char *buf, unsigned int buflen,
		const unsigned long *map, int size);
#endif
