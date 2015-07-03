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
#include <unistd.h>
#include <sys/param.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define BITS_PER_LONG		(sizeof(unsigned long) * 8)
#define DIV_ROUND_UP(n,d)	(((n) + (d) - 1) / (d))
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP((nr), BITS_PER_LONG)
#define BIT_MASK(nr)		(1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)

int test_bit(int nr, const unsigned long *map)
{
	return (map[BIT_WORD(nr)] & BIT_MASK(nr)) != 0;
}

void bitmap_set_bit(int nr, unsigned long *map)
{
	map[BIT_WORD(nr)] |= BIT_MASK(nr);
}

void bitmap_zero(unsigned long *map, int size)
{
	memset(map, 0, size);
}

int bitmap_empty(const unsigned long *map, int size)
{
	int i, len = size / sizeof(unsigned long);

	for (i = 0; i < len; i++)
		if (map[i])
			return 0;
	return 1;
}

int bitmap_andnot(unsigned long *dst, const unsigned long *map1,
		const unsigned long *map2, int size)
{
	int i, len = size / sizeof(unsigned long);
	unsigned long result = 0;

	for (i = 0; i < len; i++)
		result |= (dst[i] = map1[i] & ~map2[i]);

	return result != 0;
}

int bitmap_or(unsigned long *dst, const unsigned long *map1,
		const unsigned long *map2, int size)
{
	int i, len = size / sizeof(unsigned long);
	unsigned long result = 0;

	for (i = 0; i < len; i++)
		result |= (dst[i] = map1[i] | map2[i]);

	return result != 0;
}

int bitmap_and(unsigned long *dst, const unsigned long *map1,
		const unsigned long *map2, int size)
{
	int i, len = size / sizeof(unsigned long);
	unsigned long result = 0;

	for (i = 0; i < len; i++)
		result |= (dst[i] = map1[i] & map2[i]);

	return result != 0;
}

static int bitmap_find_first_bit(const unsigned long *map, int nmaskbits)
{
	int i, n;
	int nmasklongs = BITS_TO_LONGS(nmaskbits);

	for (i = 0; i < nmasklongs; i++) {
		if (map[i] != 0)
			break;
	}
	if (i == nmasklongs)
		return nmaskbits;
	i *= BITS_PER_LONG;
	n = i + BITS_PER_LONG;
	n = MIN(n, nmaskbits);
	do {
		if (test_bit(i, map))
			break;
	} while (++i < n);
	return i;
}

static int bitmap_find_bit(const unsigned long *map, unsigned nmaskbits, unsigned offset)
{
	unsigned n;

	if (offset % BITS_PER_LONG != 0) {
		n = (BIT_WORD(offset) + 1) * BITS_PER_LONG;
		n = MIN(n, nmaskbits);
		while (offset < n) {
			if (test_bit(offset, map))
				return offset;
			offset++;
		}
	}
	if (offset >= nmaskbits)
		return nmaskbits;

	return offset + bitmap_find_first_bit(map + BIT_WORD(offset),
			nmaskbits - offset);;
}

static int bitmap_find_first_zero_bit(const unsigned long *map, unsigned nmaskbits)
{
	unsigned i, n;
	unsigned nmasklongs = BITS_TO_LONGS(nmaskbits);

	for (i = 0; i < nmasklongs; i++) {
		if (~map[i] != 0)
			break;
	}
	if (i == nmasklongs)
		return nmaskbits;
	i *= BITS_PER_LONG;
	n = i + BITS_PER_LONG;
	n = MIN(n, nmaskbits);
	do {
		if (!test_bit(i, map))
			break;
	} while (++i < n);
	return i;
}

static int bitmap_find_zero_bit(const unsigned long *map, unsigned nmaskbits, unsigned offset)
{
        unsigned n;

        if (offset % BITS_PER_LONG != 0) {
                n = (BIT_WORD(offset) + 1) * BITS_PER_LONG;
                n = MIN(n, nmaskbits);
                while (offset < n) {
                        if (!test_bit(offset, map))
                                return offset;
                        offset++;
                }
        }
        if (offset >= nmaskbits)
                return nmaskbits;
        return offset + bitmap_find_first_zero_bit(map + BIT_WORD(offset),
                                            nmaskbits - offset);
}

int bitmap_all_bit_set(const unsigned long *map, int size)
{
	int nmaskbits = size * 8;

	return bitmap_find_first_zero_bit(map, nmaskbits) == nmaskbits;
}

int print_range(char *buf, unsigned int buflen, int a, int b)
{
	if (a == b)
		return snprintf(buf, buflen, "%d", a);
	return snprintf(buf, buflen, "%d-%d", a, b);
}

int bitmap_snprintf(char *buf, unsigned int buflen,
		const unsigned long *map, int size)
{
	int a, b;
	unsigned int len = 0;
	int nmaskbits = size * 8;

	buf[0] = '\0';
	a = bitmap_find_bit(map, nmaskbits, 0);
	while (a < nmaskbits) {
		b = bitmap_find_zero_bit(map, nmaskbits, a + 1) - 1;
		if (len > 0)
			len += snprintf(buf + len,
					buflen > len ? buflen - len : 0, ",");
		len += print_range(buf + len,
				buflen > len ? buflen - len : 0, a, b);
		a = bitmap_find_bit(map, nmaskbits, b + 1);
	}
	return len;
}

static int parse_range(const char *str, unsigned *a, unsigned *b,
		char **endptr)
{
	*a = *b = strtoul(str, endptr, 10);
	if (errno == ERANGE)
                return -1;
	if (**endptr == '-') {
		str = *endptr + 1;
		if (!isdigit(*str))
			return -1;
		*b = strtol(str, endptr, 10);
		if (*a > *b)
			return -1;
	}
	return 0;
}

int bitmap_parse(const char *str, unsigned long *maskp, int size)
{
	unsigned a, b;
	char *endptr;
	unsigned nmaskbits = size * 8;

	if (!strcmp(str, "all") || !strcmp(str, "")) {
		memset(maskp, 0xff, size);
		return 0;
	}

	bitmap_zero(maskp, size);
	do {
		if (parse_range(str, &a, &b, &endptr) != 0) {
			errno = EINVAL;
			return -1;
		}
		if (b >= nmaskbits) {
			errno = ERANGE;
			return -1;
		}
		for (; a <= b; a++)
			bitmap_set_bit(a, maskp);
		if (*endptr == ',')
			endptr++;
		str = endptr;
	} while (*str != '\0');
	return 0;
}
