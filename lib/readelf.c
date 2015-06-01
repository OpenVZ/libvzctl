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

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>

#include "vztypes.h"

#define EI_NIDENT	16
#define ELFMAG		"\177ELF"
#define OLFMAG		"\177OLF"

#define ELFCLASSNONE	0
#define ELFCLASS32	1
#define ELFCLASS64	2


struct elf_hdr_s {
	uint8_t ident[EI_NIDENT];
	uint16_t type;
	uint16_t machine;
};

static inline int check_elf_magic(const uint8_t *buf)
{
	if (memcmp(buf, ELFMAG, 4) &&
	    memcmp(buf, OLFMAG, 4))
	{
		return -1;
	}
	return 0;
}

int get_arch_from_elf(const char *file)
{
	int fd, nbytes, class;
	struct stat st;
	struct elf_hdr_s elf_hdr;

	if (stat(file, &st))
		return -1;
	if (!S_ISREG(st.st_mode))
		return -1;
	fd = open(file, O_RDONLY);
	if (fd < 0)
		return -1;
	nbytes = read(fd, (void *) &elf_hdr, sizeof(elf_hdr));
	close(fd);
	if (nbytes < sizeof(elf_hdr))
		return -1;
	if (check_elf_magic(elf_hdr.ident))
		return -1;
	class = elf_hdr.ident[4];
	switch (class) {
	case ELFCLASS32:
		return elf_32;
	case ELFCLASS64:
		return elf_64;
	}
	return elf_none;
}
