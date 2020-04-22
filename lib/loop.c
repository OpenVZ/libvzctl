/*
 *  copyright (c) 2020 virtuozzo international gmbh. all rights reserved.
 *
 *  this program is free software; you can redistribute it and/or modify
 *  it under the terms of the gnu general public license as published by
 *  the free software foundation; either version 2 of the license, or
 *  (at your option) any later version.
 *
 *  this program is distributed in the hope that it will be useful,
 *  but without any warranty; without even the implied warranty of
 *  merchantability or fitness for a particular purpose.  see the
 *  gnu general public license for more details.
 *
 *  you should have received a copy of the gnu general public license
 *  along with this program; if not, write to the free software
 *  foundation, inc., 59 temple place, suite 330, boston, ma  02111-1307  usa
 */

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/loop.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "logger.h"
#include "vzerror.h"

#ifndef LOOP_SET_DIRECT_IO
#define LOOP_SET_DIRECT_IO	0x4C08
#endif

int loop_release(const char *ldev)
{
	int fd;

	logger(0, 0, "Release %s", ldev);
	fd = open(ldev, O_RDWR|O_CLOEXEC);
	if (fd == -1)
		return vzctl_err(-1, errno, "Can not open %s", ldev);

	if (ioctl(fd, LOOP_CLR_FD)) {
		vzctl_err(-1, errno, "ioctl(LOOP_CLR_FD) %s", ldev);
		close(fd);
		return -1;
	}
	close(fd);

	return 0;
}

static int get_free_loop_minor(void)
{
	int fd, minor;

	fd = open("/dev/loop-control", O_RDWR|O_CLOEXEC);
	if (fd == -1) {
		return vzctl_err(-1, errno, "Can not open /dev/loop-control");
	}
	minor = ioctl(fd, LOOP_CTL_GET_FREE);
	close(fd);

	return minor;
}

char *get_loop_name(int minor, int full, char *buf, int len)
{
	snprintf(buf, len, "%sloop%d", full ? "/dev/" : "", minor);
	return buf;
}

int loop_create(const char *delta, char *ldev, int size)
{
	struct loop_info64 info = {};
	int lfd, fd, minor;

	minor = get_free_loop_minor();
	if (minor == -1)
		return vzctl_err(-1, 0, "Can not get free loop device");

	get_loop_name(minor, 1, ldev, size);
	logger(0, 0, "Create %s %s", ldev, delta);
	lfd = open(ldev, O_RDWR|O_CLOEXEC);
	if (lfd == -1)
		return vzctl_err(-1, errno, "Can not open %s", ldev);

	fd = open(delta, O_RDWR|O_CLOEXEC);
	if (fd == -1) {
		vzctl_err(-1, errno, "Can not open %s", ldev);
		goto err;
	}
	if (ioctl(lfd, LOOP_SET_FD, fd)) {
		vzctl_err(-1, errno, "ioctl(LOOP_SET_FD) %s", ldev);
		close(fd);
		goto err;
	}
	close(fd);

	if (ioctl(lfd, LOOP_GET_STATUS64, &info)) {
		vzctl_err(-1, errno, "ioctl(LOOP_GET_STATUS64) %s", ldev);
		goto err1;
	}

	info.lo_flags |= LO_FLAGS_AUTOCLEAR;
	if (ioctl(lfd, LOOP_SET_STATUS64, &info)) {
		vzctl_err(-1, errno, "ioctl(LOOP_SET_STATUS64) %s", ldev);
		goto err1;	
	}

	return lfd;

err1:
	ioctl(lfd, LOOP_CLR_FD);
err:
	close(lfd);
	return -1;
}
