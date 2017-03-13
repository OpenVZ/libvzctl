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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "logger.h"
#include "vzerror.h"

#define NLMSG_TAIL(nmsg) \
        ((struct rtattr *) (((char *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))


struct iplink_req {
	struct nlmsghdr         h;
	struct ifinfomsg        i;
	char                    buf[1024];
};

static int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
		int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen)
		return vzctl_err(-1, 0, "addattr_l: message exceeded bound of %d",
				maxlen);

	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);

	return 0;
}

static int ifup(const char *dev)
{
	struct ifreq ifr;
	int fd, ret = -1;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return vzctl_err(-1, errno, "Cannot create socket");

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr)) {
		vzctl_err(-1, 0, "Cannot get %s flags", dev);
		goto err;
	}

	if (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;

		logger(5, 0, "Bringing up %s", dev);
		if (ioctl(fd, SIOCSIFFLAGS, &ifr)) {
			vzctl_err(-1, 0, "Cannot bring up %s", dev);
			goto err;
		}
	}
	ret = 0;
err:
	close(fd);

	return ret;
}

int create_venet_link(void)
{
	int nl;
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct iplink_req req;
	struct rtattr *linkinfo;
	struct msghdr msg = {
		.msg_name    = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov     = &iov,
		.msg_iovlen  = 1,
	};

	if (access("/proc/sys/net/ipv4/conf/venet0", F_OK) == 0)
		return 0;

	nl = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);  
	if (nl < 0)
		return vzctl_err(-1, errno, "Cannot open socket");

	memset(&req, 0, sizeof(req));

	req.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.h.nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE;
	req.h.nlmsg_type = RTM_NEWLINK;
	req.h.nlmsg_seq = 0;
	req.i.ifi_family = AF_PACKET;

	linkinfo = NLMSG_TAIL(&req.h);
	addattr_l(&req.h, sizeof(req), IFLA_LINKINFO, NULL, 0);
	addattr_l(&req.h, sizeof(req), IFLA_INFO_KIND, "venet", 5);

	linkinfo->rta_len = (char *)NLMSG_TAIL(&req.h) - (char *)linkinfo;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	iov.iov_base    = &req;
	iov.iov_len     = req.h.nlmsg_len;

	if (sendmsg(nl, &msg, 0) < 0) {
		vzctl_err(-1, errno, "Can't send request message");
		close(nl);

		return -1;
	}

	close(nl);

	return 0;
}

int setup_venet(void)
{
	if (access("/sys/class/net/venet0", F_OK) == 0)
		return 0;

	logger(0, 0, "Create venet0 link");
	if (create_venet_link())
		return vzctl_err(VZCTL_E_SYSTEM, 0, "Cannot create venet link");

	if (ifup("venet0"))
		return VZCTL_E_SYSTEM;

	return 0;
}
