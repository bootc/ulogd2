/*
 * ifi.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Holger Eitzenberger, 2006.
 */

#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/ifi.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>

#define IFI_STATIC_MAX			64

#define TAILQ_FOR_EACH(pos, head, link) \
        for (pos = (head).tqh_first; pos != NULL; pos = pos->link.tqe_next)

/* the first IFI_STATIC_MAX entries are kept in ifi_static[] for performance
   reasons, whereas all entries with an interface index larger than
   IFI_STATIX_MAX-1 are kept in the linked ifi_list. */
static TAILQ_HEAD(ifi_lh, ifi) ifi_list;
static struct ifi ifi_static[IFI_STATIC_MAX];

static unsigned nl_seq;			/* last seq# */


static struct ifi *
ifi_alloc(void)
{
	struct ifi *ifi;

	if ((ifi = calloc(1, sizeof(struct ifi))) == NULL)
		return NULL;

	return ifi;
}


struct ifi *
ifi_find_by_idx(unsigned idx)
{
	struct ifi *ifi;

	if (idx < IFI_STATIC_MAX)
		ifi = &ifi_static[idx];
	else {
		TAILQ_FOR_EACH(ifi, ifi_list, link) {
			if (ifi->idx == idx)
				break;
		}

		if (ifi == NULL)
			return NULL;
	}

	return ifi->used ? ifi : NULL;
}


static struct ifi *
ifi_find_or_add(unsigned idx)
{
	struct ifi *ifi = ifi_find_by_idx(idx);
	
	if (ifi != NULL)
		return ifi;

	/* add */
	if (idx < IFI_STATIC_MAX)
		ifi = &ifi_static[idx];
	else
		ifi = ifi_alloc();
		
	ifi->idx = idx;
	ifi->used = 1;

	TAILQ_INSERT_TAIL(&ifi_list, ifi, link);
	
	return ifi;
}


static bool
ifi_del(unsigned idx)
{
	struct ifi *ifi;
	
	if (idx < IFI_STATIC_MAX) {
		ifi = &ifi_static[idx];

		if (ifi->used) {
			ifi->used = 0;

			return true;
		}
	} else {
		TAILQ_FOR_EACH(ifi, ifi_list, link) {
			if (ifi->idx == idx) {
				TAILQ_REMOVE(&ifi_list, ifi, link);
				free(ifi);
				
				return true;
			}
		}
	}

	return false;
}


static void dump_bytes(const char *, unsigned char *, size_t) unused;

static void
dump_bytes(const char *prefix, unsigned char *data, size_t len)
{
	int i;
	static unsigned char buf[1024];
	char *pch = buf;

	if (prefix) 
		pch += sprintf(pch, "%s: ", prefix);

	for (i = 0; i < len; i++)
		pch += sprintf(pch, "0x%.2x ", data[i]);

	fprintf(stdout, "%s\n", buf);
}


static void dump_nlmsg(FILE *, struct nlmsghdr *) unused;

static void
dump_nlmsg(FILE *fp, struct nlmsghdr *nlh)
{
	fprintf(fp, "rtmsg: len=%04x type=%08x flags=%08x seq=%08x\n",
			nlh->nlmsg_len,	nlh->nlmsg_type, nlh->nlmsg_flags,
			nlh->nlmsg_seq);
}


static ssize_t sprint_lladdr(char *, size_t, const unsigned char *) unused;

static ssize_t
sprint_lladdr(char *buf, size_t len, const unsigned char *addr)
{
	char delim = '\0', *pch = buf;
	int i;

	for (i = 0; i < 6; i++) {
		pch += sprintf(pch, "%02x", addr[i]);

		delim = ':';

		if (i + 1 < 6)
			*pch++ = delim;
	}

	return pch - buf;
}

static int
rtnl_parse_attrs(struct rtattr *attr, size_t attr_len,
				 struct rtattr **rta, size_t rta_len)
{
	memset(rta, 0, rta_len * sizeof(struct rtattr *));

	while (RTA_OK(attr, attr_len)) {
		if (attr->rta_type < rta_len)
			rta[attr->rta_type] = attr;

		attr = RTA_NEXT(attr, attr_len);
	}

	return 0;
}


static int
nl_send(int fd, struct nlmsghdr *nlh)
{
	struct sockaddr_nl sa;

	memset(&sa, 0, sizeof(sa));

	sa.nl_family = AF_NETLINK;

	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_seq = ++nl_seq;

	return sendto(fd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&sa,
				  sizeof(sa));
}


static int
nl_dump_request(int fd, int type)
{
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg gen;
	} req = {
		.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
		.gen.rtgen_family = AF_UNSPEC,
	};

	req.nlh.nlmsg_type = type;
	req.nlh.nlmsg_len = sizeof(req);

	return nl_send(fd, &req.nlh);
}


static int
nl_listen(int fd, char *buf, size_t len)
{
	return read(fd, buf, len);
}


static int
rtnl_handle_link(struct nlmsghdr *nlh)
{
	struct ifinfomsg *m = NLMSG_DATA(nlh);
	struct rtattr *ifla[IFLA_MAX];
	struct ifi *ifi;
	size_t len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));

	rtnl_parse_attrs(IFLA_RTA(m), len, ifla, IFLA_MAX);

	switch (nlh->nlmsg_type) {
	case RTM_NEWLINK:
		if (m->ifi_flags & IFF_UP) {
			if ((ifi = ifi_find_or_add(m->ifi_index)) == NULL)
				return -1;
			
			ifi->flags = m->ifi_flags;
			
			if (ifla[IFLA_ADDRESS])
				memcpy(ifi->lladdr, RTA_DATA(ifla[IFLA_ADDRESS]), 6);
			
			if (ifla[IFLA_IFNAME])
				strcpy(ifi->name, RTA_DATA(ifla[IFLA_IFNAME]));
		} else
			ifi_del(m->ifi_index);
		break;

	case RTM_DELLINK:
		break;

	default:
		break;
	}

	return 0;
}


static int
rtnl_handle_msg(struct nlmsghdr *nlh, size_t len)
{
	if (nlh == NULL)
		return -1;

	while (NLMSG_OK(nlh, len)) {
		if (nlh->nlmsg_type & NLMSG_DONE)
			return 0;

#if 0
		dump_nlmsg(stdout, nlh);
#endif /* 0 */

		switch (nlh->nlmsg_type) {
		case RTM_NEWLINK:
		case RTM_DELLINK:
			rtnl_handle_link(nlh);
			break;

		case NLMSG_ERROR:
			break;

		default:
			break;
		}

		nlh = NLMSG_NEXT(nlh, len);
	}
	

	return 0;
}


static int
rtnl_read_cb(int fd, unsigned what, void *data)
{
	static char buf[4096];

	for (;;) {
		int nbytes;

		if ((nbytes = nl_listen(fd, buf, sizeof(buf))) < 0) {
			if (errno == EWOULDBLOCK)
				return 0;

			ulogd_log(ULOGD_ERROR, "nl_listen: %s\n", strerror(errno));

			return -1;
		}

		rtnl_handle_msg((struct nlmsghdr *)buf, nbytes);
	}
	
	return 0;
}


static struct ulogd_fd nl_fd = {
	.fd = -1,
	.cb = rtnl_read_cb,
	.when = ULOGD_FD_READ,
};


int
ifi_init(void)
{
	struct sockaddr_nl sa = {
		.nl_family = AF_NETLINK,
		.nl_groups = RTNLGRP_LINK,
	};

	sa.nl_pid = getpid();

	if ((nl_fd.fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) {
		ulogd_log(ULOGD_ERROR, "ifi: socket: %s\n", strerror(errno));
		return -1;
	}

	if (bind(nl_fd.fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		ulogd_log(ULOGD_ERROR, "ifi: bind: %s\n", strerror(errno));
		return -1;
	}

	if (connect(nl_fd.fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		ulogd_log(ULOGD_ERROR, "ifi: connect: %s\n", strerror(errno));
		return -1;
	}

	TAILQ_INIT(&ifi_list);

	if (ulogd_register_fd(&nl_fd) < 0)
		return -1;

	nl_dump_request(nl_fd.fd, RTM_GETLINK);

	return 0;
}
