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
#include "config.h"
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/ifi.h>
#include <unistd.h>
#include <sys/types.h>

#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/route/link.h>
#include <net/if.h>
#include <netinet/ether.h>


static struct ulogd_fd rtnl_ufd;
static struct nl_handle *nlh;
static struct nl_cache *cache;
static struct nl_cache_mngr *mngr;


static int
rtnl_ufd_cb(int fd, unsigned what, void *arg)
{
	switch (what) {
	case ULOGD_FD_READ:
		nl_cache_mngr_data_ready(mngr);
		break;

	default:
		break;
	}

	return 0;
}

static void
rtnl_change_cb(struct nl_cache *cache, struct nl_object *obj, int action)
{
	struct nl_dump_params dp = {
		.dp_type = NL_DUMP_BRIEF,
		.dp_fd = logfile,
	};

	switch (action) {
	case NL_ACT_NEW:
	case NL_ACT_DEL:
		nl_object_dump(obj, &dp);
		break;

	case NL_ACT_CHANGE:
		break;

	default:
		break;
	}
}

char *
ifi_index2name(int ifi, char *dst, size_t len)
{
	return rtnl_link_i2name(cache, ifi, dst, len);
}

/**
 * Return hardware address of interface
 *
 * @arg ifi		interface index
 * @arg dst		target buffer of at least size %ETH_ALEN
 *
 * @return pointer to buffer or %NULL
 */
uint8_t *
ifi_get_hwaddr(int ifi, uint8_t *dst)
{
	static uint8_t zero_hwaddr[ETH_ALEN];
	struct rtnl_link *link = rtnl_link_get(cache, ifi);
	struct nl_addr *addr;

	if (!link)
		return NULL;

	if ((addr = rtnl_link_get_addr(link)) == NULL)
		goto err_put;

	if (nl_addr_iszero(addr))
		memset(dst, 0, ETH_ALEN);
	else
		memcpy(dst, nl_addr_get_binary_addr(addr), ETH_ALEN);

	rtnl_link_put(link);

	return dst;

err_put:
	rtnl_link_put(link);
	return NULL;
}

/**
 * Return hardware address as string
 *
 * @arg ifi		interface index
 * @arg dst		target buff
 * @arg len		buffer of appropriate size
 *
 * @return 0 on success, -1 on error
 */
char *
ifi_hwaddr2str(int ifi, char *dst, size_t len)
{
	struct rtnl_link *link = rtnl_link_get(cache, ifi);
	struct nl_addr *addr;

	if (!link)
		return NULL;

	if ((addr = rtnl_link_get_addr(link)) == NULL)
		goto err_put;

	if (!nl_addr2str(addr, dst, len))
		goto err_put;

	rtnl_link_put(link);

	return dst;

err_put:
	rtnl_link_put(link);
	return NULL;
}

int
ifi_init(void)
{
	if ((nlh = nl_handle_alloc()) == NULL) {
		ulogd_log(ULOGD_ERROR, "ifi: unable to allocate netlink handle\n");
		return -1;
	}

	nl_disable_sequence_check(nlh);

	mngr = nl_cache_mngr_alloc(nlh, NETLINK_ROUTE, NL_AUTO_PROVIDE);
	if (!mngr) {
		ulogd_log(ULOGD_ERROR, "ifi: unable to allocate cache manager\n");
		return -1;
	}

	cache = nl_cache_mngr_add(mngr, "route/link", rtnl_change_cb);
	if (!cache) {
		ulogd_log(ULOGD_ERROR, "ifi: unable to add cache to manager\n");
		return -1;
	}		

	ulogd_init_fd(&rtnl_ufd, nl_cache_mngr_get_fd(mngr),
				  ULOGD_FD_READ, rtnl_ufd_cb, mngr);

	if (ulogd_register_fd(&rtnl_ufd) < 0)
		return -1;

	ulogd_log(ULOGD_DEBUG, "interface notifier initialized\n");

	return 0;
}
