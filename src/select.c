/* ulogd, Version $LastChangedRevision: 476 $
 *
 * $Id: ulogd.c 476 2004-07-23 03:19:35Z laforge $
 *
 * userspace logging daemon for the iptables ULOG target
 * of the linux 2.4 netfilter subsystem.
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <fcntl.h>
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/signal.h>
#include <ulogd/linuxlist.h>

static fd_set readset, writeset, exceptset;
static int maxfd = -1;
static LLIST_HEAD(ulogd_fds);


static int
set_nonblock(int fd)
{
	int flags;

	if ((flags = fcntl(fd, F_GETFL)) < 0)
		return -1;

	flags |= O_NONBLOCK;

	if ((flags = fcntl(fd, F_SETFL, flags)) < 0)
		return -1;

	return 0;
}

int
ulogd_register_fd(struct ulogd_fd *ufd)
{
	if (set_nonblock(ufd->fd) < 0)
		return -1;

	if (ufd->when & ULOGD_FD_READ)
		FD_SET(ufd->fd, &readset);
	
	if (ufd->when & ULOGD_FD_WRITE)
		FD_SET(ufd->fd, &writeset);
	
	if (ufd->when & ULOGD_FD_EXCEPT)
		FD_SET(ufd->fd, &exceptset);

	if (ufd->fd > maxfd)
		maxfd = ufd->fd;

	llist_add_tail(&ufd->list, &ulogd_fds);

	return 0;
}

void
ulogd_unregister_fd(struct ulogd_fd *ufd)
{
	if (ufd->when & ULOGD_FD_READ)
		FD_CLR(ufd->fd, &readset);
	
	if (ufd->when & ULOGD_FD_WRITE)
		FD_CLR(ufd->fd, &writeset);
	
	if (ufd->when & ULOGD_FD_EXCEPT)
		FD_CLR(ufd->fd, &exceptset);

	llist_del(&ufd->list);

	maxfd = -1;
	llist_for_each_entry(ufd, &ulogd_fds, list) {
		assert(ufd->fd >= 0);

		if (ufd->fd > maxfd)
			maxfd = ufd->fd;
	}
}

/* ulogd_dispatch() - dispatch events */
int
ulogd_dispatch(void)
{
	fd_set rds_tmp, wrs_tmp, exs_tmp;
	sigset_t curr_ss;

	ulogd_get_sigset(&curr_ss);

	pthread_sigmask(SIG_UNBLOCK, &curr_ss, NULL);

	for (;;) {
		struct ulogd_fd *ufd;
		int n;

	again:
		rds_tmp = readset;
		wrs_tmp = writeset;
		exs_tmp = exceptset;

		n = select(maxfd+1, &rds_tmp, &wrs_tmp, &exs_tmp, NULL);
		if (n < 0) {
			if (errno == EINTR)
				goto again;

			ulogd_log(ULOGD_FATAL, "select: %m\n");

			break;
		}

		if (n > 0) {
			/* call registered callback functions */
			llist_for_each_entry(ufd, &ulogd_fds, list) {
				int flags = 0;

				if (FD_ISSET(ufd->fd, &rds_tmp))
					flags |= ULOGD_FD_READ;

				if (FD_ISSET(ufd->fd, &wrs_tmp))
					flags |= ULOGD_FD_WRITE;

				if (FD_ISSET(ufd->fd, &exs_tmp))
					flags |= ULOGD_FD_EXCEPT;

				if (flags)
					ufd->cb(ufd->fd, flags, ufd->data);
			}
		}
	}

	return 0;
}
