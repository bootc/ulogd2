/*
 * common.c
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
 * Holger Eitzenberger <holger@eitzenberger.org>, 2007.
 */
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <sys/types.h>
#include <sys/socket.h>


int
set_sockbuf_len(int fd, int rcv_len, int snd_len)
{
	int ret;

	pr_debug("%s: fd=%d rcv-len=%d snd-len\n", __func__, fd, rcv_len,
			 snd_len);

	if (snd_len > 0) {
		ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &snd_len,
						 sizeof(snd_len));
		if (ret < 0) {
			ulogd_log(ULOGD_ERROR, "setsockopt: SO_SNDBUF: %m\n");
			return -1;
		}
	}

	if (rcv_len > 0) {
		ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv_len,
						 sizeof(rcv_len));
		if (ret < 0) {
			ulogd_log(ULOGD_ERROR, "setsockopt: SO_RCVBUF: %m\n");
			return -1;
		}
	}

	return 0;
}
