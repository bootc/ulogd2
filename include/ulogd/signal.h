/*
 * signal.h
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
 *
 * Holger Eitzenberger, 2007.
 */
#ifndef SIGNAL_H
#define SIGNAL_H

#include <signal.h>
#include <ulogd/linuxlist.h>


/* signal flags */
#define ULOGD_SIGF_SYNC		0x00000001 /* signal is synchronous */


struct ulogd_signal {
	struct llist_head link;
	int signo;
	unsigned flags;
	void (* handler)(int);
};


struct ulogd_signal *ulogd_register_signal(int, void (*)(int), unsigned);
int ulogd_unregister_signal(struct ulogd_signal *);
int ulogd_sigaddset(int);
int ulogd_get_sigset(sigset_t *);
int ulogd_deliver_signal(int signo);
int ulogd_signal_init(void);

#endif /* SIGNAL_H */
