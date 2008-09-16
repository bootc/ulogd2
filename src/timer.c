/* ulogd, Version $LastChangedRevision: 476 $
 *
 * $Id: ulogd.c 476 2004-07-23 03:19:35Z laforge $
 *
 * userspace logging daemon for the netfilter subsystem
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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>

#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/linuxlist.h>

static LLIST_HEAD(ulogd_timers);
static int expired;
static sigset_t ss_alrm;
time_t t_now;


int
ulogd_register_timer(struct ulogd_timer *timer)
{
	if (timer->flags & TIMER_F_PERIODIC) {
		timer->expires = t_now + timer->ival;
	} else {
		if (timer->expires == 0) {
			errno = EINVAL;
			return -1;
		}
	}

	llist_add_tail(&timer->list, &ulogd_timers);

	return 0;
}


void
ulogd_timer_schedule(void)
{
	t_now = time(NULL);

	expired++;
}


int
ulogd_timer_handle(void)
{
	struct ulogd_timer *t;

	if (expired == 0)
		return 0;

	/* disable SIGALRM for duration of this call */
	pthread_sigmask(SIG_BLOCK, &ss_alrm, NULL);
	
	llist_for_each_entry(t, &ulogd_timers, list) {
		if (t->expires <= t_now) {
			(t->cb)(t);
			
			if (t->flags & TIMER_F_PERIODIC)
				t->expires = t_now + t->ival;
			else
				llist_del(&t->list);
		}
	}

	expired = 0;

	/* enable again */
	pthread_sigmask(SIG_UNBLOCK, &ss_alrm, NULL);

	return 0;
}


void
ulogd_unregister_timer(struct ulogd_timer *timer)
{
	llist_del(&timer->list);
}


int
ulogd_timer_init(void)
{
	t_now = time(NULL);

	sigemptyset(&ss_alrm);
	sigaddset(&ss_alrm, SIGALRM);

	return 0;
}


/* start periodic timer */
int
ulogd_timer_run(void)
{
	struct itimerval itv = {	/* run timer every second */
		.it_interval = { .tv_sec = 1, },
		.it_value = { .tv_sec = 1, },
	};

	if (setitimer(ITIMER_REAL, &itv, NULL) < 0) {
		ulogd_log(ULOGD_ERROR, "setitimer: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}
