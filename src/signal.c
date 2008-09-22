/*
 * signal.c
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
 * Holger Eitzenberger, 2007.
 */
#include "config.h"
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/signal.h>
#include <unistd.h>

#define SIG_F_USED		0x00000001


static struct sig_state {
	struct llist_head head;
	struct llist_head async_head;
	unsigned flags;
	unsigned cnt;
} sig_state[NSIG];
static sigset_t currset;
static int sig_pipe[2] = { -1, -1 };
static struct ulogd_fd sig_pipe_fd;


static void
sig_handler(int signo)
{
	struct ulogd_signal *sig;
	sigset_t sigset;

	assert(sig_pipe[1] >= 0);

	pr_debug("%s: received signal '%d'\n", __func__, signo);

	sigemptyset(&sigset);
	sigaddset(&sigset, signo);

	pthread_sigmask(SIG_BLOCK, &sigset, NULL);

	llist_for_each_entry(sig, &sig_state[signo].async_head, link)
		sig->handler(signo);

	pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);

	if (!llist_empty(&sig_state[signo].head))
		write(sig_pipe[1], &signo, sizeof(signo));
}

struct ulogd_signal *
ulogd_register_signal(int signo, void (* sigh)(int), unsigned flags)
{
	struct ulogd_signal *sig;

	if (signo < 0 || signo > NSIG || sigh == NULL)
		return NULL;

	/* TODO check signo for values which may not be used synchronous */

	pr_debug("%s: registering handler %p for signal '%d'\n", __func__,
			 sigh, signo);

	if ((sig = calloc(1, sizeof(struct ulogd_signal))) == NULL)
		return NULL;

	sig->signo = signo;
	sig->flags = flags;
	sig->handler = sigh;

	sig_state[signo].cnt++;

	/* add real signal handler */
	if ((sig_state[signo].flags & SIG_F_USED) == 0) {
		signal(signo, sig_handler);
		
		sig_state[signo].flags |= SIG_F_USED;
	}

	if (flags & ULOGD_SIGF_SYNC)
		llist_add_tail(&sig->link, &sig_state[signo].head);
	else
		llist_add_tail(&sig->link, &sig_state[signo].async_head);

	ulogd_sigaddset(signo);

	return sig;
}

int
ulogd_unregister_signal(struct ulogd_signal *sig)
{
	if (sig == NULL || sig->signo < 0 || sig->signo >= NSIG)
		return -1;

	pr_debug("%s: unregistering handler %p\n", __func__, sig);

	if (--sig_state[sig->signo].cnt == 0)
		signal(sig->signo, SIG_DFL);

	llist_del(&sig->link);

	free(sig);

	return 0;
}

int
ulogd_sigaddset(int signo)
{
	return sigaddset(&currset, signo);
}

int
ulogd_get_sigset(sigset_t *sigset)
{
	assert(sigset != NULL);

	memcpy(sigset, &currset, sizeof(sigset_t));

	return 0;
}

static int
sig_pipe_cb(int fd, unsigned what, void *arg)
{
	struct ulogd_signal *sig;
	sigset_t sigset;
	int signo, nbytes;

	assert(what == ULOGD_FD_READ);

	nbytes = read(fd, &signo, sizeof(signo));

	pr_debug("%s: signo=%d\n", __func__, signo);

	assert(nbytes == sizeof(signo));

	if (signo < 0 || signo > NSIG)
		abort();

	sigemptyset(&sigset);
	sigaddset(&sigset, signo);

	pthread_sigmask(SIG_BLOCK, &sigset, NULL);

	llist_for_each_entry(sig, &sig_state[signo].head, link)
		sig->handler(signo);

	pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);

	return 0;
}

int
ulogd_signal_init(void)
{
	int i;
	sigset_t fullset;

	sigfillset(&fullset);
	pthread_sigmask(SIG_SETMASK, &fullset, NULL);

	sigemptyset(&currset);

	for (i = 0; i < NSIG; i++) {
		INIT_LLIST_HEAD(&sig_state[i].head);
		INIT_LLIST_HEAD(&sig_state[i].async_head);
	}

	/* init signal pipe */
	if (pipe(sig_pipe) < 0) {
		ulogd_log(ULOGD_FATAL, "unable to initialize signal pipe\n");
		return -1;
	}

	sig_pipe_fd.fd = sig_pipe[0];
	sig_pipe_fd.cb = sig_pipe_cb;
	sig_pipe_fd.when = ULOGD_FD_READ;

	return ulogd_register_fd(&sig_pipe_fd);
}
