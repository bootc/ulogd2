#ifndef _ULOGD_H
#define _ULOGD_H
/* ulogd, Version $Revision$
 *
 * userspace logging daemon for netfilter ULOG target
 * of the linux 2.4/2.6 netfilter subsystem.
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
 *
 * this code is released under the terms of GNU GPL
 *
 * $Id$
 */

#include <ulogd/linuxlist.h>
#include <ulogd/conffile.h>
#include <ulogd/ipfix_protocol.h>
#include <stdio.h>
#include <stdbool.h>
#include <signal.h>	/* need this because of extension-sighandler */
#include <sys/types.h>

/* TODO should move to common.h */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define __fmt_printf(idx, first) \
						__attribute__((format (printf,(idx),(first))))

#define __noreturn		__attribute__((noreturn))
#define __cold			__attribute__((cold))

#define LIKELY(expr)	__builtin_expect(!!(expr), 1)
#define UNLIKELY(expr)	__builtin_expect(!!(expr), 0)

enum ulogd_loglevel {
	ULOGD_DEBUG = 1,	/* debugging information */
	ULOGD_INFO = 3,
	ULOGD_NOTICE = 5,	/* abnormal/unexpected condition */
	ULOGD_ERROR = 7,	/* error condition, requires user action */
	ULOGD_FATAL = 8,	/* fatal, program aborted */
	__ULOGD_LOGLEVEL_MAX = ULOGD_FATAL
};

extern FILE *logfile;

/***********************************************************************
 * PUBLIC INTERFACE 
 ***********************************************************************/
enum GlobalState {
	GS_INVAL = 0,
	GS_INITIALIZING,			/* also reconfiguration */
	GS_RUNNING,
};

void ulogd_set_state(enum GlobalState);
enum GlobalState ulogd_get_state(void);

void ulogd_log(enum ulogd_loglevel, const char *fmt, ...)
				__fmt_printf(2, 3) __cold;

#define ulogd_error(format, args...) ulogd_log(ULOGD_ERROR, format, ## args)

void ulogd_bug(const char *, int) __noreturn __cold;

#ifdef NDEBUG
#define BUG()			    do { } while (0)
#define BUG_ON(expr)
#else
#define BUG()				ulogd_bug(__FILE__, __LINE__)
#define BUG_ON(expr)		do { if (UNLIKELY(expr)) BUG(); } while (0)
#endif /* NDEBUG */

/***********************************************************************
 * file descriptor handling
 ***********************************************************************/

#define ULOGD_FD_READ	0x0001
#define ULOGD_FD_WRITE	0x0002
#define ULOGD_FD_EXCEPT	0x0004

typedef int (* ulogd_fd_cb_t)(int fd, unsigned what, void *data);

struct ulogd_fd {
	struct llist_head list;
	int fd;						/* file descriptor */
	unsigned when;
	ulogd_fd_cb_t cb;			/* callback */
	void *data;					/* void * to pass to callback */
};

int ulogd_init_fd(struct ulogd_fd *ufd, int fd, unsigned when,
				  ulogd_fd_cb_t cb, void *data);
int ulogd_register_fd(struct ulogd_fd *ufd);
void ulogd_unregister_fd(struct ulogd_fd *ufd);
int ulogd_dispatch(void);

/***********************************************************************
 * timer handling (timer.c)
 ***********************************************************************/
#define TIMER_F_PERIODIC			0x01

struct ulogd_timer;

typedef void (* ulogd_timer_cb_t)(struct ulogd_timer *);

struct ulogd_timer {
	struct llist_head list;
	unsigned expires;			/* seconds */
	unsigned ival;				/* seconds */
	unsigned flags;
	ulogd_timer_cb_t cb;
	void *data;					/* usually (ulogd_pluginstance *) */
};

extern struct timeval tv_now;
extern struct timeval tv_now_local;

#define t_now			tv_now.tv_sec
#define t_now_local		tv_now_local.tv_sec

int ulogd_timer_init(void);
int ulogd_timer_run(void);
int ulogd_init_timer(struct ulogd_timer *timer, unsigned freq,
					 ulogd_timer_cb_t cb, void *arg, unsigned flags);
int ulogd_register_timer(struct ulogd_timer *timer);
void ulogd_unregister_timer(struct ulogd_timer *timer);
void ulogd_timer_schedule(void);
int ulogd_timer_handle(void);

static inline bool
timer_running(const struct ulogd_timer *t)
{
	return t->expires > 0;
}

#endif /* _ULOGD_H */
