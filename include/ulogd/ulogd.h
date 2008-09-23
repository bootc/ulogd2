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
#include <signal.h>	/* need this because of extension-sighandler */
#include <sys/types.h>

/* TODO should move to common.h */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define __fmt_printf(idx, first) \
						__attribute__ ((format (printf,(idx),(first))))

#define __noreturn		__attribute__ ((noreturn))

enum ulogd_loglevel {
	ULOGD_DEBUG = 1,	/* debugging information */
	ULOGD_INFO = 3,
	ULOGD_NOTICE = 5,	/* abnormal/unexpected condition */
	ULOGD_ERROR = 7,	/* error condition, requires user action */
	ULOGD_FATAL = 8,	/* fatal, program aborted */
	__ULOGD_LOGLEVEL_MAX = ULOGD_FATAL
};

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

/* write a message to the daemons' logfile */
void __ulogd_log(enum ulogd_loglevel, const char *file, int line,
				 const char *fmt, ...) __fmt_printf(4, 5);

/* macro for logging including filename and line number */
#define ulogd_log(level, format, args...) \
	__ulogd_log(level, __FILE__, __LINE__, format, ## args)
/* backwards compatibility */
#define ulogd_error(format, args...) ulogd_log(ULOGD_ERROR, format, ## args)

void __ulogd_abort(const char *, int, const char *, ...) __noreturn;

#define ulogd_abort(fmt, args...) \
	__ulogd_abort(__FILE__, __LINE__, fmt, ## args)

/***********************************************************************
 * file descriptor handling
 ***********************************************************************/

#define ULOGD_FD_READ	0x0001
#define ULOGD_FD_WRITE	0x0002
#define ULOGD_FD_EXCEPT	0x0004

struct ulogd_fd {
	struct llist_head list;
	int fd;				/* file descriptor */
	unsigned int when;
	int (*cb)(int fd, unsigned int what, void *data);
	void *data;			/* void * to pass to callback */
};

int ulogd_register_fd(struct ulogd_fd *ufd);
void ulogd_unregister_fd(struct ulogd_fd *ufd);
int ulogd_dispatch(void);

/***********************************************************************
 * timer handling (timer.c)
 ***********************************************************************/
#define TIMER_F_PERIODIC			0x01

struct ulogd_timer {
	struct llist_head list;
	unsigned expires;			/* seconds */
	unsigned ival;				/* seconds */
	unsigned flags;
	void (* cb)(struct ulogd_timer *);
	void *data;					/* usually (ulogd_pluginstance *) */
};

extern struct timeval tv_now;
extern struct timeval tv_now_local;

#define t_now			tv_now.tv_sec
#define t_now_local		tv_now_local.tv_sec

int ulogd_timer_init(void);
int ulogd_timer_run(void);
int ulogd_register_timer(struct ulogd_timer *timer);
void ulogd_unregister_timer(struct ulogd_timer *timer);
void ulogd_timer_schedule(void);
int ulogd_timer_handle(void);

#endif /* _ULOGD_H */
