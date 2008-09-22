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

/* key types */
enum ulogd_ktype {
	ULOGD_RET_NONE = 0,
    ULOGD_RET_INT8,
	ULOGD_RET_INT16,
	ULOGD_RET_INT32,
	ULOGD_RET_INT64,
	ULOGD_RET_UINT8,
	ULOGD_RET_UINT16,
	ULOGD_RET_UINT32,
	ULOGD_RET_UINT64,
	ULOGD_RET_BOOL,
	ULOGD_RET_IPADDR,
	ULOGD_RET_IP6ADDR,
	ULOGD_RET_STRING,
	ULOGD_RET_RAW,
};

/* key flags */
#define ULOGD_RETF_NONE		0x0000
#define ULOGD_RETF_VALID	0x0001	/* contains a valid result */
#define ULOGD_RETF_FREE		0x0002	/* ptr needs to be free()d */
#define ULOGD_RETF_NEEDED	0x0004	/* this parameter is actually needed
					 * by some downstream plugin */

#define ULOGD_KEYF_OPTIONAL	0x0100	/* this key is optional */
#define ULOGD_KEYF_INACTIVE	0x0200	/* marked as inactive (i.e. totally
					   to be ignored by everyone */


/* maximum length of ulogd key */
#define ULOGD_MAX_KEYLEN 31

enum ulogd_loglevel {
	ULOGD_DEBUG = 1,	/* debugging information */
	ULOGD_INFO = 3,
	ULOGD_NOTICE = 5,	/* abnormal/unexpected condition */
	ULOGD_ERROR = 7,	/* error condition, requires user action */
	ULOGD_FATAL = 8,	/* fatal, program aborted */
	__ULOGD_LOGLEVEL_MAX = ULOGD_FATAL
};

/* ulogd data type */
enum ulogd_dtype {
	ULOGD_DTYPE_NULL	= 0x0000,
	ULOGD_DTYPE_SOURCE	= 0x0001, /* source of data, no input keys */
	ULOGD_DTYPE_RAW		= 0x0002, /* raw packet data */
	ULOGD_DTYPE_PACKET	= 0x0004, /* packet metadata */
	ULOGD_DTYPE_FLOW	= 0x0008, /* flow metadata */
	ULOGD_DTYPE_SINK	= 0x0010, /* sink of data, no output keys */
};

/* structure describing an input  / output parameter of a plugin */
struct ulogd_key {
	/* length of the returned value (only for lengthed types */
	u_int32_t len;

	/* type of the returned value */
	enum ulogd_ktype type;

	u_int16_t flags;

	/* name of this key */
	char name[ULOGD_MAX_KEYLEN+1];

	/* IETF IPFIX attribute ID */
	struct {
		u_int32_t	vendor;
		u_int16_t	field_id;
	} ipfix;

	union {
		/* and finally the returned value */
		union {
			u_int8_t	b;
			u_int8_t	ui8;
			u_int16_t	ui16;
			u_int32_t	ui32;
			u_int64_t	ui64;
			int8_t		i8;
			int16_t		i16;
			int32_t		i32;
			int64_t		i64;
			void		*ptr;
			char		*str;
		} value;
		struct ulogd_key *source;
	} u;

	/* private date owned by plugin */
	void *priv;
};

struct ulogd_keyset {
	/* possible input keys of this interpreter */
	struct ulogd_key *keys;
	/* number of input keys */
	unsigned int num_keys;
	/* bitmask of possible types */
	unsigned int type;
};

struct ulogd_pluginstance_stack;
struct ulogd_pluginstance;

/* plugin flags */
#define ULOGD_PF_RECONF			0x00000001
#define ULOGD_PF_FSM			0x00000002 /* stack FSM running */

struct ulogd_plugin {
	/* global list of plugins */
	struct llist_head list;

	/* revision number, incremented on API changes */
	unsigned rev;

	/* name of this plugin (set by plugin) */
	char name[ULOGD_MAX_KEYLEN+1];

	unsigned flags;

	const struct ulogd_keyset input;
	const struct ulogd_keyset output;

	/* called per packet, may return ULOGD_IRET_AGAIN */
	int (* interp)(struct ulogd_pluginstance *pi);

	/* may return ULOGD_IRET_AGAIN */
	int (* configure)(struct ulogd_pluginstance *pi,
					  struct ulogd_pluginstance_stack *stack);

	/* may return ULOGD_IRET_AGAIN */
	int (* start)(struct ulogd_pluginstance *pi);

	/* function to destruct an existing pluginstance */
	int (* stop)(struct ulogd_pluginstance *pi);

	/* function to receive a signal, may return ULOGD_IRET_AGAIN */
	int (* signal)(struct ulogd_pluginstance *pi, int signal);

	/* configuration parameters */
	const struct config_keyset *config_kset;

	/* size of instance->priv */
	unsigned priv_size;
};

#define ULOGD_IRET_ERR		-1
#define ULOGD_IRET_STOP		-2
#define ULOGD_IRET_AGAIN    -3	/* try again later */
#define ULOGD_IRET_OK		0

/**
 * Plugin instance state handling
 *
 * PsInit		Plugin initialized.
 * PsConfigured	Plugin configured, if this step fails the daemon is stopped.
 * PsStarting	Plugin is in the process of starting.  If the start() fails
 *				there is a chance to restart if start() returns
 *				%ULOGD_IRET_AGAIN.
 * PsStart		Plugin up and running.
 */
enum UpiState {
	PsInit = 0,
	PsConfiguring,
	PsConfigured,
	PsStarting,
	PsStarted,
	__PsMax = PsStarted
};

/* an instance of a plugin, element in a stack */
struct ulogd_pluginstance {
	/* local list of plugins in this stack */
	struct llist_head list;
	/* state dependant usage (e. g. restart handling) */
	struct llist_head state_link;
	enum UpiState state;
	/* plugin */
	struct ulogd_plugin *plugin;
	/* stack that we're part of */
	struct ulogd_pluginstance_stack *stack;
	/* name / id  of this instance*/
	char id[ULOGD_MAX_KEYLEN+1];
	/* per-instance input keys */
	struct ulogd_keyset input;
	/* per-instance output keys */
	struct ulogd_keyset output;
	/* per-instance config parameters (array) */
	struct config_keyset *config_kset;
	/* private data */
	char private[0];
};

static inline void *
upi_priv(struct ulogd_pluginstance *upi)
{
	return (void *)&upi->private;
}

struct ulogd_pluginstance_stack {
	/* global list of pluginstance stacks */
	struct llist_head stack_list;
	/* list of plugins in this stack */
	struct llist_head list;
	unsigned flags;
	enum UpiState state;
	/* for state handling */
	struct llist_head state_link;
	char *name;
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

void ulogd_propagate_results(struct ulogd_pluginstance *pi);

/* register a new interpreter plugin */
void ulogd_register_plugin(struct ulogd_plugin *me);

/* allocate a new ulogd_key */
struct ulogd_key *alloc_ret(const u_int16_t type, const char*);

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

#define IS_VALID(x)	((x).flags & ULOGD_RETF_VALID)
#define SET_VALID(x)	(x.flags |= ULOGD_RETF_VALID)
#define IS_NEEDED(x)	(x.flags & ULOGD_RETF_NEEDED)
#define SET_NEEDED(x)	(x.flags |= ULOGD_RETF_NEEDED)

int ulogd_key_size(struct ulogd_key *key);
int ulogd_wildcard_inputkeys(struct ulogd_pluginstance *upi);

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
