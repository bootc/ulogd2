/* DB handling functions
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
 * (C) 2013 by Eric Leblond <eric@regit.org>
 *
 * This code is distributed under the terms of GNU GPL version 2 */


#ifndef _ULOGD_DB_H
#define _ULOGD_DB_H

#include <ulogd/ulogd.h>

struct db_driver {
	int (*get_columns)(struct ulogd_pluginstance *upi);
	int (*open_db)(struct ulogd_pluginstance *upi);
	int (*close_db)(struct ulogd_pluginstance *upi);
	int (*escape_string)(struct ulogd_pluginstance *upi,
			     char *dst, const char *src, unsigned int len);
	int (*execute)(struct ulogd_pluginstance *upi,
			const char *stmt, unsigned int len);
};

enum {
	RING_NO_QUERY,
	RING_QUERY_READY,
};

struct db_stmt_ring {
	/* Ring buffer: 1 status byte + string */
	char *ring; /* pointer to the ring */
	uint32_t size; /* size of ring buffer in element */
	int length; /* length of one ring buffer element */
	uint32_t wr_item; /* write item in ring buffer */
	uint32_t rd_item; /* read item in ring buffer */
	char *wr_place;
	pthread_cond_t cond;
	pthread_mutex_t mutex;
	int full;
};

struct db_stmt {
	char *stmt;
	int len;
	struct llist_head list;
};

struct db_instance {
	char *stmt; /* buffer for our insert statement */
	int stmt_offset; /* offset to the beginning of the "VALUES" part */
	char *schema;
	time_t reconnect;
	int (*interp)(struct ulogd_pluginstance *upi);
	struct db_driver *driver;
	/* DB ring buffer */
	struct db_stmt_ring ring;
	pthread_t db_thread_id;
	/* Backlog system */
	unsigned int backlog_memcap;
	unsigned int backlog_memusage;
	unsigned int backlog_oneshot;
	unsigned char backlog_full;
	struct llist_head backlog;
};
#define TIME_ERR		((time_t)-1)	/* Be paranoid */
#define RECONNECT_DEFAULT	2
#define MAX_ONESHOT_REQUEST	10
#define RING_BUFFER_DEFAULT_SIZE	10

#define DB_CES							\
		{						\
			.key = "table",				\
			.type = CONFIG_TYPE_STRING,		\
			.options = CONFIG_OPT_MANDATORY,	\
		},						\
		{						\
			.key = "reconnect",			\
			.type = CONFIG_TYPE_INT,		\
			.u.value = RECONNECT_DEFAULT,		\
		},						\
		{						\
			.key = "connect_timeout",		\
			.type = CONFIG_TYPE_INT,		\
		},						\
		{						\
			.key = "procedure",			\
			.type = CONFIG_TYPE_STRING,		\
			.options = CONFIG_OPT_MANDATORY,	\
		},						\
		{						\
			.key = "backlog_memcap",		\
			.type = CONFIG_TYPE_INT,		\
			.u.value = 0,				\
		},						\
		{						\
			.key = "backlog_oneshot_requests",	\
			.type = CONFIG_TYPE_INT,		\
			.u.value = MAX_ONESHOT_REQUEST,		\
		},						\
		{						\
			.key = "ring_buffer_size",		\
			.type = CONFIG_TYPE_INT,		\
			.u.value = RING_BUFFER_DEFAULT_SIZE,	\
		}

#define DB_CE_NUM		7
#define table_ce(x)		(x->ces[0])
#define reconnect_ce(x)		(x->ces[1])
#define timeout_ce(x)		(x->ces[2])
#define procedure_ce(x)		(x->ces[3])
#define backlog_memcap_ce(x)	(x->ces[4])
#define backlog_oneshot_ce(x)	(x->ces[5])
#define ringsize_ce(x)		(x->ces[6])

void ulogd_db_signal(struct ulogd_pluginstance *upi, int signal);
int ulogd_db_start(struct ulogd_pluginstance *upi);
int ulogd_db_stop(struct ulogd_pluginstance *upi);
int ulogd_db_interp(struct ulogd_pluginstance *upi);
int ulogd_db_configure(struct ulogd_pluginstance *upi,
			struct ulogd_pluginstance_stack *stack);


#endif
