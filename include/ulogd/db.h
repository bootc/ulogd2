#ifndef _ULOGD_DB_H
#define _ULOGD_DB_H

#include <ulogd/ulogd.h>
#include <stdbool.h>

/**
 * default buffer size used for batching.  If this limit is reached
 * a commit is done (or after timer elapsed).
 */
#define ULOGD_DB_BUFFER_DEFAULT	100

struct db_driver {
	/* set input keys depending on database shema (required) */
	int (* get_columns)(struct ulogd_pluginstance *upi);

	/* prepare SQL statement (optional) */
	int (* prepare)(struct ulogd_pluginstance *);

	int (* interp)(struct ulogd_pluginstance *);

	int (* commit)(struct ulogd_pluginstance *, int);

	int (* open_db)(struct ulogd_pluginstance *upi);
	int (* close_db)(struct ulogd_pluginstance *upi);
	int (* escape_string)(struct ulogd_pluginstance *upi,
			     char *dst, const char *src, unsigned int len);
	int (*execute)(struct ulogd_pluginstance *upi,
			const char *stmt, unsigned int len);
};

/**
 * A generic database row.
 */
struct db_row {
	struct llist_head link;
	uint32_t ip_saddr;
	uint32_t ip_daddr;
	unsigned char ip_proto;
	unsigned l4_dport;
	uint64_t raw_in_pktlen;
	uint64_t raw_in_pktcount;
	uint64_t raw_out_pktlen;
	uint64_t raw_out_pktcount;
	unsigned flow_start_day;
	unsigned flow_start_sec;
	unsigned flow_duration;
};

struct db_instance {
	char *stmt; /* buffer for our insert statement */
	char *stmt_val; /* pointer to the beginning of the "VALUES" part */
	char *stmt_ins; /* pointer to current inser position in statement */
	char *schema;
	time_t reconnect;
	int (*interp)(struct ulogd_pluginstance *upi);
	struct db_driver *driver;

	struct ulogd_timer timer;

	/* batching */
	struct llist_head rows;
	struct llist_head rows_committed;
	int num_rows;
	int buffer_size;
	int max_backlog;

	unsigned overlimit_msg : 1;
};

static inline bool
db_has_prepare(const struct db_instance *di)
{
	return di->driver->prepare != NULL;
}

#define TIME_ERR		((time_t)-1)	/* Be paranoid */

/*
 * GENERIC DATABASE CONFIGURATION SWITCHES
 *
 * buffer=N		Buffer size used for batching.  If this limit is reached
 *				a commit is forced (or after timer elapsed).
 */
#define DB_CES											   \
		CONFIG_KEY("table", STRING, CONFIG_OPT_MANDATORY), \
		CONFIG_KEY("reconnect", INT, 0),				   \
		CONFIG_KEY("ip_as_string", INT, 0),				   \
		CONFIG_KEY("connect_timeout", INT, 0),			   \
		CONFIG_KEY_INT("buffer", ULOGD_DB_BUFFER_DEFAULT), \
		CONFIG_KEY_INT("disable", 0),					   \
		CONFIG_KEY_INT("blackhole", 0)

#define __DB_CE_BASE			0
#define DB_CE_NUM				7

#define table_ce(pi)			ulogd_config_str(pi, __DB_CE_BASE)
#define reconnect_ce(pi)		ulogd_config_int(pi, __DB_CE_BASE + 1)
#define asstring_ce(pi)			ulogd_config_int(pi, __DB_CE_BASE + 2)
#define timeout_ce(pi)			ulogd_config_int(pi, __DB_CE_BASE + 3)
#define db_buffer_ce(pi)		ulogd_config_int(pi, __DB_CE_BASE + 4)
#define disable_ce(pi)			ulogd_config_int(pi, __DB_CE_BASE + 5)
#define blackhole_ce(pi)		ulogd_config_int(pi, __DB_CE_BASE + 6)

int ulogd_db_start(struct ulogd_pluginstance *upi);
int ulogd_db_stop(struct ulogd_pluginstance *upi);
int ulogd_db_interp(struct ulogd_pluginstance *upi, unsigned *flags);
int ulogd_db_interp_batch(struct ulogd_pluginstance *upi, unsigned *flags);
int ulogd_db_configure(struct ulogd_pluginstance *upi);
int ulogd_db_signal(struct ulogd_pluginstance *upi, int signal);

/* generic row handling */
struct db_row *db_row_new(struct ulogd_pluginstance *pi);
int db_row_add(struct ulogd_pluginstance *pi, struct db_row *);
void db_row_del(struct ulogd_pluginstance *pi, struct db_row *);

#endif
