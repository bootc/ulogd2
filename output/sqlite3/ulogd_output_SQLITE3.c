/*
 * ulogd output plugin for logging to a SQLITE database
 *
 * (C) 2005 by Ben La Monica <ben.lamonica@gmail.com>
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
 * 
 *  This module has been adapted from the ulogd_MYSQL.c written by
 *  Harald Welte <laforge@gnumonks.org>
 *  Alex Janssen <alex@ynfonatic.de>
 *
 *  You can see benchmarks and an explanation of the testing
 *  at http://www.pojo.us/ulogd/
 *
 *  2005-02-09 Harald Welte <laforge@gnumonks.org>:
 *  	- port to ulogd-1.20 
 *
 *  2006-10-09 Holger Eitzenberger <holger@my-eitzenberger.de>
 *  	- port to ulogd-2.00
 */
#include "config.h"
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/plugin.h>
#include <sqlite3.h>
#include <string.h>
#include <arpa/inet.h>

#define PFX		"SQLITE3: "

/* config defaults */
#define CFG_BUFFER_DEFAULT		100
#define CFG_TIMER_DEFAULT		1 SEC
#define CFG_MAX_BACKLOG_DEFAULT	0		/* unlimited */


#define SQLITE3_BUSY_TIMEOUT 300

/* number of colums we have (really should be configurable) */
#define DB_NUM_COLS	12


/* map DB column to ulogd key */
struct col {
	char name[ULOGD_MAX_KEYLEN];
	struct ulogd_key *key;
};

struct row {
	struct llist_head link;
	uint32_t ip_saddr;
	uint32_t ip_daddr;
	unsigned char ip_proto;
	unsigned l4_dport;
	unsigned raw_in_pktlen;
	unsigned raw_in_pktcount;
	unsigned raw_out_pktlen;
	unsigned raw_out_pktcount;
	unsigned flow_start_day;
	unsigned flow_start_sec;
	unsigned flow_duration;
};

#define RKEY(key)	((key)->u.source)


struct sqlite3_priv {
	sqlite3 *dbh;				/* database handle we are using */
	char *stmt;
	sqlite3_stmt *p_stmt;
	int buffer_size;

	struct ulogd_timer timer;

	struct col cols[DB_NUM_COLS];

	/* our backlog buffer */
	struct llist_head rows;
	int num_rows;
	int max_backlog;

	time_t commit_time;

	unsigned disable : 1;
	unsigned overlimit_msg : 1;
};


static const struct config_keyset sqlite3_kset = {
	.num_ces = 6,
	.ces = {
		{
			.key = "db",
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_MANDATORY,
		},
		{
			.key = "table",
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_MANDATORY,
		},
		{
			.key = "buffer",
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = CFG_BUFFER_DEFAULT,
		},
		{
			.key = "timer",
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = CFG_TIMER_DEFAULT,
		},
		{
			.key = "max-backlog",
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = CFG_MAX_BACKLOG_DEFAULT,
		},
		{
			.key = "disable",
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
	},
};

#define db_ce(pi)		(pi)->config_kset->ces[0].u.string
#define table_ce(pi)	(pi)->config_kset->ces[1].u.string
#define buffer_ce(pi)	(pi)->config_kset->ces[2].u.value
#define timer_ce(pi)	(pi)->config_kset->ces[3].u.value
#define max_backlog_ce(pi)	(pi)->config_kset->ces[4].u.value
#define disable_ce(pi)	(pi)->config_kset->ces[5].u.value


#define SQL_CREATE_STR \
		"create table daily(ip_saddr integer, ip_daddr integer, " \
		"ip_protocol integer, l4_dport integer, raw_in_pktlen integer, " \
		"raw_in_pktcount integer, raw_out_pktlen integer, " \
		"raw_out_pktcount integer, flow_start_day integer, " \
		"flow_start_sec integer, flow_duration integer, flow_count integer)"


static struct row *
row_new(void)
{
	struct row *row;

	if ((row = calloc(1, sizeof(struct row))) == NULL)
		ulogd_error("%s: out of memory\n", __func__);

	return row;
}


static inline void
__row_del(struct sqlite3_priv *priv, struct row *row)
{
	assert(row != NULL);

	free(row);
}


static void
row_del(struct sqlite3_priv *priv, struct row *row)
{
	llist_del(&row->link);

	__row_del(priv, row);

	priv->num_rows--;
}


static int
row_add(struct sqlite3_priv *priv, struct row *row)
{
	if (priv->max_backlog && priv->num_rows >= priv->max_backlog) {
		if (!priv->overlimit_msg) {
			ulogd_error(PFX "over max-backlog limit, dropping rows\n");

			priv->overlimit_msg = 1;
		}

		__row_del(priv, row);

		return -1;
	}

	llist_add_tail(&row->link, &priv->rows);

	priv->num_rows++;

	return 0;
}

/* set_commit_time() - set time for next try on locked database
 *
 * The database is effectively locked in between.
 */
static void
set_commit_time(const struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = upi_priv(pi);

	priv->commit_time = t_now + 1;

	pr_debug("%s: commit time %d\n", __func__, priv->commit_time);
}

#define _SQLITE3_INSERTTEMPL   "insert into X (Y) values (Z)"

/* create static part of our insert statement */
static int
db_createstmt(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = upi_priv(pi);
	char buf[ULOGD_MAX_KEYLEN];
	char *underscore;
	char *stmt_pos;
	int i;

	if (priv->stmt != NULL)
		free(priv->stmt);

	if ((priv->stmt = calloc(1, 1024)) == NULL) {
		ulogd_error(PFX "out of memory\n");
		return -1;
	}

	sprintf(priv->stmt, "insert into %s (", table_ce(pi));
	stmt_pos = priv->stmt + strlen(priv->stmt);

	for (i = 0; i < DB_NUM_COLS; i++) {
		struct col *col = &priv->cols[i];

		/* convert name */
		strncpy(buf, col->name, ULOGD_MAX_KEYLEN);

		while ((underscore = strchr(buf, '.')))
			*underscore = '_';

		sprintf(stmt_pos, "%s,", buf);
		stmt_pos = priv->stmt + strlen(priv->stmt);
	}

	*(stmt_pos - 1) = ')';

	sprintf(stmt_pos, " values (");
	stmt_pos = priv->stmt + strlen(priv->stmt);

	for (i = 0; i < DB_NUM_COLS - 1; i++) {
		sprintf(stmt_pos,"?,");
		stmt_pos += 2;
	}

	sprintf(stmt_pos, "?)");
	upi_log(pi, ULOGD_DEBUG, "stmt='%s'\n", priv->stmt);

	sqlite3_prepare(priv->dbh, priv->stmt, -1, &priv->p_stmt, 0);
	if (priv->p_stmt == NULL) {
		ulogd_error(PFX "prepare: %s\n", sqlite3_errmsg(priv->dbh));
		return 1;
	}

	pr_debug("%s: statement prepared.\n", pi->id);

	return 0;
}

#define SELECT_ALL_STR			"select * from "
#define SELECT_ALL_LEN			sizeof(SELECT_ALL_STR)

static int
db_count_cols(struct ulogd_pluginstance *pi, sqlite3_stmt **stmt)
{
	struct sqlite3_priv *priv = upi_priv(pi);
	char query[255] = SELECT_ALL_STR;

	strncat(query, table_ce(pi), LINE_LEN);

	if (sqlite3_prepare(priv->dbh, query, -1, stmt, 0) != SQLITE_OK) {
		return -1;
	}

	return sqlite3_column_count(*stmt);
}


static int
db_create_tbl(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = upi_priv(pi);
	char *errmsg;
	int ret;

	sqlite3_exec(priv->dbh, "drop table daily", NULL, NULL, NULL);

	ret = sqlite3_exec(priv->dbh, SQL_CREATE_STR, NULL, NULL, &errmsg);
	if (ret != SQLITE_OK) {
		ulogd_error(PFX "create table: %s\n", errmsg);
		sqlite3_free(errmsg);

		return -1;
	}

	return 0;
}


/* initialize DB, possibly creating it */
static int
db_init(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = upi_priv(pi);
	char buf[ULOGD_MAX_KEYLEN];
	char *underscore;
	sqlite3_stmt *schema_stmt;
	int num_cols, i;

	if (priv->dbh == NULL)
		return -1;

	num_cols = db_count_cols(pi, &schema_stmt);
	if (num_cols != DB_NUM_COLS) {
		upi_log(pi, ULOGD_INFO, "(re)creating database\n");

		if (db_create_tbl(pi) < 0)
			return -1;

		num_cols = db_count_cols(pi, &schema_stmt);
	}

	assert(num_cols == DB_NUM_COLS);

	for (i = 0; i < DB_NUM_COLS; i++) {
		struct col *col = &priv->cols[i];

		strncpy(buf, sqlite3_column_name(schema_stmt, i), ULOGD_MAX_KEYLEN);

		/* replace all underscores with dots */
		while ((underscore = strchr(buf, '_')) != NULL)
			*underscore = '.';

		pr_debug("column '%s' found\n", buf);

		strncpy(col->name, buf, ULOGD_MAX_KEYLEN);

		/* hack alarm: ignore this column */
		if (strcmp(buf, "flow.count") == 0)
			continue;

		if ((col->key = ulogd_key_find(&pi->input, buf)) == NULL) {
			upi_log(pi, ULOGD_ERROR, "%s: key not found\n", buf);
			return -1;
		}
	}

	upi_log(pi, ULOGD_INFO, "database opened\n");

	if (sqlite3_finalize(schema_stmt) != SQLITE_OK) {
		ulogd_error(PFX "sqlite_finalize: %s\n",
					sqlite3_errmsg(priv->dbh));
		return -1;
	}

	return 0;
}


static void
db_reset(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = upi_priv(pi);

	sqlite3_finalize(priv->p_stmt);

	sqlite3_close(priv->dbh);
	priv->dbh = NULL;

	free(priv->stmt);
	priv->stmt = NULL;
}


static int
db_start(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = upi_priv(pi);

	upi_log(pi, ULOGD_DEBUG, "opening database connection\n");

	if (sqlite3_open(db_ce(pi), &priv->dbh) != SQLITE_OK) {
		ulogd_error(PFX "%s\n", sqlite3_errmsg(priv->dbh));
		return -1;
	}

	/* set the timeout so that we don't automatically fail
	   if the table is busy */
	sqlite3_busy_timeout(priv->dbh, SQLITE3_BUSY_TIMEOUT);

	/* read the fieldnames to know which values to insert */
	if (db_init(pi) < 0)
		return -1;

	/* initialize our buffer size and counter */
	priv->buffer_size = buffer_ce(pi);

	priv->max_backlog = max_backlog_ce(pi);

	/* create and prepare the actual insert statement */
	db_createstmt(pi);

	return 0;
}

/* db_err() - handle database errors */
static int
db_err(struct ulogd_pluginstance *pi, int ret)
{
	struct sqlite3_priv *priv = upi_priv(pi);

	pr_debug("%s: ret=%d (errcode %d)\n", __func__, ret,
			 sqlite3_errcode(priv->dbh));

	assert(ret != SQLITE_OK && ret != SQLITE_DONE);

	if (ret == SQLITE_BUSY || ret == SQLITE_LOCKED)
		set_commit_time(pi);
	else {
		switch (sqlite3_errcode(priv->dbh)) {
		case SQLITE_LOCKED:
		case SQLITE_BUSY:
			set_commit_time(pi);
			break;

		case SQLITE_SCHEMA:
			if (priv->stmt) {
				sqlite3_finalize(priv->p_stmt);

				db_createstmt(pi);

				upi_log(pi, ULOGD_INFO, "database schema changed\n");
			}
			break;

		default:
			upi_log(pi, ULOGD_ERROR, "transaction: %s\n",
					sqlite3_errmsg(priv->dbh));
			break;
		}
	}

	sqlite3_exec(priv->dbh, "rollback", NULL, NULL, NULL);

	/* no sqlit3_clear_bindings(), as an unbind will be done implicitely
	   on next bind. */
	if (priv->p_stmt != NULL)
		sqlite3_reset(priv->p_stmt);

	return 0;
}

static int
db_add_row(struct ulogd_pluginstance *pi, const struct row *row)
{
	struct sqlite3_priv *priv = upi_priv(pi);
	int db_col = 1, ret;

	do {
		ret = sqlite3_bind_int64(priv->p_stmt, db_col++, row->ip_saddr);
		if (ret != SQLITE_OK)
			break;

		ret = sqlite3_bind_int64(priv->p_stmt, db_col++, row->ip_daddr);
		if (ret != SQLITE_OK)
			break;

		ret = sqlite3_bind_int(priv->p_stmt, db_col++, row->ip_proto);
		if (ret != SQLITE_OK)
			break;

		ret = sqlite3_bind_int(priv->p_stmt, db_col++, row->l4_dport);
		if (ret != SQLITE_OK)
			break;

		ret = sqlite3_bind_int(priv->p_stmt, db_col++, row->raw_in_pktlen);
		if (ret != SQLITE_OK)
			break;

		ret = sqlite3_bind_int64(priv->p_stmt, db_col++, row->raw_in_pktcount);
		if (ret != SQLITE_OK)
			break;

		ret = sqlite3_bind_int(priv->p_stmt, db_col++, row->raw_out_pktlen);
		if (ret != SQLITE_OK)
			break;

		ret = sqlite3_bind_int64(priv->p_stmt, db_col++,
								 row->raw_out_pktcount);
		if (ret != SQLITE_OK)
			break;

		ret = sqlite3_bind_int(priv->p_stmt, db_col++, row->flow_start_day);
		if (ret != SQLITE_OK)
			break;

		ret = sqlite3_bind_int(priv->p_stmt, db_col++, row->flow_start_sec);
		if (ret != SQLITE_OK)
			break;

		ret = sqlite3_bind_int(priv->p_stmt, db_col++, row->flow_duration);
		if (ret != SQLITE_OK)
			break;

		/* hack alarm: add static data (argh!) */
		ret = sqlite3_bind_int(priv->p_stmt, db_col++, 1);
		if (ret != SQLITE_OK)
			break;

		if (sqlite3_step(priv->p_stmt) == SQLITE_DONE) {
			/* no sqlite3_clear_bindings(), as an unbind will be
			   implicetely done before next bind. */
			sqlite3_reset(priv->p_stmt);

			return 0;
		}

		/* according to the documentation sqlite3_step() always returns a
		   generic SQLITE_ERROR.  In order to find out the cause of the
		   error you have to call sqlite3_reset() or sqlite3_finalize(). */
		ret = sqlite3_reset(priv->p_stmt);
	} while (0);

	return db_err(pi, ret);
}

/* delete_rows() - delete rows from the tail of the list */
static int
delete_rows(struct ulogd_pluginstance *pi, int rows)
{
	struct sqlite3_priv *priv = upi_priv(pi);
	struct llist_head *curr, *tmp;

    llist_for_each_prev_safe(curr, tmp, &priv->rows) {
		struct row *row = container_of(curr, struct row, link);

		if (rows-- == 0)
			break;

		row_del(priv, row);
	}

	return 0;
}

/*
  db_commit_rows()

  RETURN
    >0	rows commited
    0	locked
   -1	error
*/
static int
db_commit_rows(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = upi_priv(pi);
	struct row *row;
	int ret, rows = 0, max_commit;

	ret = sqlite3_exec(priv->dbh, "begin immediate transaction", NULL,
					   NULL, NULL);
	if (ret != SQLITE_OK)
		return db_err(pi, ret);

	/* Limit number of rows to commit.  Note that currently three times
	   buffer_size is a bit arbitrary and therefore might be adjusted in
	   the future. */
	max_commit = max(3 * priv->buffer_size, 1024);

	llist_for_each_entry_reverse(row, &priv->rows, link) {
		if (++rows > max_commit)
			break;

		if (db_add_row(pi, row) < 0)
			return db_err(pi, ret);
	}

	ret = sqlite3_exec(priv->dbh, "commit", NULL, NULL, NULL);
	if (ret != SQLITE_OK)
		return db_err(pi, ret);

	sqlite3_reset(priv->p_stmt);
	
	pr_debug("%s: commited %d/%d rows\n", pi->id, rows, priv->num_rows);

	delete_rows(pi, rows);
	
	if (priv->commit_time >= t_now)
		priv->commit_time = 0;		/* release commit lock */
	
	if (priv->overlimit_msg)
		priv->overlimit_msg = 0;

	return rows;
}


/* our main output function, called by ulogd */
static int
sqlite3_interp(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = upi_priv(pi);
	struct col *cols = priv->cols;
	struct row *row;

	if ((row = row_new()) == NULL)
		return ULOGD_IRET_ERR;

	row->ip_saddr = key_src_u32(cols[0].key);
	row->ip_daddr = key_src_u32(cols[1].key);
	row->ip_proto = key_src_u8(cols[2].key);
	row->l4_dport = key_src_u16(cols[3].key);
	row->raw_in_pktlen = key_src_u32(cols[4].key);
	row->raw_in_pktcount = key_src_u32(cols[5].key);
	row->raw_out_pktlen = key_src_u32(cols[6].key);
	row->raw_out_pktcount = key_src_u32(cols[7].key);
	row->flow_start_day = key_src_u32(cols[8].key);
	row->flow_start_sec = key_src_u32(cols[9].key);
	row->flow_duration = key_src_u32(cols[10].key);

	if (row_add(priv, row) < 0)
		return ULOGD_IRET_OK;

	if (priv->num_rows >= priv->buffer_size && priv->commit_time == 0)
		db_commit_rows(pi);

	return ULOGD_IRET_OK;
}


static void
sqlite_timer_cb(struct ulogd_timer *t)
{
	struct ulogd_pluginstance *pi = t->data;
	struct sqlite3_priv *priv = upi_priv(pi);
	int rows;

	pr_debug("%s: timer=%p\n", __func__, t);

	if (priv->commit_time != 0 && priv->commit_time > t_now)
		return;

	if (priv->num_rows == 0)
		return;

	rows = db_commit_rows(pi);

	upi_log(pi, ULOGD_DEBUG, "rows=%d commited=%d\n",
			priv->num_rows, rows);
}


static int
sqlite3_configure(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = upi_priv(pi);

	memset(priv, 0, sizeof(struct sqlite3_priv));
	
	if (ulogd_wildcard_inputkeys(pi) < 0)
		return -1;

	if (db_ce(pi) == NULL) {
		ulogd_error("%s: configure: no database specified\n", pi->id);
		return -1;
	}

	if (table_ce(pi) == NULL) {
		ulogd_error("%s: configure: no table specified\n", pi->id);
		return -1;
	}

	if (timer_ce(pi) <= 0) {
		ulogd_error("%s: configure: invalid timer value\n", pi->id);
		return -1;
	}

	if (max_backlog_ce(pi)) {
		if (max_backlog_ce(pi) <= buffer_ce(pi)) {
			ulogd_error("%s: configure: invalid max-backlog value\n",
						pi->id);
			return -1;
		}
	}

	priv->max_backlog = max_backlog_ce(pi);
	priv->disable = disable_ce(pi);

	pr_debug("%s: db='%s' table='%s' timer=%d max-backlog=%d\n", pi->id,
			 db_ce(pi), table_ce(pi), timer_ce(pi), max_backlog_ce(pi));

	ulogd_init_timer(&priv->timer, timer_ce(pi), sqlite_timer_cb, pi,
					 TIMER_F_PERIODIC);

	ulogd_register_timer(&priv->timer);

	return 0;
}


static int
sqlite3_start(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = upi_priv(pi);

	pr_debug("%s: pi=%p\n", __func__, pi);

	if (priv->disable) {
		upi_log(pi, ULOGD_NOTICE, "disabled\n");
		return 0;
	}

	priv->num_rows = 0;
	INIT_LLIST_HEAD(&priv->rows);

	if (db_start(pi) < 0)
		return -1;

	upi_log(pi, ULOGD_INFO, "started\n");

	return 0;
}


/* give us an opportunity to close the database down properly */
static int
sqlite3_stop(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = upi_priv(pi);

	pr_debug("%s: pi=%p\n", __func__, pi);

	if (priv->disable)
		return 0;				/* wasn't started */

	if (priv->dbh == NULL)
		return 0;				/* already stopped */

	db_reset(pi);

	return 0;
}


static int
sqlite3_signal(struct ulogd_pluginstance *pi, int sig)
{
	struct sqlite3_priv *priv = upi_priv(pi);

	switch (sig) {
	case SIGUSR1:
		if (priv->dbh != NULL) {
			db_reset(pi);

			if (db_start(pi) < 0) {
				upi_log(pi, ULOGD_FATAL, "database reset failed\n");
				exit(EXIT_FAILURE);
			}
		}
		break;

	default:
		break;
	}

	return 0;
}


static struct ulogd_plugin sqlite3_plugin = { 
	.name = "SQLITE3",
	.flags = ULOGD_PF_RECONF,
	.input = {
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.config_kset = &sqlite3_kset,
	.priv_size = sizeof(struct sqlite3_priv),
	.configure = sqlite3_configure,
	.start = sqlite3_start,
	.stop = sqlite3_stop,
	.signal = sqlite3_signal,
	.interp = sqlite3_interp,
	.rev = ULOGD_PLUGIN_REVISION,
};

static void init(void) __upi_ctor;

static void
init(void) 
{
	ulogd_register_plugin(&sqlite3_plugin);

	ulogd_log(ULOGD_INFO, "using Sqlite version %s\n", sqlite3_libversion());
}
