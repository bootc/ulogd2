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
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include <ulogd/common.h>
#include <sqlite3.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/queue.h>

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
	TAILQ_ENTRY(row) link;
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

TAILQ_HEAD(row_lh, row);

#define TAILQ_FOR_EACH(pos, head, link) \
        for (pos = (head).tqh_first; pos != NULL; pos = pos->link.tqe_next)

#define RKEY(key)	((key)->u.source)


struct sqlite3_priv {
	sqlite3 *dbh;				/* database handle we are using */
	char *stmt;
	sqlite3_stmt *p_stmt;
	int buffer_size;

	struct ulogd_timer timer;

	struct col cols[DB_NUM_COLS];

	/* our backlog buffer */
	struct row_lh rows;
	int num_rows;
	int max_rows;				/* number of rows actually seen */
	int max_rows_allowed;

	unsigned disable : 1;
	unsigned overlimit_msg : 1;
};


static struct config_keyset sqlite3_kset = {
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


static void
row_del(struct sqlite3_priv *priv, struct row *row)
{
	TAILQ_REMOVE(&priv->rows, row, link);

	free(row);

	priv->num_rows--;
}


static void
row_add(struct sqlite3_priv *priv, struct row *row)
{
	if (priv->max_rows_allowed && priv->num_rows > priv->max_rows_allowed) {
		if (!priv->overlimit_msg) {
			ulogd_error(PFX "over max-backlog limit, dropping row\n");

			priv->overlimit_msg = 1;
		}

		return;
	}

	TAILQ_INSERT_TAIL(&priv->rows, row, link);

	priv->num_rows++;
}


#define _SQLITE3_INSERTTEMPL   "insert into X (Y) values (Z)"

/* create static part of our insert statement */
static int
db_createstmt(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = (void *)pi->private;
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
	ulogd_log(ULOGD_DEBUG, "%s: stmt='%s'\n", pi->id, priv->stmt);

	pr_debug("about to prepare statement.\n");

	sqlite3_prepare(priv->dbh, priv->stmt, -1, &priv->p_stmt, 0);
	if (priv->p_stmt == NULL) {
		ulogd_error(PFX "prepare: %s\n", sqlite3_errmsg(priv->dbh));
		return 1;
	}

	pr_debug("%s: statement prepared.\n", pi->id);

	return 0;
}


static struct ulogd_key *
ulogd_find_key(struct ulogd_pluginstance *pi, const char *name)
{
	int i;

	for (i = 0; i < pi->input.num_keys; i++) {
		if (strcmp(pi->input.keys[i].name, name) == 0)
			return &pi->input.keys[i];
	}

	return NULL;
}

#define SELECT_ALL_STR			"select * from "
#define SELECT_ALL_LEN			sizeof(SELECT_ALL_STR)

static int
db_count_cols(struct ulogd_pluginstance *pi, sqlite3_stmt **stmt)
{
	struct sqlite3_priv *priv = (void *)pi->private;
	char query[SELECT_ALL_LEN + CONFIG_VAL_STRING_LEN] = SELECT_ALL_STR;

	strncat(query, table_ce(pi), LINE_LEN);

	if (sqlite3_prepare(priv->dbh, query, -1, stmt, 0) != SQLITE_OK) {
		return -1;
	}

	return sqlite3_column_count(*stmt);
}


static int
db_create_tbl(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = (void *)pi->private;
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
	struct sqlite3_priv *priv = (void *)pi->private;
	char buf[ULOGD_MAX_KEYLEN];
	char *underscore;
	sqlite3_stmt *schema_stmt;
	int num_cols, i;

	if (priv->dbh == NULL)
		return -1;

	num_cols = db_count_cols(pi, &schema_stmt);
	if (num_cols != DB_NUM_COLS) {
		ulogd_log(ULOGD_INFO, "%s: (re)creating database\n", pi->id);

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

		if ((col->key = ulogd_find_key(pi, buf)) == NULL) {
			printf(PFX "%s: key not found\n", buf);
			return -1;
		}
	}

	ulogd_log(ULOGD_INFO, "%s: database opened\n", pi->id);

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
	struct sqlite3_priv *priv = (void *)pi->private;

	sqlite3_finalize(priv->p_stmt);

	sqlite3_close(priv->dbh);
	priv->dbh = NULL;

	free(priv->stmt);
	priv->stmt = NULL;
}


static int
db_start(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = (void *)pi->private;

	ulogd_log(ULOGD_DEBUG, "%s: opening database connection\n", pi->id);

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

	priv->max_rows_allowed = max_backlog_ce(pi);

	/* create and prepare the actual insert statement */
	db_createstmt(pi);

	return 0;
}


static int
db_add_row(struct ulogd_pluginstance *pi, const struct row *row)
{
	struct sqlite3_priv *priv = (void *)pi->private;
	int db_col = 1, ret = 0, db_ret;

	db_ret = sqlite3_bind_int64(priv->p_stmt, db_col++, row->ip_saddr);
	if (db_ret != SQLITE_OK)
		goto err_bind;

	db_ret = sqlite3_bind_int64(priv->p_stmt, db_col++, row->ip_daddr);
	if (db_ret != SQLITE_OK)
		goto err_bind;

	db_ret = sqlite3_bind_int(priv->p_stmt, db_col++, row->ip_proto);
	if (db_ret != SQLITE_OK)
		goto err_bind;

	db_ret = sqlite3_bind_int(priv->p_stmt, db_col++, row->l4_dport);
	if (db_ret != SQLITE_OK)
		goto err_bind;

	db_ret = sqlite3_bind_int(priv->p_stmt, db_col++, row->raw_in_pktlen);
	if (db_ret != SQLITE_OK)
		goto err_bind;

	db_ret = sqlite3_bind_int64(priv->p_stmt, db_col++, row->raw_in_pktcount);
	if (db_ret != SQLITE_OK)
		goto err_bind;

	db_ret = sqlite3_bind_int(priv->p_stmt, db_col++, row->raw_out_pktlen);
	if (db_ret != SQLITE_OK)
		goto err_bind;

	db_ret = sqlite3_bind_int64(priv->p_stmt, db_col++, row->raw_out_pktcount);
	if (db_ret != SQLITE_OK)
		goto err_bind;

	db_ret = sqlite3_bind_int(priv->p_stmt, db_col++, row->flow_start_day);
	if (db_ret != SQLITE_OK)
		goto err_bind;

	db_ret = sqlite3_bind_int(priv->p_stmt, db_col++, row->flow_start_sec);
	if (db_ret != SQLITE_OK)
		goto err_bind;

	db_ret = sqlite3_bind_int(priv->p_stmt, db_col++, row->flow_duration);
	if (db_ret != SQLITE_OK)
		goto err_bind;

	/* hack alarm: add static data (argh!) */
	db_ret = sqlite3_bind_int(priv->p_stmt, db_col++, 1);
	if (db_ret != SQLITE_OK)
		goto err_bind;

	db_ret = sqlite3_step(priv->p_stmt);

	if (db_ret == SQLITE_DONE) {
		/* the SQLITE book doesn't say that expclicitely _but_ between
		   two sqlite_bind_*() calls to the same variable you need to
		   call sqlite3_reset(). */
		sqlite3_reset(priv->p_stmt);

		return 0;
	}

	/* Ok, this is a bit confusing: some errors are reported as return
	   values, most others are reported through sqlite3_errcode() instead.
	   I think the only authorative source of information is the sqlite
	   source code.	*/
	switch (sqlite3_errcode(priv->dbh)) {
	case SQLITE_LOCKED:
	case SQLITE_BUSY:
		break;

	case SQLITE_SCHEMA:
		if (priv->stmt) {
			sqlite3_finalize(priv->p_stmt);

			db_createstmt(pi);
		}
		return -1;

	case SQLITE_ERROR: /* e.g. constraint violation */
	case SQLITE_MISUSE:
		ulogd_error(PFX "step: %s\n", sqlite3_errmsg(priv->dbh));
		ret = -1;
		break;

	default:
		break;
	}

	sqlite3_reset(priv->p_stmt);

	return ret;

 err_bind:
	ulogd_error(PFX "bind: %s\n", sqlite3_errmsg(priv->dbh));

	sqlite3_reset(priv->p_stmt);

	return -1;
}


static int
delete_all_rows(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = (void *)pi->private;

	while (priv->rows.tqh_first != NULL) {
		struct row *row = priv->rows.tqh_first;

		row_del(priv, row);
	}

	return 0;
}


static int
db_commit_rows(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = (void *)pi->private;
	struct row *row;
	int ret, rows = 0;

	ret = sqlite3_exec(priv->dbh, "begin immediate transaction", NULL,
					   NULL, NULL);
	if (ret != SQLITE_OK) {
		if (ret == SQLITE_BUSY)
			goto err_rollback;

		if (sqlite3_errcode(priv->dbh) == SQLITE_LOCKED)
			return 0;			/* perform commit later */
	
		ulogd_error("%s: begin transaction: %s\n", pi->id,
					sqlite3_errmsg(priv->dbh));

		return -1;
	}

	TAILQ_FOR_EACH(row, priv->rows, link) {
		if (db_add_row(pi, row) < 0)
			goto err_rollback;

		rows++;
	}

	ret = sqlite3_exec(priv->dbh, "commit", NULL, NULL, NULL);
	if (ret == SQLITE_OK) {
		sqlite3_reset(priv->p_stmt);

		if (priv->num_rows > priv->buffer_size)
			ulogd_log(ULOGD_INFO, "%s: commited backlog buffer (%d rows)\n",
					  pi->id, priv->num_rows);

		delete_all_rows(pi);

		if (priv->overlimit_msg)
			priv->overlimit_msg = 0;

		return 0;
	}

 err_rollback:
	if (sqlite3_errcode(priv->dbh) == SQLITE_LOCKED)
		return 0;

	sqlite3_exec(priv->dbh, "rollback", NULL, NULL, NULL);

	return -1;
}


/* our main output function, called by ulogd */
static int
sqlite3_interp(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = (void *)pi->private;
	struct col *cols = priv->cols;
	struct row *row;

	if ((row = row_new()) == NULL)
		return ULOGD_IRET_ERR;

	row->ip_saddr = RKEY(cols[0].key)->u.value.ui32;
	row->ip_daddr = RKEY(cols[1].key)->u.value.ui32;
	row->ip_proto = RKEY(cols[2].key)->u.value.ui8;
	row->l4_dport = RKEY(cols[3].key)->u.value.ui16;
	row->raw_in_pktlen = RKEY(cols[4].key)->u.value.ui32;
	row->raw_in_pktcount = RKEY(cols[5].key)->u.value.ui32;
	row->raw_out_pktlen = RKEY(cols[6].key)->u.value.ui32;
	row->raw_out_pktcount = RKEY(cols[7].key)->u.value.ui32;
	row->flow_start_day = RKEY(cols[8].key)->u.value.ui32;
	row->flow_start_sec = RKEY(cols[9].key)->u.value.ui32;
	row->flow_duration = RKEY(cols[10].key)->u.value.ui32;

	row_add(priv, row);

	if (priv->num_rows >= priv->buffer_size)
		db_commit_rows(pi);

	return ULOGD_IRET_OK;
}


static void
sqlite_timer_cb(struct ulogd_timer *t)
{
	struct ulogd_pluginstance *pi = t->data;
	struct sqlite3_priv *priv = (void *)pi->private;

	priv->max_rows = max(priv->max_rows, priv->num_rows);

	if (priv->num_rows > 0)
		db_commit_rows(pi);
}


static int
sqlite3_configure(struct ulogd_pluginstance *pi,
				  struct ulogd_pluginstance_stack *stack)
{
	struct sqlite3_priv *priv = (void *)pi->private;

	memset(priv, 0, sizeof(struct sqlite3_priv));
	
	config_parse_file(pi->id, pi->config_kset);

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

	priv->max_rows_allowed = max_backlog_ce(pi);
	priv->disable = disable_ce(pi);

	pr_debug("%s: db='%s' table='%s' timer=%d max-backlog=%d\n", pi->id,
			 db_ce(pi), table_ce(pi), timer_ce(pi), max_backlog_ce(pi));

	/* init timer */
	priv->timer.cb = sqlite_timer_cb;
	priv->timer.ival = timer_ce(pi);
	priv->timer.flags = TIMER_F_PERIODIC;
	priv->timer.data = pi;

	ulogd_register_timer(&priv->timer);

	return 0;
}


static int
sqlite3_start(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = (void *)pi->private;

	pr_debug("%s: pi=%p\n", __func__, pi);

	if (priv->disable) {
		ulogd_log(ULOGD_NOTICE, "%s: disabled\n", pi->id);
		return 0;
	}

	priv->num_rows = priv->max_rows = 0;
	TAILQ_INIT(&priv->rows);

	if (db_start(pi) < 0)
		return -1;

	ulogd_log(ULOGD_INFO, "%s: started\n", pi->id);

	return 0;
}


/* give us an opportunity to close the database down properly */
static int
sqlite3_stop(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = (void *)pi->private;

	pr_debug("%s: pi=%p\n", __func__, pi);

	if (priv->disable)
		return 0;				/* wasn't started */

	if (priv->dbh == NULL)
		return 0;				/* already stopped */

	db_reset(pi);

	return 0;
}


static void
sqlite3_signal(struct ulogd_pluginstance *pi, int sig)
{
	struct sqlite3_priv *priv = (void *)pi->private;

	switch (sig) {
	case SIGUSR1:
		if (priv->dbh != NULL) {
			db_reset(pi);

			if (db_start(pi) < 0) {
				ulogd_log(ULOGD_FATAL, "%s: database reset failed\n", pi->id);
				exit(EXIT_FAILURE);
			}
		}
		break;

	default:
		break;
	}
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
	.version = ULOGD_VERSION,
};

static void init(void) __attribute__((constructor));

static void
init(void) 
{
	ulogd_register_plugin(&sqlite3_plugin);

	ulogd_log(ULOGD_INFO, "using Sqlite version %s\n", sqlite3_libversion());
}
