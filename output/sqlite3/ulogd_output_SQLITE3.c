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

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include <ulogd/common.h>
#include <sqlite3.h>
#include <sys/queue.h>

#define CFG_BUFFER_DEFAULT		10

#define SQLITE3_BUSY_TIMEOUT 300

/* number of colums we have (really should be configurable) */
#define DB_NUM_COLS	11

#if 0
#define DEBUGP(x, args...)	fprintf(stderr, x, ## args)
#else
#define DEBUGP(x, args...)
#endif

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
	int max_rows;
};


static struct config_keyset sqlite3_kset = {
	.num_ces = 3,
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
	},
};

#define db_ce(pi)		(pi)->config_kset->ces[0].u.string
#define table_ce(pi)	(pi)->config_kset->ces[1].u.string
#define buffer_ce(pi)	(pi)->config_kset->ces[2].u.value


#define SQL_CREATE_STR \
		"create table daily(ip_saddr integer, ip_daddr integer, " \
		"ip_protocol integer, l4_dport integer, raw_in_pktlen integer, " \
		"raw_in_pktcount integer, raw_out_pktlen integer, " \
		"raw_out_pktcount integer, flow_start_day integer, " \
		"flow_start_sec integer, flow_duration integer)"


/* forward declarations */
static int sqlite3_createstmt(struct ulogd_pluginstance *);


static struct row *
row_new(void)
{
	struct row *row;

	if ((row = calloc(1, sizeof(struct row))) == NULL)
		ulogd_error("%s: out of memory\n", __func__);

	return row;
}


static void
row_add(struct sqlite3_priv *priv, struct row *row)
{
	TAILQ_INSERT_TAIL(&priv->rows, row, link);

	priv->num_rows++;
}


static void
row_del(struct sqlite3_priv *priv, struct row *row)
{
	TAILQ_REMOVE(&priv->rows, row, link);

	priv->num_rows--;
}


static int
db_add_row(struct ulogd_pluginstance *pi, const struct row *row)
{
	struct sqlite3_priv *priv = (void *)pi->private;
	int db_col = 1, ret;

	do {
		ret = sqlite3_bind_int(priv->p_stmt, db_col++, row->ip_saddr);
		if (ret != SQLITE_OK)
			break;

		ret = sqlite3_bind_int(priv->p_stmt, db_col++, row->ip_daddr);
		if (ret != SQLITE_OK)
			break;

		sqlite3_bind_int(priv->p_stmt, db_col++, row->ip_proto);
		if (ret != SQLITE_OK)
			break;

		sqlite3_bind_int(priv->p_stmt, db_col++, row->l4_dport);
		if (ret != SQLITE_OK)
			break;

		sqlite3_bind_int(priv->p_stmt, db_col++, row->raw_in_pktlen);
		if (ret != SQLITE_OK)
			break;

		sqlite3_bind_int(priv->p_stmt, db_col++, row->raw_in_pktcount);
		if (ret != SQLITE_OK)
			break;

		sqlite3_bind_int(priv->p_stmt, db_col++, row->raw_out_pktlen);
		if (ret != SQLITE_OK)
			break;

		sqlite3_bind_int(priv->p_stmt, db_col++, row->raw_out_pktcount);
		if (ret != SQLITE_OK)
			break;

		sqlite3_bind_int(priv->p_stmt, db_col++, row->flow_start_day);
		if (ret != SQLITE_OK)
			break;

		sqlite3_bind_int(priv->p_stmt, db_col++, row->flow_start_sec);
		if (ret != SQLITE_OK)
			break;

		sqlite3_bind_int(priv->p_stmt, db_col++, row->flow_duration);
		if (ret != SQLITE_OK)
			break;

		ret = sqlite3_step(priv->p_stmt);
	} while (0);

	sqlite3_reset(priv->p_stmt);

	if (ret == SQLITE_DONE)
		return 0;

	if (ret == SQLITE_ERROR) {
		sqlite3_finalize(priv->p_stmt);

		priv->p_stmt = NULL;

		if (ret == SQLITE_SCHEMA)
			sqlite3_createstmt(pi);
		else
			ulogd_error("SQLITE3: step: %s\n", sqlite3_errmsg(priv->dbh));
	}

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
	int ret;

	ret = sqlite3_exec(priv->dbh, "begin immediate transaction", NULL,
					   NULL, NULL);
	if (ret != SQLITE_OK) {
		if (ret == SQLITE_BUSY)
			return 0;

		ulogd_error("SQLITE3: sqlite3_exec: %s\n", sqlite3_errmsg(priv->dbh));

		return -1;
	}

	TAILQ_FOR_EACH(row, priv->rows, link) {
		if (db_add_row(pi, row) < 0)
			return -1;
	}

	ret = sqlite3_exec(priv->dbh, "commit", NULL, NULL, NULL);
	if (ret == SQLITE_OK) {
		delete_all_rows(pi);

		return 0;
	}

	/* XXX SQLITE_BUSY possible here? */

	ulogd_error("SQLITE3: sqlite3_exec: %s\n", sqlite3_errmsg(priv->dbh));

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

#define _SQLITE3_INSERTTEMPL   "insert into X (Y) values (Z)"

/* create the static part of our insert statement */
static int
sqlite3_createstmt(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = (void *)pi->private;
	char buf[ULOGD_MAX_KEYLEN];
	char *underscore;
	char *stmt_pos;
	int i;

	if (priv->stmt != NULL)
		free(priv->stmt);

	if ((priv->stmt = calloc(1, 1024)) == NULL) {
		ulogd_error("SQLITE3: out of memory\n");
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

	DEBUGP("about to prepare statement.\n");

	sqlite3_prepare(priv->dbh, priv->stmt, -1, &priv->p_stmt, 0);
	if (priv->p_stmt == NULL) {
		ulogd_error("SQLITE3: prepare: %s\n", sqlite3_errmsg(priv->dbh));
		return 1;
	}

	DEBUGP("statement prepared.\n");

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
		ulogd_error("SQLITE3: create table: %s\n", errmsg);
		sqlite3_free(errmsg);

		return -1;
	}

	return 0;
}


/* initialize DB, possibly creating it */
static int
sqlite3_init_db(struct ulogd_pluginstance *pi)
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

		DEBUGP("column '%s' found\n", buf);

		strncpy(col->name, buf, ULOGD_MAX_KEYLEN);

		if ((col->key = ulogd_find_key(pi, buf)) == NULL) {
			printf("SQLITE3: %s: key not found\n", buf);
			return -1;
		}
	}

	if (sqlite3_finalize(schema_stmt) != SQLITE_OK) {
		ulogd_error("SQLITE3: sqlite_finalize: %s\n",
					sqlite3_errmsg(priv->dbh));
		return -1;
	}

	return 0;
}


static void
timer_cb(struct ulogd_timer *t)
{
	struct ulogd_pluginstance *pi = t->data;
	struct sqlite3_priv *priv = (void *)pi->private;

	priv->max_rows = max(priv->max_rows, priv->num_rows);

	db_commit_rows(pi);
}


static int
sqlite3_configure(struct ulogd_pluginstance *pi,
				  struct ulogd_pluginstance_stack *stack)
{
	struct sqlite3_priv *priv = (void *)pi->private;

	config_parse_file(pi->id, pi->config_kset);

	if (ulogd_wildcard_inputkeys(pi) < 0)
		return -1;

	if (db_ce(pi) == NULL) {
		ulogd_error("SQLITE3: configure: no database specified\n");
		return -1;
	}

	if (table_ce(pi) == NULL) {
		ulogd_error("SQLITE3: configure: no table specified\n");
		return -1;
	}

	DEBUGP("%s: db='%s' table='%s'\n", pi->id, db_ce(pi), table_ce(pi));

	/* init timer */
	priv->timer.cb = timer_cb;
	priv->timer.ival = 1 SEC;
	priv->timer.flags = TIMER_F_PERIODIC;
	priv->timer.data = pi;

	ulogd_register_timer(&priv->timer);

	return 0;
}


static int
sqlite3_start(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = (void *)pi->private;

	TAILQ_INIT(&priv->rows);

	if (sqlite3_open(db_ce(pi), &priv->dbh) != SQLITE_OK) {
		ulogd_error("SQLITE3: %s\n", sqlite3_errmsg(priv->dbh));
		return -1;
	}

	/* set the timeout so that we don't automatically fail
	   if the table is busy */
	sqlite3_busy_timeout(priv->dbh, SQLITE3_BUSY_TIMEOUT);

	/* read the fieldnames to know which values to insert */
	if (sqlite3_init_db(pi) < 0)
		return -1;

	/* initialize our buffer size and counter */
	priv->buffer_size = buffer_ce(pi);

	/* create and prepare the actual insert statement */
	sqlite3_createstmt(pi);

	return 0;
}

/* give us an opportunity to close the database down properly */
static int
sqlite3_stop(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = (void *)pi->private;

	/* free up our prepared statements so we can close the db */
	if (priv->p_stmt) {
		sqlite3_finalize(priv->p_stmt);
		DEBUGP("prepared statement finalized\n");
	}

	if (priv->dbh == NULL)
		return -1;

	sqlite3_close(priv->dbh);

	return 0;
}


static struct ulogd_plugin sqlite3_plugin = { 
	.name = "SQLITE3", 
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
	.interp = sqlite3_interp,
	.version = ULOGD_VERSION,
};

static void init(void) __attribute__((constructor));

static void
init(void) 
{
	ulogd_register_plugin(&sqlite3_plugin);
}
