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
#include <sqlite3.h>
#include <sys/queue.h>

#define CFG_BUFFER_DEFAULT		10

#if 0
#define DEBUGP(x, args...)	fprintf(stderr, x, ## args)
#else
#define DEBUGP(x, args...)
#endif

struct field {
	TAILQ_ENTRY(field) link;
	char name[ULOGD_MAX_KEYLEN];
	struct ulogd_key *key;
};

TAILQ_HEAD(field_lh, field);

#define tailq_for_each(pos, head, link) \
        for (pos = (head).tqh_first; pos != NULL; pos = pos->link.tqe_next)


struct sqlite3_priv {
	sqlite3 *dbh;				/* database handle we are using */
	struct field_lh fields;
	char *stmt;
	sqlite3_stmt *p_stmt;
	int buffer_size;
	int buffer_curr;
	struct {
		unsigned err_tbl_busy;	/* "Table busy" */
	} stats;
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

/* forward declarations */
static int sqlite3_createstmt(struct ulogd_pluginstance *);


static int
add_row(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = (void *)pi->private;
	int ret;

	ret = sqlite3_step(priv->p_stmt);
	if (ret == SQLITE_DONE)
		priv->buffer_curr++;
	else if (ret == SQLITE_BUSY)
		priv->stats.err_tbl_busy++;
	else if (ret == SQLITE_ERROR) {
		ret = sqlite3_finalize(priv->p_stmt);
		priv->p_stmt = NULL;

		if (ret == SQLITE_SCHEMA)
			sqlite3_createstmt(pi);
		else {
			ulogd_log(ULOGD_ERROR, "SQLITE3: step: %s\n",
					  sqlite3_errmsg(priv->dbh));
			goto err_reset;
		}
	}

	ret = sqlite3_reset(priv->p_stmt);

	return 0;

 err_reset:
	sqlite3_reset(priv->p_stmt);

	return -1;
}


/* our main output function, called by ulogd */
static int
sqlite3_interp(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = (void *)pi->private;
	struct field *f;
	int ret, i = 1;

	tailq_for_each(f, priv->fields, link) {
		struct ulogd_key *k_ret = f->key->u.source;

		if (f->key == NULL || !IS_VALID(*k_ret)) {
			sqlite3_bind_null(priv->p_stmt, i);
			i++;
			continue;
		}

		switch (f->key->type) {
		case ULOGD_RET_INT8:
			ret = sqlite3_bind_int(priv->p_stmt, i, k_ret->u.value.i8);
			break;

		case ULOGD_RET_INT16:
			ret = sqlite3_bind_int(priv->p_stmt, i, k_ret->u.value.i16);
			break;

		case ULOGD_RET_INT32:
			ret = sqlite3_bind_int(priv->p_stmt, i, k_ret->u.value.i32);
			break;

		case ULOGD_RET_INT64:
			ret = sqlite3_bind_int(priv->p_stmt, i, k_ret->u.value.i64);
			break;
			
		case ULOGD_RET_UINT8:
			ret = sqlite3_bind_int(priv->p_stmt, i, k_ret->u.value.ui8);
			break;
			
		case ULOGD_RET_UINT16:
			ret = sqlite3_bind_int(priv->p_stmt, i, k_ret->u.value.ui16);
			break;

		case ULOGD_RET_UINT32:
			ret = sqlite3_bind_int(priv->p_stmt, i, k_ret->u.value.ui32);
			break;

		case ULOGD_RET_IPADDR:
		case ULOGD_RET_UINT64:
			ret = sqlite3_bind_int64(priv->p_stmt, i, k_ret->u.value.ui64);
			break;

		case ULOGD_RET_BOOL:
			ret = sqlite3_bind_int(priv->p_stmt, i, k_ret->u.value.b);
			break;

		case ULOGD_RET_STRING:
			ret = sqlite3_bind_text(priv->p_stmt, i, k_ret->u.value.ptr,
									strlen(k_ret->u.value.ptr), SQLITE_STATIC);
			break;

		default:
			ret = SQLITE_OK;
			ulogd_log(ULOGD_NOTICE, "unknown type %d for %s\n",
					  f->key->type, f->key->name);
		}
		if (ret != SQLITE_OK)
			goto err_bind;

		i++;
	}

	if (add_row(pi) < 0)
		return ULOGD_IRET_ERR;

	return ULOGD_IRET_OK;

 err_bind:
	ulogd_log(ULOGD_ERROR, "SQLITE: bind: %s\n", sqlite3_errmsg(priv->dbh));
	
	return ULOGD_IRET_ERR;
}

#define _SQLITE3_INSERTTEMPL   "insert into X (Y) values (Z)"

/* create the static part of our insert statement */
static int
sqlite3_createstmt(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = (void *)pi->private;
	struct field *f;
	char buf[ULOGD_MAX_KEYLEN];
	char *underscore;
	char *stmt_pos;
	int i, cols = 0;

	if (priv->stmt != NULL)
		free(priv->stmt);

	if ((priv->stmt = calloc(1, 1024)) == NULL) {
		ulogd_log(ULOGD_ERROR, "SQLITE3: out of memory\n");
		return -1;
	}

	sprintf(priv->stmt, "insert into %s (", table_ce(pi));
	stmt_pos = priv->stmt + strlen(priv->stmt);

	tailq_for_each(f, priv->fields, link) {
		strncpy(buf, f->name, ULOGD_MAX_KEYLEN);

		while ((underscore = strchr(buf, '.')))
			*underscore = '_';

		sprintf(stmt_pos, "%s,", buf);
		stmt_pos = priv->stmt + strlen(priv->stmt);

		cols++;
	}

	*(stmt_pos - 1) = ')';

	sprintf(stmt_pos, " values (");
	stmt_pos = priv->stmt + strlen(priv->stmt);

	for (i = 0; i < cols - 1; i++) {
		sprintf(stmt_pos,"?,");
		stmt_pos += 2;
	}

	sprintf(stmt_pos, "?)");
	ulogd_log(ULOGD_DEBUG, "%s: stmt='%s'\n", pi->id, priv->stmt);

	DEBUGP("about to prepare statement.\n");

	sqlite3_prepare(priv->dbh, priv->stmt, -1, &priv->p_stmt, 0);
	if (priv->p_stmt == NULL) {
		ulogd_log(ULOGD_ERROR, "SQLITE3: prepare: %s\n",
				  sqlite3_errmsg(priv->dbh));
		return 1;
	}

	DEBUGP("statement prepared.\n");

	return 0;
}


static struct ulogd_key *
ulogd_find_key(struct ulogd_pluginstance *pi, const char *name)
{
	unsigned int i;

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

	strncat(query, table_ce(pi), sizeof(query) - strlen(query) - 1);

	if (sqlite3_prepare(priv->dbh, query, -1, stmt, 0) != SQLITE_OK)
		return -1;

	return sqlite3_column_count(*stmt);
}

/* initialize DB, possibly creating it */
static int
sqlite3_init_db(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = (void *)pi->private;
	char buf[ULOGD_MAX_KEYLEN];
	char *underscore;
	struct field *f;
	sqlite3_stmt *schema_stmt;
	int col, num_cols;

	if (priv->dbh == NULL) {
		ulogd_log(ULOGD_ERROR, "SQLITE3: No database handle.\n");
		return -1;
	}

	num_cols = db_count_cols(pi, &schema_stmt);
	if (num_cols <= 0) {
		ulogd_log(ULOGD_ERROR, "table `%s' is empty or missing in "
				       "file `%s'. Did you created this "
				       "table in the database file? Please, "
				       "see ulogd2 documentation.\n",
					table_ce(pi), db_ce(pi));
		return -1;
	}

	for (col = 0; col < num_cols; col++) {
		strncpy(buf, sqlite3_column_name(schema_stmt, col), ULOGD_MAX_KEYLEN);

		/* replace all underscores with dots */
		while ((underscore = strchr(buf, '_')) != NULL)
			*underscore = '.';

		DEBUGP("field '%s' found\n", buf);

		/* prepend it to the linked list */
		if ((f = calloc(1, sizeof(struct field))) == NULL) {
			ulogd_log(ULOGD_ERROR, "SQLITE3: out of memory\n");
			return -1;
		}
		strncpy(f->name, buf, ULOGD_MAX_KEYLEN);

		if ((f->key = ulogd_find_key(pi, buf)) == NULL)
			return -1;

		TAILQ_INSERT_TAIL(&priv->fields, f, link);
	}

	sqlite3_finalize(schema_stmt);

	return 0;
}

#define SQLITE3_BUSY_TIMEOUT 300

static int
sqlite3_configure(struct ulogd_pluginstance *pi,
				  struct ulogd_pluginstance_stack *stack)
{
	/* struct sqlite_priv *priv = (void *)pi->private; */

	config_parse_file(pi->id, pi->config_kset);

	if (ulogd_wildcard_inputkeys(pi) < 0)
		return -1;

	DEBUGP("%s: db='%s' table='%s'\n", pi->id, db_ce(pi), table_ce(pi));

	return 0;
}

static int
sqlite3_start(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = (void *)pi->private;

	TAILQ_INIT(&priv->fields);

	if (sqlite3_open(db_ce(pi), &priv->dbh) != SQLITE_OK) {
		ulogd_log(ULOGD_ERROR, "SQLITE3: %s\n", sqlite3_errmsg(priv->dbh));
		return -1;
	}

	/* set the timeout so that we don't automatically fail
	   if the table is busy */
	sqlite3_busy_timeout(priv->dbh, SQLITE3_BUSY_TIMEOUT);

	/* read the fieldnames to know which values to insert */
	if (sqlite3_init_db(pi) < 0) {
		ulogd_log(ULOGD_ERROR, "SQLITE3: Could not read database fieldnames.\n");
		return -1;
	}

	/* initialize our buffer size and counter */
	priv->buffer_size = buffer_ce(pi);
	priv->buffer_curr = 0;

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

	priv->dbh = NULL;

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
	.version = VERSION,
};

static void init(void) __attribute__((constructor));

static void
init(void) 
{
	ulogd_register_plugin(&sqlite3_plugin);
}
