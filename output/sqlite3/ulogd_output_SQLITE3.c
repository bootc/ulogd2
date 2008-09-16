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

#define CFG_BUFFER_DEFAULT		10

#if 0
#define DEBUGP(x, args...)	fprintf(stderr, x, ## args)
#else
#define DEBUGP(x, args...)
#endif


struct field {
	char name[ULOGD_MAX_KEYLEN];
	struct ulogd_key *key;
	struct field *next;
};

struct sqlite3_priv {
	sqlite3 *dbh;				/* database handle we are using */
	struct field *fields;
	char *stmt;
	sqlite3_stmt *p_stmt;
	int buffer_size;
	int buffer_curr;
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

/* our main output function, called by ulogd */
static int
sqlite3_interp(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = (void *)pi->private;
	struct field *f;
	int i, ret;
	
	for (i = 0, f = priv->fields; f != NULL; f = f->next, i++) {
		struct ulogd_key *k_ret = f->key->u.source;

		if (f->key == NULL || !IS_VALID(*k_ret)) {
			sqlite3_bind_null(priv->p_stmt, i);
			continue;
		}

		switch (f->key->type) {
		case ULOGD_RET_INT8:
			sqlite3_bind_int(priv->p_stmt, i, k_ret->u.value.i8);
			break;

		case ULOGD_RET_INT16:
			sqlite3_bind_int(priv->p_stmt, i, k_ret->u.value.i16);
			break;

		case ULOGD_RET_INT32:
			sqlite3_bind_int(priv->p_stmt, i, k_ret->u.value.i32);
			break;

		case ULOGD_RET_INT64:
			sqlite3_bind_int(priv->p_stmt, i, k_ret->u.value.i64);
			break;
			
		case ULOGD_RET_UINT8:
			sqlite3_bind_int(priv->p_stmt, i, k_ret->u.value.ui8);
			break;
			
		case ULOGD_RET_UINT16:
			sqlite3_bind_int(priv->p_stmt, i, k_ret->u.value.ui16);
			break;

		case ULOGD_RET_IPADDR:
		case ULOGD_RET_UINT32:
			sqlite3_bind_int(priv->p_stmt, i, k_ret->u.value.ui32);
			break;

		case ULOGD_RET_UINT64:
			sqlite3_bind_int(priv->p_stmt, i, k_ret->u.value.ui64);
			break;

		case ULOGD_RET_BOOL:
			sqlite3_bind_int(priv->p_stmt, i, k_ret->u.value.b);
			break;

		case ULOGD_RET_STRING:
			sqlite3_bind_text(priv->p_stmt, i, k_ret->u.value.ptr,
							  strlen(k_ret->u.value.ptr), SQLITE_STATIC);
			break;

		default:
			ulogd_log(ULOGD_NOTICE, "unknown type %d for %s\n",
					  f->key->type, f->key->name);
		}
	}

	/* add row */
	if (sqlite3_step(priv->p_stmt) == SQLITE_DONE) {
		sqlite3_reset(priv->p_stmt);
		priv->buffer_curr++;
	} else {
		ulogd_log(ULOGD_ERROR, "SQL error during insert: %s\n",
				  sqlite3_errmsg(priv->dbh));
		return 1;
	}

	if (priv->buffer_curr > priv->buffer_size) {
		ret = sqlite3_exec(priv->dbh, "commit", NULL, NULL, NULL);
		if (ret != SQLITE_OK)
			ulogd_log(ULOGD_ERROR, "unable to commit rows to DB\n");

		ret = sqlite3_exec(priv->dbh, "begin deferred", NULL, NULL, NULL);
		if (ret != SQLITE_OK)
			ulogd_log(ULOGD_ERROR, "unable to begin new transaction\n");

		priv->buffer_curr = 0;
	}

	return 0;
}

#define _SQLITE3_INSERTTEMPL   "insert into X (Y) values (Z)"

/* create the static part of our insert statement */
static int
sqlite3_createstmt(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = (void *)pi->private;
	struct field *f;
	unsigned size;
	char buf[ULOGD_MAX_KEYLEN];
	char *underscore;
	char *stmt_pos;
	int col_count;
	int i;

	if (priv->stmt != NULL) {
		ulogd_log(ULOGD_NOTICE, "createstmt called, but stmt already "
				  "existing\n");	
		return 1;
	}

	/* calculate the size for the insert statement */
	size = strlen(_SQLITE3_INSERTTEMPL) + strlen(table_ce(pi));

	DEBUGP("initial size: %u\n", size);

	for (col_count = 0, f = priv->fields; f != NULL; f = f->next) {
		/* we need space for the key and a comma, and a ? */
		size += strlen(f->name) + 3;

		DEBUGP("size is now %u since adding %s\n",size,f->name);
		col_count++;
	}

	DEBUGP("there were %d columns\n",col_count);
	DEBUGP("after calc name length: %u\n",size);

	ulogd_log(ULOGD_DEBUG, "allocating %u bytes for statement\n", size);

	if ((priv->stmt = calloc(1, size)) == NULL) {
		ulogd_log(ULOGD_ERROR, "OOM!\n");
		return 1;
	}

	sprintf(priv->stmt, "insert into %s (", table_ce(pi));
	stmt_pos = priv->stmt + strlen(priv->stmt);

	for (f = priv->fields; f != NULL; f = f->next) {
		strncpy(buf, f->name, ULOGD_MAX_KEYLEN);

		while ((underscore = strchr(buf, '.')))
			*underscore = '_';

		sprintf(stmt_pos, "%s,", buf);
		stmt_pos = priv->stmt + strlen(priv->stmt);
	}

	*(stmt_pos - 1) = ')';

	sprintf(stmt_pos, " values (");
	stmt_pos = priv->stmt + strlen(priv->stmt);

	for (i = 0; i < col_count - 1; i++) {
		sprintf(stmt_pos,"?,");
		stmt_pos += 2;
	}

	sprintf(stmt_pos, "?)");
	ulogd_log(ULOGD_DEBUG, "stmt='%s'\n", priv->stmt);

	DEBUGP("about to prepare statement.\n");

	sqlite3_prepare(priv->dbh, priv->stmt, -1, &priv->p_stmt, 0);

	DEBUGP("statement prepared.\n");

	if (priv->p_stmt != NULL) {
		ulogd_log(ULOGD_ERROR, "unable to prepare statement");
		return 1;
	}

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

/* length of "select * from \0" */
#define SQLITE_SELECT_LEN 14

/* find out which columns the table has */
static int
sqlite3_get_columns(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = (void *)pi->private;
	char buf[ULOGD_MAX_KEYLEN];
	char query[SQLITE_SELECT_LEN + CONFIG_VAL_STRING_LEN] = "select * from ";
	char *underscore;
	struct field *f;
	sqlite3_stmt *schema_stmt;
	int col;

	if (priv->dbh == NULL)
		return 1;

	strncat(query, table_ce(pi), LINE_LEN);
	
	if (sqlite3_prepare(priv->dbh, query, -1, &schema_stmt, 0) != SQLITE_OK)
		return 1;

	for (col = 0; col < sqlite3_column_count(schema_stmt); col++) {
		strncpy(buf, sqlite3_column_name(schema_stmt, col), ULOGD_MAX_KEYLEN);

		/* replace all underscores with dots */
		while ((underscore = strchr(buf, '_')) != NULL)
			*underscore = '.';

		DEBUGP("field '%s' found\n", buf);

		/* prepend it to the linked list */
		if ((f = calloc(1, sizeof(struct field))) == NULL) {
			ulogd_log(ULOGD_ERROR, "OOM!\n");
			return 1;
		}
		strncpy(f->name, buf, ULOGD_MAX_KEYLEN);

		if ((f->key = ulogd_find_key(pi, buf)) == NULL)
			return -1;

		f->next = priv->fields;
		priv->fields = f;	
	}

	sqlite3_finalize(schema_stmt);

	return 0;
}

#define SQLITE3_BUSY_TIMEOUT 300

static int
sqlite3_configure(struct ulogd_pluginstance *pi,
				  struct ulogd_pluginstance_stack *stack)
{
	struct sqlite_priv *priv = (void *)pi->private;

	if (ulogd_wildcard_inputkeys(pi) < 0)
		return -1;

	config_parse_file(pi->id, pi->config_kset);

	DEBUGP("sqlite3: db='%s' table='%s'\n", db_ce(pi), table_ce(pi));

	return 0;
}

static int
sqlite3_start(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = (void *)pi->private;
	int ret;

	if (sqlite3_open(db_ce(pi), &priv->dbh) != SQLITE_OK) {
		ulogd_log(ULOGD_ERROR, "can't open the database file\n");
		return 1;
	}

	/* set the timeout so that we don't automatically fail
	   if the table is busy */
	sqlite3_busy_timeout(priv->dbh, SQLITE3_BUSY_TIMEOUT);

	/* read the fieldnames to know which values to insert */
	if (sqlite3_get_columns(pi) < 0) {
		ulogd_log(ULOGD_ERROR, "unable to get sqlite columns\n");
		return 1;
	}

	/* initialize our buffer size and counter */
	priv->buffer_size = buffer_ce(pi);
	priv->buffer_curr = 0;

	ret = sqlite3_exec(priv->dbh, "begin deferred", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		ulogd_log(ULOGD_ERROR, "can't create a new transaction\n");
		return 1;
	}

	/* create and prepare the actual insert statement */
	sqlite3_createstmt(pi);

	return 0;
}

/* give us an opportunity to close the database down properly */
static int
sqlite3_stop(struct ulogd_pluginstance *pi)
{
	struct sqlite3_priv *priv = (void *)pi->private;
	int result;

	/* free up our prepared statements so we can close the db */
	if (priv->p_stmt) {
		sqlite3_finalize(priv->p_stmt);
		DEBUGP("prepared statement finalized\n");
	}

	if (priv->dbh == NULL)
		return -1;

	/* flush the remaining insert statements to the database. */
	result = sqlite3_exec(priv->dbh, "commit", NULL, NULL, NULL);
	if (result != SQLITE_OK)
		ulogd_log(ULOGD_ERROR, "unable to commit remaining records to db");
	
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
