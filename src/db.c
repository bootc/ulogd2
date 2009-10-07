/* db.c
 *
 * ulogd helper functions for Database / SQL output plugins
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
 *
 *  Portions (C) 2001 Alex Janssen <alex@ynfonatic.de>,
 *           (C) 2005 Sven Schuster <schuster.sven@gmx.de>,
 *           (C) 2005 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
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
 */
#include "config.h"
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/plugin.h>
#include <ulogd/db.h>
#include <time.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define TOK_INVAL		-1
#define TOK_NONE		0
#define TOK_NAME		1
#define TOK_NUM			2
#define TOK_COMMA		','
#define TOK_COLON		':'

#define KEYMAP_LEX_LEN	32

static char keymap_lexbuf[KEYMAP_LEX_LEN];


/* generic row handling */

struct db_row *
db_row_new(struct ulogd_pluginstance *pi)
{
	struct db_instance *di = upi_priv(pi);
	struct db_row *row;
	size_t size;

	BUG_ON(!di->num_cols);

	size = sizeof(struct db_row) + di->num_cols * sizeof(struct ulogd_value);
	if ((row = malloc(size)) == NULL) {
		upi_log(pi, ULOGD_FATAL, "out of memory\n");
		return NULL;
	}

	/* the key values don't need to be set to zero */
	memset(row, 0, sizeof(*row));

	return row;
}

static void
__db_row_del(struct ulogd_pluginstance *pi, struct db_row *row)
{
	pr_fn_debug("pi=%p row=%p\n", pi, row);

	if (row) {
		struct db_instance *di = upi_priv(pi);

		free(row);

		di->num_rows--;
	}
}

void
db_row_del(struct ulogd_pluginstance *pi, struct db_row *row)
{
	pr_fn_debug("pi=%p row=%p\n", pi, row);

	llist_del(&row->link);

	__db_row_del(pi, row);
}

int
db_row_add(struct ulogd_pluginstance *pi, struct db_row *row)
{
	struct db_instance *di = upi_priv(pi);

	pr_fn_debug("pi=%p row=%p\n", pi, row);

	if (di->max_backlog && di->num_rows >= di->max_backlog) {
		if (!di->overlimit_msg) {
			upi_log(pi, ULOGD_ERROR, "over backlog limit, dropping rows\n");
			di->overlimit_msg = 1;
		}

		__db_row_del(pi, row);

		return -1;
	}

	llist_add(&row->link, &di->rows);

	di->num_rows++;

	return 0;
}

/**
 * Commit loop for passing rows to database.
 *
 * Does much (but currently not all) of the list handling after
 * finishing (both successfully and unsuccessfully).  On success
 * the committed rows are deleted.
 *
 * @arg pi		Plugin instance to use.
 * @return Number of rows committed.
 */
static int
__db_commit(struct ulogd_pluginstance *pi)
{
	struct db_instance *di = upi_priv(pi);
	struct llist_head *curr, *tmp;
	struct db_row *row;
	int max_commit, rows;

	pr_fn_debug("pi=%p\n", pi);

	if (llist_empty(&di->rows))
		return 0;

	/* Limit number of rows to commit.  Note that currently three times
	   buffer_size is a bit arbitrary and therefore might be adjusted in
	   the future. */
	max_commit = max(3 * di->buffer_size, 1024);

	if ((rows = di->driver->commit(pi, max_commit)) < 0) {
		upi_log(pi, ULOGD_DEBUG, "commit failed\n");
		goto err_rollback;
	}

	llist_for_each_safe(curr, tmp, &di->rows_committed) {
		row = llist_entry(curr, struct db_row, link);

		db_row_del(pi, row);
	}

	upi_log(pi, ULOGD_DEBUG, "rows=%d commited=%d\n", di->num_rows, rows);

	return rows;


err_rollback:
	llist_for_each_prev_safe(curr, tmp, &di->rows_committed)
		llist_move_tail(curr, &di->rows);

	return rows;
}

static int
db_alloc_columns(struct db_instance *di, size_t cols)
{
	if (!di)
		return -1;

	di->col = calloc(cols, sizeof(struct db_column));
	if (!di->col) {
		ulogd_log(ULOGD_FATAL, "%s: out of memory\n", __func__);
		return -1;
	}

	return 0;
}

static void
db_free_columns(struct db_instance *di)
{
	if (di) {
		free(di->col);
		di->col = NULL;
	}
}

/**
 * Periodic database timer, reponsible for committing database rows.
 *
 * @arg t		Timer to use.
 */
static void
db_timer_cb(struct ulogd_timer *t)
{
	struct ulogd_pluginstance *pi = t->data;
	struct db_instance *di = upi_priv(pi);
	int rows;

	pr_fn_debug("timer=%p\n", t);

	if (pi->state == PsStarted) {
		if (di->num_rows == 0)
			return;

		if ((rows = __db_commit(pi)) < 0) {
			ulogd_unregister_timer(&di->timer);
			ulogd_upi_error(pi, rows);

			return;
		}
	}
}

#define SQL_INSERTTEMPL   "insert into X (Y) values (Z)"
#define SQL_VALSIZE	100

/* create the static part of our insert statement */
static int
sql_createstmt(struct ulogd_pluginstance *upi)
{
	struct db_instance *mi = upi_priv(upi);
	unsigned int size;
	char *table = table_ce(upi);
	int i;

	pr_debug("%s: upi=%p\n", __func__, upi);

	if (mi->stmt)
		free(mi->stmt);

	/* caclulate the size for the insert statement */
	size = strlen(SQL_INSERTTEMPL) + strlen(table);

	for (i = 0; i < upi->input.num_keys; i++) {
		if (upi->input.keys[i].flags & ULOGD_KEYF_INACTIVE)
			continue;
		/* we need space for the key and a comma, as well as
		 * enough space for the values */
		size += strlen(upi->input.keys[i].name) + 1 + SQL_VALSIZE;
	}

	upi_log(upi, ULOGD_DEBUG, "allocating %u bytes for statement\n", size);

	mi->stmt = (char *) malloc(size);
	if (!mi->stmt) {
		upi_log(upi, ULOGD_FATAL, "out of memory\n");
		return -ENOMEM;
	}

	if (mi->schema)
		sprintf(mi->stmt, "insert into %s.%s (", mi->schema, table);
	else
		sprintf(mi->stmt, "insert into %s (", table);

	mi->stmt_val = mi->stmt + strlen(mi->stmt);

	for (i = 0; i < upi->input.num_keys; i++) {
		if (upi->input.keys[i].flags & ULOGD_KEYF_INACTIVE)
			continue;

		strncpy(mi->stmt_val, upi->input.keys[i].name, ULOGD_MAX_KEYLEN);
		strntr(mi->stmt_val, '.', '_');

		mi->stmt_val += strlen(upi->input.keys[i].name);

		if (i + 1 < upi->input.num_keys)
			*(mi->stmt_val)++ = ',';
	}

	*(mi->stmt_val)++ = ')';
	mi->stmt_val += sprintf(mi->stmt_val, " values (");

	upi_log(upi, ULOGD_DEBUG, "stmt='%s'\n", mi->stmt);

	return 0;
}

static int
check_driver(struct ulogd_pluginstance *pi)
{
	const struct db_instance *di = upi_priv(pi);
	const struct db_driver *drv = di->driver;

	if (!drv->open_db || !drv->close_db || !drv->commit)
		return -1;

	return 0;
}

static int
keymap_lexer(const char **in)
{
	char *out = keymap_lexbuf, *end = keymap_lexbuf + KEYMAP_LEX_LEN - 1;
	int tok = TOK_INVAL;

	if (!in || !(*in)[0])
		return TOK_NONE;

	if (**in && isalpha(**in)) {
		*out++ = *(*in)++;
		while (**in && out < end && (isalnum(**in) || **in == '.'))
			*out++ = *(*in)++;
		tok = TOK_NAME;
	} else if (**in && **in >= '0' && **in <= '9' && out < end) {
		while (**in && **in >= '0' && **in <= '9' && out < end)
			*out++ = *(*in)++;
		tok = TOK_NUM;
	} else if (**in == ',' || **in == ':') {
		tok = *(*in)++;
		return tok;
	}

	*out = '\0';

	return tok;
}

/**
 * Determine number of keys and database columns in keymap
 *
 * @arg str		keymap string to parse
 * @arg cols	Number of database columns used
 *
 * @return number of keys on success, <0 on error
 */
static int
keymap_check(const char *str, int *cols)
{
	int tok, state = 0, num_keys = 0;

	if (!str || !cols)
		return -1;

	*cols = 0;
	while ((tok = keymap_lexer(&str)) != TOK_NONE) {
		if (tok == TOK_INVAL)
			goto err_inval;

		switch (state) {
		case 0:
			if (tok != TOK_NAME)
				goto err_inval;
			state++;
			break;

		case 1:
			if (tok != TOK_COLON)
				goto err_inval;
			state++;
			break;

		case 2:
			if (tok != TOK_NUM)
				goto err_inval;
			num_keys++;
			*cols = max(*cols, atoi(keymap_lexbuf) + 1);
			state++;
			break;

		case 3:
			if (tok == TOK_NONE)
				return 0;
			else if (tok == TOK_COMMA)
				state = 0;
			break;

		default:
			BUG();
		}
	}

	return num_keys;

err_inval:
	ulogd_log(ULOGD_FATAL, "invalid keymap: %s\n", str);
	return -1;
}

/**
 * Map ulogd keys to database columns by keymap
 *
 * @arg str		String to parse
 * @arg set		Pointer to array of ulogd keys
 *
 * @return 0 on success, <0 on error
 */
int
keymap_map_keys(const char *str, struct ulogd_keyset *set,
				struct db_instance *di)
{
	int tok, state = 0, keyno = 0, col;

	if (!str || !set || !di) {
		ulogd_log(ULOGD_ERROR, "%s: %s\n", __func__, strerror(EINVAL));
		return -1;
	}

	BUG_ON(!set->keys || !set->num_keys);

	while ((tok = keymap_lexer(&str)) != TOK_NONE) {
		if (tok == TOK_INVAL)
			goto err_inval;

		switch (state) {
		case 0:
			if (tok != TOK_NAME)
				goto err_inval;
			xstrncpy(set->keys[keyno].name, keymap_lexbuf, ULOGD_MAX_KEYLEN);
			state++;
			break;

		case 1:
			if (tok != TOK_COLON)
				goto err_inval;
			state++;
			break;

		case 2:
			if (tok != TOK_NUM)
				goto err_inval;
			BUG_ON(!set->keys[keyno].name);
			col = atoi(keymap_lexbuf);
			set->keys[keyno].col = &di->col[col];
			ulogd_log(ULOGD_DEBUG, "db: key%d ('%s') maps to col%d\n",
					  keyno, set->keys[keyno].name, col);
			keyno++;
			state++;
			break;

		case 3:
			if (tok == TOK_NONE)
				return 0;
			else if (tok == TOK_COMMA)
				state = 0;
			break;

		default:
			BUG();
		}
	}

	return 0;

err_inval:
	ulogd_log(ULOGD_FATAL, "invalid keymap: %s\n", str);
	return -1;
}

/*
 * Mapy ulogd keys to database columns
 */
static int
db_map_keys(struct ulogd_pluginstance *pi)
{
	struct db_instance *di = upi_priv(pi);
	int ret;

	if ((ret = di->driver->get_columns(pi)) < 0)
		return -1;

	/* TODO map to database columns */

	return 0;
}

static int
db_open(struct ulogd_pluginstance *pi)
{
	struct db_instance *di = upi_priv(pi);

	if (!(di->flags & DB_F_OPEN)) {
		int ret;

		if ((ret = di->driver->open_db(pi)) < 0)
			return ret;

		di->flags |= DB_F_OPEN;
	}

	return ULOGD_IRET_OK;
}

static int
db_close(struct ulogd_pluginstance *pi)
{
	struct db_instance *di = upi_priv(pi);

	if (di->flags & DB_F_OPEN) {
		di->flags &= ~DB_F_OPEN;

		return di->driver->close_db(pi);
	}

	return ULOGD_IRET_OK;
}

/**
 * Map ulogd keys to database columns.
 */
int
ulogd_db_map_keys(struct ulogd_pluginstance *pi)
{
	struct db_instance *di = upi_priv(pi);
	struct ulogd_keyset *set = &pi->input;
	char *keymap = keymap_ce(pi);

	if (keymap) {
		if ((set->num_keys = keymap_check(keymap, &di->num_cols)) < 0)
			return -1;

		if ((set->keys = ulogd_alloc_keyset(set->num_keys)) == NULL)
			return -1;

		if (db_alloc_columns(di, di->num_cols) < 0)
			goto err_free;

		if (keymap_map_keys(keymap, set, di) < 0)
			goto err_free;
	} else {
		if (db_map_keys(pi) < 0)
			return -1;
	}

	return 0;

err_free:
	db_free_columns(di);
	ulogd_free_keyset(set);
	return -1;
}

int
ulogd_db_configure(struct ulogd_pluginstance *upi)
{
	struct db_instance *di = upi_priv(upi);
	int ret;

	if (!!keymap_ce(upi) != !!insert_ce(upi)) {
		upi_log(upi, ULOGD_FATAL, "'keymap' requires 'insert'.\n");
		return ULOGD_IRET_ERR;
	}

	if (blackhole_ce(upi))
		return ULOGD_IRET_OK;

	if (check_driver(upi) < 0)
		return ULOGD_IRET_ERR;

	if (disable_ce(upi)) {
		upi_log(upi, ULOGD_INFO, "disabled in config\n");

		return ULOGD_IRET_OK;
	}

	di->buffer_size = db_buffer_ce(upi);
	di->max_backlog = 1024 * di->buffer_size;

	if (insert_ce(upi))
		di->stmt = strdup(insert_ce(upi));

	if ((ret = db_open(upi)) < 0)
		goto err_free;

	if ((ret = ulogd_db_map_keys(upi)) < 0)
		goto err_close;

	ulogd_init_timer(&di->timer, 1 SEC, db_timer_cb, upi, TIMER_F_PERIODIC);

	return 0;

err_free:
	free(di->stmt);
	di->stmt = NULL;
err_close:
	db_close(upi);
	return ret;
}

int
ulogd_db_start(struct ulogd_pluginstance *upi)
{
	struct db_instance *di = upi_priv(upi);
	int ret;

	pr_fn_debug("pi=%p\n", upi);

	if (blackhole_ce(upi)) {
		upi_log(upi, ULOGD_INFO, "running in blackhole mode");
		return ULOGD_IRET_OK;
	}

	if ((ret = db_open(upi)) < 0)
		return ret;

	if (db_has_prepare(di)) {
		BUG_ON(!di->stmt);
		if (di->driver->prepare(upi) < 0) {
			upi_log(upi, ULOGD_FATAL, "prepare failed\n");
			goto err_close;
		}
	} else if (sql_createstmt(upi) < 0)
		goto err_close;

	INIT_LLIST_HEAD(&di->rows);
	INIT_LLIST_HEAD(&di->rows_committed);
	di->num_rows = 0;

	if (ulogd_register_timer(&di->timer) < 0)
		return -1;

	return 0;

err_close:
	db_close(upi);
	return -1;
}

int
ulogd_db_stop(struct ulogd_pluginstance *upi)
{
	struct db_instance *di = upi_priv(upi);

	pr_debug("%s: upi=%p\n", __func__, upi);

	if (blackhole_ce(upi))
		return ULOGD_IRET_OK;

	db_close(upi);
	upi_log(upi, ULOGD_INFO, "database connection closed\n");

	/* try to free our dynamically allocated input key array */
	if (upi->input.keys) {
		upi->input.num_keys = 0;

		free(upi->input.keys);
		upi->input.keys = NULL;
	}

	ulogd_unregister_timer(&di->timer);

	return 0;
}

int
ulogd_db_signal(struct ulogd_pluginstance *upi, int signal)
{
	switch (signal) {
	case SIGHUP:
		/* reopen database connection */
		ulogd_db_stop(upi);
		ulogd_db_start(upi);
		break;
	default:
		break;
	}

	return 0;
}

int
ulogd_db_interp(struct ulogd_pluginstance *pi, unsigned *flags)
{
	struct db_instance *di = upi_priv(pi);
	struct ulogd_key *key, *in = pi->input.keys;
	struct db_row *row;
	int i, ret = ULOGD_IRET_OK;

	if (blackhole_ce(pi))
		return ULOGD_IRET_OK;

	for (i = 0; i < pi->input.num_keys; i++) {
		key = &in[i];

		if (!key_src_valid(key))
			continue;

		BUG_ON(!key->col);
		BUG_ON(key->col->key);

		key->col->key = key_src(key);
	}

	if ((row = db_row_new(pi)) == NULL)
		return ULOGD_IRET_ERR;

	/*
	 * iterate over the database columns and copy key values, zero out
	 * everything else.
	 */
	for (i = 0; i < di->num_cols; i++) {
		key = di->col[i].key;

		if (!key)
			memset(&row->value[i], 0, sizeof(struct ulogd_value));
		else
			memcpy(&row->value[i], &key->u.val, sizeof(struct ulogd_value));
	}

	/* reset key pointers */
	memset(di->col, 0, di->num_cols * sizeof(struct db_column));

	if (db_row_add(pi, row) < 0)
		return ULOGD_IRET_OK;

	if (di->num_rows >= di->buffer_size && pi->state == PsStarted)
		ret = __db_commit(pi);

	return ret;
}
