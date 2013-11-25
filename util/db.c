/* db.c
 *
 * ulogd helper functions for Database / SQL output plugins
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
 *
 *  Portions (C) 2001 Alex Janssen <alex@ynfonatic.de>,
 *           (C) 2005 Sven Schuster <schuster.sven@gmx.de>,
 *           (C) 2005 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *           (C) 2008,2013 Eric Leblond <eric@regit.org>
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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <inttypes.h>
#include <pthread.h>

#include <ulogd/ulogd.h>
#include <ulogd/db.h>


/* generic db layer */

static int __interp_db(struct ulogd_pluginstance *upi);

/* this is a wrapper that just calls the current real
 * interp function */
int ulogd_db_interp(struct ulogd_pluginstance *upi)
{
	struct db_instance *dbi = (struct db_instance *) &upi->private;
	return dbi->interp(upi);
}

/* no connection, plugin disabled */
static int disabled_interp_db(struct ulogd_pluginstance *upi)
{
	return 0;
}

#define SQL_INSERTTEMPL   "SELECT P(Y)"
#define SQL_VALSIZE	100

/* create the static part of our insert statement */
static int sql_createstmt(struct ulogd_pluginstance *upi)
{
	struct db_instance *mi = (struct db_instance *) upi->private;
	unsigned int size;
	unsigned int i;
	char *table = table_ce(upi->config_kset).u.string;
	char *procedure = procedure_ce(upi->config_kset).u.string;
	char *stmt_val = NULL;

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
	size += strlen(procedure);

	ulogd_log(ULOGD_DEBUG, "allocating %u bytes for statement\n", size);

	mi->stmt = (char *) malloc(size);
	if (!mi->stmt) {
		ulogd_log(ULOGD_ERROR, "OOM!\n");
		return -ENOMEM;
	}
	mi->ring.length = size + 1;

	if (strncasecmp(procedure,"INSERT", strlen("INSERT")) == 0 &&
	    (procedure[strlen("INSERT")] == '\0' ||
			procedure[strlen("INSERT")] == ' ')) {
		char buf[ULOGD_MAX_KEYLEN];
		char *underscore;

		if(procedure[6] == '\0') {
			/* procedure == "INSERT" */
			if (mi->schema)
				sprintf(mi->stmt, "insert into %s.%s (", mi->schema, table);
			else
				sprintf(mi->stmt, "insert into %s (", table);
		}
		else
			sprintf(mi->stmt, "%s (", procedure);

		stmt_val = mi->stmt + strlen(mi->stmt);

		for (i = 0; i < upi->input.num_keys; i++) {
			if (upi->input.keys[i].flags & ULOGD_KEYF_INACTIVE)
				continue;

			strncpy(buf, upi->input.keys[i].name, ULOGD_MAX_KEYLEN);	
			while ((underscore = strchr(buf, '.')))
				*underscore = '_';
			sprintf(stmt_val, "%s,", buf);
			stmt_val = mi->stmt + strlen(mi->stmt);
		}
		*(stmt_val - 1) = ')';

		sprintf(stmt_val, " values (");
	} else if (strncasecmp(procedure,"CALL", strlen("CALL")) == 0) {
		sprintf(mi->stmt, "CALL %s(", procedure);
	} else {
		sprintf(mi->stmt, "SELECT %s(", procedure);

	}

	mi->stmt_offset = strlen(mi->stmt);

	ulogd_log(ULOGD_DEBUG, "stmt='%s'\n", mi->stmt);

	return 0;
}

static int _init_db(struct ulogd_pluginstance *upi);

static void *__inject_thread(void *gdi);

int ulogd_db_configure(struct ulogd_pluginstance *upi,
			struct ulogd_pluginstance_stack *stack)
{
	struct db_instance *di = (struct db_instance *) upi->private;
	int ret;

	ulogd_log(ULOGD_NOTICE, "(re)configuring\n");

	/* First: Parse configuration file section for this instance */
	ret = config_parse_file(upi->id, upi->config_kset);
	if (ret < 0) {
		ulogd_log(ULOGD_ERROR, "error parsing config file\n");
		return ret;
	}

	/* Second: Open Database */
	ret = di->driver->open_db(upi);
	if (ret < 0) {
		ulogd_log(ULOGD_ERROR, "error in open_db\n");
		return ret;
	}

	/* Third: Determine required input keys for given table */
	ret = di->driver->get_columns(upi);
	if (ret < 0)
		ulogd_log(ULOGD_ERROR, "error in get_columns\n");
	
	/* Close database, since ulogd core could just call configure
	 * but abort during input key resolving routines.  configure
	 * doesn't have a destructor... */
	di->driver->close_db(upi);

	INIT_LLIST_HEAD(&di->backlog);
	di->backlog_memusage = 0;

	di->ring.size = ringsize_ce(upi->config_kset).u.value;
	di->backlog_memcap = backlog_memcap_ce(upi->config_kset).u.value;

	if (di->ring.size && di->backlog_memcap) {
		ulogd_log(ULOGD_ERROR, "Ring buffer has precedence over backlog\n");
		di->backlog_memcap = 0;
	} else if (di->backlog_memcap > 0) {
		di->backlog_oneshot = backlog_oneshot_ce(upi->config_kset).u.value;
		if (di->backlog_oneshot <= 2) {
			ulogd_log(ULOGD_ERROR,
				  "backlog_oneshot_requests must be > 2 to hope"
				  " cleaning. Setting it to 3.\n");
			di->backlog_oneshot = 3;
		}
		di->backlog_full = 0;
	}

	return ret;
}

int ulogd_db_start(struct ulogd_pluginstance *upi)
{
	struct db_instance *di = (struct db_instance *) upi->private;
	int ret;
	unsigned int i;

	ulogd_log(ULOGD_NOTICE, "starting\n");

	ret = di->driver->open_db(upi);
	if (ret < 0)
		return ret;

	ret = sql_createstmt(upi);
	if (ret < 0)
		goto db_error;

	if (di->ring.size > 0) {
		/* allocate */
		di->ring.ring = calloc(di->ring.size, sizeof(char) * di->ring.length);
		if (di->ring.ring == NULL) {
			ret = -1;
			goto db_error;
		}
		di->ring.wr_place = di->ring.ring;
		ulogd_log(ULOGD_NOTICE,
			  "Allocating %d elements of size %d for ring\n",
			  di->ring.size, di->ring.length);
		/* init start of query for each element */
		for(i = 0; i < di->ring.size; i++) {
			strncpy(di->ring.ring + di->ring.length * i + 1,
				di->stmt,
				strlen(di->stmt));
		}
		/* init cond & mutex */
		ret = pthread_cond_init(&di->ring.cond, NULL);
		if (ret != 0)
			goto alloc_error;
		ret = pthread_mutex_init(&di->ring.mutex, NULL);
		if (ret != 0)
			goto cond_error;
		/* create thread */
		ret = pthread_create(&di->db_thread_id, NULL, __inject_thread, upi);
		if (ret != 0)
			goto mutex_error;
	}

	di->interp = &_init_db;

	return ret;

mutex_error:
	pthread_mutex_destroy(&di->ring.mutex);
cond_error:
	pthread_cond_destroy(&di->ring.cond);
alloc_error:
	free(di->ring.ring);
db_error:
	di->driver->close_db(upi);
	return ret;
}

static int ulogd_db_instance_stop(struct ulogd_pluginstance *upi)
{
	struct db_instance *di = (struct db_instance *) upi->private;
	ulogd_log(ULOGD_NOTICE, "stopping\n");
	di->driver->close_db(upi);

	/* try to free the buffer for insert statement */
	if (di->stmt) {
		free(di->stmt);
		di->stmt = NULL;
	}
	if (di->ring.size > 0) {
		pthread_cancel(di->db_thread_id);
		free(di->ring.ring);
		pthread_cond_destroy(&di->ring.cond);
		pthread_mutex_destroy(&di->ring.mutex);
		di->ring.ring = NULL;
	}
	return 0;
}

int ulogd_db_stop(struct ulogd_pluginstance *upi)
{
	ulogd_db_instance_stop(upi);

	/* try to free our dynamically allocated input key array */
	if (upi->input.keys) {
		free(upi->input.keys);
		upi->input.keys = NULL;
	}

	return 0;
}


static int _init_reconnect(struct ulogd_pluginstance *upi)
{
	struct db_instance *di = (struct db_instance *) upi->private;

	if (reconnect_ce(upi->config_kset).u.value) {
		if (time(NULL) < di->reconnect)
			return -1;
		di->reconnect = time(NULL);
		if (di->reconnect != TIME_ERR) {
			ulogd_log(ULOGD_ERROR, "no connection to database, "
				  "attempting to reconnect after %u seconds\n",
				  reconnect_ce(upi->config_kset).u.value);
			di->reconnect += reconnect_ce(upi->config_kset).u.value;
			di->interp = &_init_db;
			return -1;
		}
	}

	/* Disable plugin permanently */
	ulogd_log(ULOGD_ERROR, "permanently disabling plugin\n");
	di->interp = &disabled_interp_db;
	
	return 0;
}

static void __format_query_db(struct ulogd_pluginstance *upi, char *start)
{
	struct db_instance *di = (struct db_instance *) &upi->private;

	unsigned int i;

	char *stmt_ins = start + di->stmt_offset;

	for (i = 0; i < upi->input.num_keys; i++) {
		struct ulogd_key *res = upi->input.keys[i].u.source;

		if (upi->input.keys[i].flags & ULOGD_KEYF_INACTIVE)
			continue;

		if (!res)
			ulogd_log(ULOGD_NOTICE, "no source for `%s' ?!?\n",
				  upi->input.keys[i].name);

		if (!res || !IS_VALID(*res)) {
			/* no result, we have to fake something */
			stmt_ins += sprintf(stmt_ins, "NULL,");
			continue;
		}

		switch (res->type) {
		case ULOGD_RET_INT8:
			sprintf(stmt_ins, "%d,", res->u.value.i8);
			break;
		case ULOGD_RET_INT16:
			sprintf(stmt_ins, "%d,", res->u.value.i16);
			break;
		case ULOGD_RET_INT32:
			sprintf(stmt_ins, "%d,", res->u.value.i32);
			break;
		case ULOGD_RET_INT64:
			sprintf(stmt_ins, "%" PRId64 ",", res->u.value.i64);
			break;
		case ULOGD_RET_UINT8:
			sprintf(stmt_ins, "%u,", res->u.value.ui8);
			break;
		case ULOGD_RET_UINT16:
			sprintf(stmt_ins, "%u,", res->u.value.ui16);
			break;
		case ULOGD_RET_IPADDR:
			/* fallthrough when logging IP as u_int32_t */
		case ULOGD_RET_UINT32:
			sprintf(stmt_ins, "%u,", res->u.value.ui32);
			break;
		case ULOGD_RET_UINT64:
			sprintf(stmt_ins, "%" PRIu64 ",", res->u.value.ui64);
			break;
		case ULOGD_RET_BOOL:
			sprintf(stmt_ins, "'%d',", res->u.value.b);
			break;
		case ULOGD_RET_STRING:
			*(stmt_ins++) = '\'';
			if (res->u.value.ptr) {
				stmt_ins +=
				di->driver->escape_string(upi, stmt_ins,
							  res->u.value.ptr,
							strlen(res->u.value.ptr));
			}
			sprintf(stmt_ins, "',");
			break;
		case ULOGD_RET_RAWSTR:
			sprintf(stmt_ins, "%s,", (char *) res->u.value.ptr);
			break;
		case ULOGD_RET_RAW:
			ulogd_log(ULOGD_NOTICE,
				"Unsupported RAW type is unsupported in SQL output");
		default:
			ulogd_log(ULOGD_NOTICE,
				"unknown type %d for %s\n",
				res->type, upi->input.keys[i].name);
			break;
		}
		stmt_ins = start + strlen(start);
	}
	*(stmt_ins - 1) = ')';
}

static int __add_to_backlog(struct ulogd_pluginstance *upi, const char *stmt, unsigned int len)
{
	struct db_instance *di = (struct db_instance *) &upi->private;
	struct db_stmt *query;

	/* check if we are using backlog */
	if (di->backlog_memcap == 0)
		return 0;

	/* check len against backlog */
	if (len + di->backlog_memusage > di->backlog_memcap) {
		if (di->backlog_full == 0)
			ulogd_log(ULOGD_ERROR,
				  "Backlog is full starting to reject events.\n");
		di->backlog_full = 1;
		return -1;
	}

	query = malloc(sizeof(struct db_stmt));
	if (query == NULL)
		return -1;

	query->stmt = strndup(stmt, len);
	query->len = len;

	if (query->stmt == NULL) {
		free(query);
		return -1;
	}

	di->backlog_memusage += len + sizeof(struct db_stmt);
	di->backlog_full = 0;

	llist_add_tail(&query->list, &di->backlog);

	return 0;
}

static int _init_db(struct ulogd_pluginstance *upi)
{
	struct db_instance *di = (struct db_instance *) upi->private;

	if (di->reconnect && di->reconnect > time(NULL)) {
		/* store entry to backlog if it is active */
		if (di->backlog_memcap && !di->backlog_full) {
			__format_query_db(upi, di->stmt);
			__add_to_backlog(upi, di->stmt,
						strlen(di->stmt));
		}
		return 0;
	}

	if (di->driver->open_db(upi)) {
		ulogd_log(ULOGD_ERROR, "can't establish database connection\n");
		if (di->backlog_memcap && !di->backlog_full) {
			__format_query_db(upi, di->stmt);
			__add_to_backlog(upi, di->stmt, strlen(di->stmt));
		}
		return _init_reconnect(upi);
	}

	/* enable 'real' logging */
	di->interp = &__interp_db;

	di->reconnect = 0;

	/* call the interpreter function to actually write the
	 * log line that we wanted to write */
	return __interp_db(upi);
}

static int __treat_backlog(struct ulogd_pluginstance *upi)
{
	struct db_instance *di = (struct db_instance *) &upi->private;
	int i = di->backlog_oneshot;
	struct db_stmt *query;
	struct db_stmt *nquery;

	/* Don't try reconnect before timeout */
	if (di->reconnect && di->reconnect > time(NULL))
		return 0;

	llist_for_each_entry_safe(query, nquery, &di->backlog, list) {
		if (di->driver->execute(upi, query->stmt, query->len) < 0) {
			/* error occur, database connexion need to be closed */
			di->driver->close_db(upi);
			return _init_reconnect(upi);
		} else {
			di->backlog_memusage -= query->len + sizeof(struct db_stmt);
			llist_del(&query->list);
			free(query->stmt);
			free(query);
		}
		if (--i < 0)
			break;
	}
	return 0;
}

static int __add_to_ring(struct ulogd_pluginstance *upi, struct db_instance *di)
{
	if (*di->ring.wr_place == RING_QUERY_READY) {
		if (di->ring.full == 0) {
			ulogd_log(ULOGD_ERROR, "No place left in ring\n");
			di->ring.full = 1;
		}
		return ULOGD_IRET_OK;
	} else if (di->ring.full) {
		ulogd_log(ULOGD_NOTICE, "Recovered some place in ring\n");
		di->ring.full = 0;
	}
	__format_query_db(upi, di->ring.wr_place + 1);
	*di->ring.wr_place = RING_QUERY_READY;
	pthread_cond_signal(&di->ring.cond);
	di->ring.wr_item ++;
	di->ring.wr_place += di->ring.length;
	if (di->ring.wr_item == di->ring.size) {
		di->ring.wr_item = 0;
		di->ring.wr_place = di->ring.ring;
	}
	return ULOGD_IRET_OK;
}

/* our main output function, called by ulogd */
static int __interp_db(struct ulogd_pluginstance *upi)
{
	struct db_instance *di = (struct db_instance *) &upi->private;

	if (di->ring.size)
		return __add_to_ring(upi, di);

	__format_query_db(upi, di->stmt);

	/* if backup log is not empty we add current query to it */
	if (!llist_empty(&di->backlog)) {
		int ret = __add_to_backlog(upi, di->stmt, strlen(di->stmt));
		if (ret == 0)
			return __treat_backlog(upi);
		else {
			ret = __treat_backlog(upi);
			if (ret)
				return ret;
			/* try adding once the data to backlog */
			return __add_to_backlog(upi, di->stmt, strlen(di->stmt));
		}
	}

	if (di->driver->execute(upi, di->stmt, strlen(di->stmt)) < 0) {
		__add_to_backlog(upi, di->stmt, strlen(di->stmt));
		/* error occur, database connexion need to be closed */
		di->driver->close_db(upi);
		return _init_reconnect(upi);
	}

	return 0;
}

static int __loop_reconnect_db(struct ulogd_pluginstance * upi) {
	struct db_instance *di = (struct db_instance *) &upi->private;

	di->driver->close_db(upi);
	while (1) {
		if (di->driver->open_db(upi)) {
			sleep(1);
		} else {
			return 0;
		}
	}
	return 0;
}

static void *__inject_thread(void *gdi)
{
	struct ulogd_pluginstance *upi = (struct ulogd_pluginstance *) gdi;
	struct db_instance *di = (struct db_instance *) &upi->private;
	char *wr_place;

	wr_place = di->ring.ring;
	pthread_mutex_lock(&di->ring.mutex);
	while(1) {
		/* wait cond */
		pthread_cond_wait(&di->ring.cond, &di->ring.mutex);
		while (*wr_place == RING_QUERY_READY) {
			if (di->driver->execute(upi, wr_place + 1,
						strlen(wr_place + 1)) < 0) {
				if (__loop_reconnect_db(upi) != 0) {
					/* loop has failed on unrecoverable error */
					ulogd_log(ULOGD_ERROR,
						  "permanently disabling plugin\n");
					di->interp = &disabled_interp_db;
					return NULL;
				}
			}
			*wr_place = RING_NO_QUERY;
			di->ring.rd_item++;
			if (di->ring.rd_item == di->ring.size) {
				di->ring.rd_item = 0;
				wr_place = di->ring.ring;
			} else
				wr_place += di->ring.length;
		}
	}

	return NULL;
}


void ulogd_db_signal(struct ulogd_pluginstance *upi, int signal)
{
	struct db_instance *di = (struct db_instance *) &upi->private;
	switch (signal) {
	case SIGHUP:
		if (!di->ring.size) {
			/* reopen database connection */
			ulogd_db_instance_stop(upi);
			ulogd_db_start(upi);
		} else
			ulogd_log(ULOGD_ERROR,
				  "No SIGHUP handling if ring buffer is used\n");
		break;
	default:
		break;
	}
}
