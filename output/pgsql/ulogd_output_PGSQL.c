/*
 * ulogd_output_PGSQL.c
 *
 * ulogd output plugin for logging to a PGSQL database
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org> 
 * This software is distributed under the terms of GNU GPL 
 * 
 * This plugin is based on the MySQL plugin made by Harald Welte.
 * The support PostgreSQL were made by Jakab Laszlo.
 *
 * Holger Eitzenberger <holger@eitzenberger.org>  Astaro AG 2008
 */
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/plugin.h>
#include <ulogd/db.h>
#include <libpq-fe.h>


struct pgsql_priv {
	struct db_instance db_inst;	/* must come first */
	PGconn *dbh;				/* database handle */
	PGresult *pgres;
	unsigned char pgsql_have_schemas;

	char *param_val[20];
};


/* our configuration directives */
static struct config_keyset pgsql_kset = {
	.num_ces = DB_CE_NUM + 6,
	.ces = {
		DB_CES,
		{ 
			.key = "db", 
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_MANDATORY,
		},
		{
			.key = "host", 
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
		{ 
			.key = "user", 
			.type = CONFIG_TYPE_STRING,
		},
		{
			.key = "pass", 
			.type = CONFIG_TYPE_STRING,
		},
		{
			.key = "port",
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
		},
		{
			.key = "schema", 
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u.string = "public",
		},
	},
};
#define db_ce(x)	(x->ces[DB_CE_NUM+0])
#define host_ce(x)	(x->ces[DB_CE_NUM+1])
#define user_ce(x)	(x->ces[DB_CE_NUM+2])
#define pass_ce(x)	(x->ces[DB_CE_NUM+3])
#define port_ce(x)	(x->ces[DB_CE_NUM+4])
#define schema_ce(x)	(x->ces[DB_CE_NUM+5])

static int
__pgsql_err(struct ulogd_pluginstance *pi, int *pgret)
{
	struct pgsql_priv *priv = upi_priv(pi);
	int __pgret;

	if (priv->pgres == NULL) {
		ulogd_log(ULOGD_FATAL, "%s: command failed\n", pi->id);
		return -1;
	}

	__pgret = PQresultStatus(priv->pgres);
	if (pgret != NULL)
		*pgret = __pgret;

	if (__pgret != PGRES_COMMAND_OK && __pgret != PGRES_TUPLES_OK)
		ulogd_log(ULOGD_ERROR, "%s: %s\n", pi->id, PQerrorMessage(priv->dbh));

	switch (__pgret) {
	case PGRES_COMMAND_OK:
		PQclear(priv->pgres);
		/* fall-through */
	case PGRES_TUPLES_OK:
		break;					/* caller has to call PQclear() */

	case PGRES_EMPTY_QUERY:
	case PGRES_NONFATAL_ERROR:
	case PGRES_BAD_RESPONSE:
	case PGRES_FATAL_ERROR:
		PQclear(priv->pgres);
		return -1;

	case PGRES_COPY_OUT:
	case PGRES_COPY_IN:
	default:
		PQclear(priv->pgres);
		abort();					/* unsupported */
	}

	return 0;
}

#define PGSQL_HAVE_NAMESPACE_TEMPLATE 			\
	"SELECT nspname FROM pg_namespace n WHERE n.nspname='%s'"

/**
 * Execute a simple SQL command on the database.  PGres is freed
 * automatically if the return value is not %PGRES_TUPLES_OK, in which
 * case it has to be cleared by the caller.
 *
 * An empty command is considered an error and reported as such.
 *
 * @arg pi     Plugin instance to use.
 * @arg cmd    SQL command to execute.
 * @return >=0 if OK, <0 on error.
 */
static int
__pgsql_exec(struct ulogd_pluginstance *pi, const char *cmd, int *pgret)
{
	struct pgsql_priv *priv = upi_priv(pi);

	if (cmd == NULL)
		return -1;

	priv->pgres = PQexec(priv->dbh, cmd);

	return __pgsql_err(pi, pgret);
}

/* Determine if server support schemas */
static int
pgsql_namespace(struct ulogd_pluginstance *upi)
{
	struct pgsql_priv *pi = upi_priv(upi);
	char pgbuf[strlen(PGSQL_HAVE_NAMESPACE_TEMPLATE) + 
			   strlen(schema_ce(upi->config_kset).u.string) + 1];

	pr_fn_debug("pi=%p\n", pi);

	if (pi->dbh == NULL)
		return -1;

	sprintf(pgbuf, PGSQL_HAVE_NAMESPACE_TEMPLATE,
			schema_ce(upi->config_kset).u.string);
	ulogd_log(ULOGD_DEBUG, "%s\n", pgbuf);

	if (__pgsql_exec(upi, pgbuf, NULL) < 0)
		return ULOGD_IRET_AGAIN;

	PQclear(pi->pgres);

	pi->db_inst.schema = schema_ce(upi->config_kset).u.string;

	ulogd_log(ULOGD_DEBUG, "%s: using schema %s\n", upi->id,
			  schema_ce(upi->config_kset).u.string);
	
	return 0;
}

#define PGSQL_GETCOLUMN_TEMPLATE							   \
	"SELECT  a.attname FROM pg_class c, pg_attribute a WHERE "			\
	"c.relname ='%s' AND a.attnum>0 AND a.attrelid=c.oid ORDER BY a.attnum"

#define PGSQL_GETCOLUMN_TEMPLATE_SCHEMA							  \
	"SELECT a.attname FROM pg_attribute a, pg_class c LEFT JOIN "	\
	"pg_namespace n ON c.relnamespace=n.oid WHERE c.relname ='%s' " \
	"AND n.nspname='%s' AND a.attnum>0 AND a.attrelid=c.oid "		\
	"AND a.attisdropped=FALSE ORDER BY a.attnum"

/* find out which columns the table has */
static int
pgsql_get_columns(struct ulogd_pluginstance *upi)
{
	struct pgsql_priv *pi = upi_priv(upi);
	char pgbuf[strlen(PGSQL_GETCOLUMN_TEMPLATE_SCHEMA)
			   + strlen(table_ce(upi->config_kset).u.string)
			   + strlen(pi->db_inst.schema) + 2];
	int i, k;

	pr_fn_debug("pi=%p\n", pi);

	if (!pi->dbh) {
		ulogd_log(ULOGD_ERROR, "no database handle\n");
		return 1;
	}

	if (pi->db_inst.schema) {
		snprintf(pgbuf, sizeof(pgbuf)-1,
				 PGSQL_GETCOLUMN_TEMPLATE_SCHEMA,
				 table_ce(upi->config_kset).u.string,
				 pi->db_inst.schema);
	} else {
		snprintf(pgbuf, sizeof(pgbuf)-1, PGSQL_GETCOLUMN_TEMPLATE,
				 table_ce(upi->config_kset).u.string);
	}

	if (__pgsql_exec(upi, pgbuf, NULL) < 0)
		return ULOGD_IRET_AGAIN;

	if (upi->input.keys != NULL)
		free(upi->input.keys);

	upi->input.num_keys = PQntuples(pi->pgres);

	/* ignore columns with leading underscore */
	for (i = 0; i < PQntuples(pi->pgres); i++) {
		char *val = PQgetvalue(pi->pgres, i, 0);

		if (val == NULL) {
			ulogd_log(ULOGD_ERROR, "%s: error fetching tuples\n", upi->id);
			return -1;
		}

		if (val[0] == '_')
			upi->input.num_keys--;
	}

	ulogd_log(ULOGD_DEBUG, "%s: using %d/%d columns of table\n",
			  upi->id, upi->input.num_keys, PQntuples(pi->pgres));

	upi->input.keys = ulogd_alloc_keyset(upi->input.num_keys, 0);
	if (upi->input.keys == NULL) {
		upi->input.num_keys = 0;
		PQclear(pi->pgres);

		ulogd_log(ULOGD_ERROR, "%s: out of memory\n", upi->id);

		return -ENOMEM;
	}

	/* skip columns with leading underscore */
	for (i = 0, k = 0; i < upi->input.num_keys; i++) {
		strncpy(upi->input.keys[k].name, PQgetvalue(pi->pgres, i, 0),
				ULOGD_MAX_KEYLEN);

		if (upi->input.keys[k].name[0] == '_') {
			pr_fn_debug("ignoring column '%s'\n", upi->input.keys[k].name);
			continue;
		}

		/* replace all underscores with dots */
		strntr(upi->input.keys[k].name, '_', '.');

		pr_fn_debug("field '%s' found: ", upi->input.keys[k].name);

		k++;
	}

	PQclear(pi->pgres);

	return 0;
}

/**
 * The prepared insert statement has the form
 *
 *   INSERT INTO mytable (col_1,col_2,...) VALUES ($1,$2,...);
 *
 * where $1,$2,... are the placeholders for the actual values which
 * are inserted.
 *
 * Columns with leading underscore are skipped, which is currently used
 * to ignore AUTOFILL columns at INSERT time.
 */
static int
pgsql_prepare(struct ulogd_pluginstance *pi)
{
	struct pgsql_priv *priv = upi_priv(pi);
	struct db_instance *di = &priv->db_inst;
	char *table = table_ce(pi->config_kset).u.string;
	char *query, *pch;
	int i, pgret;

	pr_fn_debug("pi=%p\n", pi);

	if ((pch = query = malloc(1024)) == NULL)
		return -1;

	if (di->schema != NULL)
		pch += sprintf(pch, "INSERT INTO %s.%s (",
				di->schema, table);
	else
		pch += sprintf(pch, "INSERT INTO %s (", table);

	for (i = 0; i < pi->input.num_keys; i++) {
		char name[ULOGD_MAX_KEYLEN + 1];

		strncpy(name, pi->input.keys[i].name, ULOGD_MAX_KEYLEN);
		strntr(name, '.', '_');

		pch += sprintf(pch, "%s", name);
		if (i + 1 < pi->input.num_keys)
			*pch++ = ',';
	}

	pch += sprintf(pch, ") VALUES (");

	for (i = 0; i < pi->input.num_keys; i++) {
		pch += sprintf(pch, "$%d", i + 1);
		if (i + 1 < pi->input.num_keys)
			*pch++ = ',';

		priv->param_val[i] = malloc(32);
	}

	*pch = '\0';
	strcat(pch, ");");

	pr_fn_debug("%s: prepare-stmt: %s\n", pi->id, query);

	priv->pgres = PQprepare(priv->dbh, "insert", query,
							pi->input.num_keys, NULL /* paramTypes */);
	if (__pgsql_err(pi, &pgret) < 0)
		goto err_free;

	if (pgret == PGRES_TUPLES_OK)
		PQclear(priv->pgres);

	free(query);

	ulogd_log(ULOGD_DEBUG, "%s: statement prepared\n", pi->id);

	return 0;

err_free:
	free(query);

	return -1;
}

static int
pgsql_close_db(struct ulogd_pluginstance *upi)
{
	struct pgsql_priv *pi = upi_priv(upi);

	pr_fn_debug("pi=%p\n", upi);

	PQfinish(pi->dbh);
	pi->dbh = NULL;

	return 0;
}

/**
 * Make connection and select database.  Return %ULOGD_IRET_AGAIN if
 * there is a chance to connect later.
 */
static int
pgsql_open_db(struct ulogd_pluginstance *upi)
{
	struct pgsql_priv *pi = upi_priv(upi);
	char *server = host_ce(upi->config_kset).u.string;
	unsigned int port = port_ce(upi->config_kset).u.value;
	char *user = user_ce(upi->config_kset).u.string;
	char *pass = pass_ce(upi->config_kset).u.string;
	char *db = db_ce(upi->config_kset).u.string;
	char *connstr;
	int errret = ULOGD_IRET_ERR;
	int len;

	pr_fn_debug("pi=%p\n", upi);

	/* 80 is more than what we need for the fixed parts below */
	len = 80 + strlen(user) + strlen(db);

	/* hostname, password, user and pass are optional, depending
	   on what kind of connection is used. */
	if (server)
		len += strlen(server);
	if (pass != NULL && *pass != '\0')
		len += strlen(pass);
	if (port)
		len += 20;

	if ((connstr = malloc(len)) == NULL)
		return ULOGD_IRET_ERR;

	*connstr = '\0';

	if (server != NULL) {
		strcat(connstr, " host=");
		strcat(connstr, server);
	}

	if (port) {
		char portbuf[12];

		snprintf(portbuf, sizeof(portbuf), " port=%u", port);
		strcat(connstr, portbuf);
	}

	strcat(connstr, " dbname=");
	strcat(connstr, db);

	if (user != NULL && *user != '\0') {
		strcat(connstr, " user=");
		strcat(connstr, user);
	}

	if (pass != NULL && *pass != '\0') {
		strcat(connstr, " password=");
		strcat(connstr, pass);
	}
	
	pi->dbh = PQconnectdb(connstr);
	if (PQstatus(pi->dbh) != CONNECTION_OK) {
		ulogd_log(ULOGD_ERROR, "unable to connect to db (%s): %s\n",
			  connstr, PQerrorMessage(pi->dbh));
		pgsql_close_db(upi);

		errret = ULOGD_IRET_AGAIN;

		goto err_free;
	}

	if (pgsql_namespace(upi) < 0) {
		ulogd_log(ULOGD_ERROR, "unable to test for pgsql schemas\n");
		pgsql_close_db(upi);
		goto err_free;
	}

	free(connstr);

	return 0;

err_free:
	free(connstr);

	return errret;
}

static int
pgsql_escape_string(struct ulogd_pluginstance *upi,
					char *dst, const char *src, unsigned int len)
{
	pr_fn_debug("pi=%p\n", upi);

	PQescapeString(dst, src, strlen(src)); 

	return 0;
}

static int
__pgsql_commit_row(struct ulogd_pluginstance *pi, struct db_row *row)
{
	struct pgsql_priv *priv = upi_priv(pi);
	int pgret;

	pr_fn_debug("pi=%p\n", pi);

	utoa(row->ip_saddr, priv->param_val[0], 32);
	utoa(row->ip_daddr, priv->param_val[1], 32);
	utoa(row->ip_proto, priv->param_val[2], 32);
	utoa(row->l4_dport, priv->param_val[3], 32);
	utoa(row->raw_in_pktlen, priv->param_val[4], 32);
	utoa(row->raw_in_pktcount, priv->param_val[5], 32);
	utoa(row->raw_out_pktlen, priv->param_val[6], 32);
	utoa(row->raw_out_pktcount, priv->param_val[7], 32);
	utoa(row->flow_start_day, priv->param_val[8], 32);
	utoa(row->flow_start_sec, priv->param_val[9], 32);
	utoa(row->flow_duration, priv->param_val[10], 32);

	priv->pgres = PQexecPrepared(priv->dbh, "insert",
								 pi->input.num_keys,
								 (const char * const *)priv->param_val,
								 NULL, NULL /* param_fmts */,
								 0 /* want result in text format */);

	if (__pgsql_err(pi, &pgret) < 0) {
		if (pgret == PGRES_FATAL_ERROR)
			return ULOGD_IRET_AGAIN;

		return ULOGD_IRET_ERR;
	}

	return 0;
}

/**
 * Commits a maximum of %max_commit rows to database as part of a
 * transaction.
 *
 * @arg pi        Plugin instance to use.
 * @arg max_commit        Maximum number of rows to commit.
 */
static int
pgsql_commit(struct ulogd_pluginstance *pi, int max_commit)
{
	struct pgsql_priv *priv = upi_priv(pi);
	struct db_instance *di = &priv->db_inst;
	struct llist_head *curr, *tmp;
	struct db_row *row;
	int pgret, rows = 0;

	pr_fn_debug("pi=%p\n", pi);

	if (__pgsql_exec(pi, "start transaction", &pgret) < 0)
		goto err;

	llist_for_each_prev_safe(curr, tmp, &di->rows) {
		if (++rows > max_commit)
			break;

		row = llist_entry(curr, struct db_row, link);

		if (__pgsql_commit_row(pi, row) < 0)
			goto err_rollback;

		llist_move(&row->link, &di->rows_committed);
    }

	if (__pgsql_exec(pi, "commit", &pgret) < 0)
		goto err_rollback;

	/* rows are deleted by generic DB layer */

	return rows;

err_rollback:
	(void)__pgsql_exec(pi, "rollback", &pgret);

err:
	ulogd_upi_set_state(pi, PsConfigured);

	return ULOGD_IRET_AGAIN;
}

static int
pgsql_execute(struct ulogd_pluginstance *upi, const char *stmt,
			  unsigned int len)
{
	struct pgsql_priv *priv = upi_priv(upi);
	int ret, pgret;

	if ((ret = __pgsql_exec(upi, stmt, &pgret)) < 0)
		return ret;

	if (pgret == PGRES_TUPLES_OK)
		PQclear(priv->pgres);

	return ret;
}

static struct db_driver db_driver_pgsql = {
	.get_columns = &pgsql_get_columns,
	.prepare = &pgsql_prepare,
	.commit = &pgsql_commit,
	.open_db = &pgsql_open_db,
	.close_db = &pgsql_close_db,
	.escape_string = &pgsql_escape_string,
	.execute = &pgsql_execute,
};

static int
pgsql_configure(struct ulogd_pluginstance *upi,
				struct ulogd_pluginstance_stack *stack)
{
	struct pgsql_priv *pi = upi_priv(upi);

	pi->db_inst.driver = &db_driver_pgsql;

	return ulogd_db_configure(upi, stack);
}

static struct ulogd_plugin pgsql_plugin = { 
	.name 		= "PGSQL", 
	.input 		= {
		.keys	= NULL,
		.num_keys = 0,
		.type	= ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
	},
	.output 	= {
		.type	= ULOGD_DTYPE_SINK,
	},
	.config_kset 	= &pgsql_kset,
	.priv_size	= sizeof(struct pgsql_priv),
	.configure	= &pgsql_configure,
	.start		= &ulogd_db_start,
	.stop		= &ulogd_db_stop,
	.signal		= &ulogd_db_signal,
	.interp		= &ulogd_db_interp_batch,
	.version	= ULOGD_VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&pgsql_plugin);
}
