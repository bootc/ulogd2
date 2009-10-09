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
#include "config.h"
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/plugin.h>
#include <ulogd/db.h>
#include <libpq-fe.h>

#define NPARAMS			16
#define PARAM_LEN		48		/* enough for an IPv6 address */


struct pgsql_priv {
	struct db_instance db_inst;	/* must come first */
	PGconn *dbh;				/* database handle */
	PGresult *pgres;
	unsigned char pgsql_have_schemas;

	char *param_val[NPARAMS];
};


/* our configuration directives */
static const struct config_keyset pgsql_kset = {
	.num_ces = DB_CE_NUM + 6,
	.ces = {
		DB_CES,
		CONFIG_KEY("db", STRING, CONFIG_OPT_MANDATORY),
		CONFIG_KEY("host", STRING, 0),
		CONFIG_KEY("user", STRING, 0),
		CONFIG_KEY("pass", STRING, 0),
		CONFIG_KEY("port", INT, 0),
		CONFIG_KEY_STR("schema", "public"),
	},
};

#define db_ce(pi)		ulogd_config_str((pi), DB_CE_NUM)
#define host_ce(pi)		ulogd_config_str((pi), DB_CE_NUM + 1)
#define user_ce(pi)		ulogd_config_str((pi), DB_CE_NUM + 2)
#define pass_ce(pi)		ulogd_config_str((pi), DB_CE_NUM + 3)
#define port_ce(pi)		ulogd_config_int((pi), DB_CE_NUM + 4)
#define schema_ce(pi)	ulogd_config_str((pi), DB_CE_NUM + 5)


static int
__pgsql_err(struct ulogd_pluginstance *pi, int *pgret)
{
	struct pgsql_priv *priv = upi_priv(pi);
	int __pgret;

	if (priv->pgres == NULL) {
		upi_log(pi, ULOGD_FATAL, "command failed\n");
		return -1;
	}

	__pgret = PQresultStatus(priv->pgres);
	if (pgret != NULL)
		*pgret = __pgret;

	if (__pgret != PGRES_COMMAND_OK && __pgret != PGRES_TUPLES_OK)
		upi_log(pi, ULOGD_ERROR, "%s\n", PQerrorMessage(priv->dbh));

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
		BUG();
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

	pr_fn_debug("cmd: %s\n", cmd);

	priv->pgres = PQexec(priv->dbh, cmd);

	return __pgsql_err(pi, pgret);
}

/* Determine if server support schemas */
static int
pgsql_namespace(struct ulogd_pluginstance *upi)
{
	struct pgsql_priv *priv = upi_priv(upi);
	char *pgbuf, *schema = schema_ce(upi);

	pr_fn_debug("pi=%p\n", upi);

	if (priv->dbh == NULL)
		return ULOGD_IRET_AGAIN;

	if (asprintf(&pgbuf, PGSQL_HAVE_NAMESPACE_TEMPLATE, schema) < 0) {
		upi_log(upi, ULOGD_ERROR, "namespace: %m\n");

		return ULOGD_IRET_ERR;
	}

	if (__pgsql_exec(upi, pgbuf, NULL) < 0) {
		upi_log(upi, ULOGD_ERROR, "error reading namespace: %s\n",
				PQerrorMessage(priv->dbh));
		free(pgbuf);

		return ULOGD_IRET_AGAIN;
	}

	PQclear(priv->pgres);

	priv->db_inst.schema = schema;
	upi_log(upi, ULOGD_DEBUG, "using schema '%s'\n", schema);

	free(pgbuf);
	
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
	struct pgsql_priv *priv = upi_priv(upi);
	struct ulogd_key *in;
	char *pgbuf;
	int i, k, tuples;
	int ret = ULOGD_IRET_AGAIN;

	pr_fn_debug("pi=%p\n", upi);

	if (priv->dbh == NULL) {
		upi_log(upi, ULOGD_ERROR, "no database handle\n");
		return ULOGD_IRET_AGAIN;
	}

	if (priv->db_inst.schema)
		ret = asprintf(&pgbuf, PGSQL_GETCOLUMN_TEMPLATE_SCHEMA,
					   table_ce(upi), priv->db_inst.schema);
	else
		ret = asprintf(&pgbuf, PGSQL_GETCOLUMN_TEMPLATE, table_ce(upi));
	if (ret < 0) {
		upi_log(upi, ULOGD_FATAL, "error creating schema: %m\n");
		return ULOGD_IRET_ERR;
	}

	if (__pgsql_exec(upi, pgbuf, NULL) < 0) {
		upi_log(upi, ULOGD_ERROR, "error getting columns: %s\n",
				PQerrorMessage(priv->dbh));
		goto err_again;
	}

	if (upi->input.keys != NULL)
		free(upi->input.keys);

	tuples = upi->input.num_keys = PQntuples(priv->pgres);

	/* ignore columns with leading underscore */
	for (i = 0; i < tuples; i++) {
		char *val = PQgetvalue(priv->pgres, i, 0);

		if (val == NULL) {
			upi_log(upi, ULOGD_ERROR, "error getting value '%d'\n", i);
			goto err_again;
		}

		if (val[0] == '_')
			upi->input.num_keys--;
	}

	upi_log(upi, ULOGD_DEBUG, "using %d/%d columns of table\n",
			upi->input.num_keys, tuples);

	if (ulogd_init_keyset(&upi->input, KEYSET_F_ALLOC) < 0) {
		PQclear(priv->pgres);
		goto err_again;
	}

	in = upi->input.keys;
	for (i = k = 0; i < upi->input.num_keys; i++) {
		in[k].name = strdup(PQgetvalue(priv->pgres, i, 0));

		/* skip columns with leading underscore */
		if (in[k].name[0] == '_') {
			pr_fn_debug("ignoring column '%s'\n", in[k].name);
			continue;
		}

		/* replace all underscores with dots */
		strntr(in[k].name, '_', '.');

		pr_fn_debug("field '%s' found: ", in[k].name);

		k++;
	}

	free(pgbuf);

	PQclear(priv->pgres);

	return 0;

err_again:
	free(pgbuf);

	return ULOGD_IRET_AGAIN;
}

/**
 * Prepare the given statement
 *
 * $1,$2,... are the placeholders for the actual values which are
 * inserted.
 */
static int
pgsql_prepare(struct ulogd_pluginstance *pi)
{
	struct pgsql_priv *priv = upi_priv(pi);
	struct db_instance *di = &priv->db_inst;
	int pgret;

	upi_log(pi, ULOGD_INFO, "prepare: %s\n", di->stmt);
	priv->pgres = PQprepare(priv->dbh, "insert", di->stmt, di->num_cols,
							NULL /* paramTypes */);
	if (__pgsql_err(pi, &pgret) < 0)
		goto err_free;

	if (pgret == PGRES_TUPLES_OK)
		PQclear(priv->pgres);

	upi_log(pi, ULOGD_DEBUG, "statement prepared\n");

	return 0;

err_free:
	return -1;
}

static int
pgsql_close_db(struct ulogd_pluginstance *upi)
{
	struct pgsql_priv *pi = upi_priv(upi);

	pr_fn_debug("pi=%p\n", upi);

	if (pi->dbh != NULL) {
		PQfinish(pi->dbh);
		pi->dbh = NULL;
	}

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
	char *server = host_ce(upi);
	unsigned port = port_ce(upi);
	char *user = user_ce(upi);
	char *pass = pass_ce(upi);
	char *db = db_ce(upi);
	char *connstr;
	int errret = ULOGD_IRET_AGAIN;
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
		upi_log(upi, ULOGD_ERROR, "unable to connect: %s\n",
				PQerrorMessage(pi->dbh));
		goto err_close;
	}

	if ((errret = pgsql_namespace(upi)) < 0) {
		upi_log(upi, ULOGD_ERROR, "unable to test for pgsql schemas\n");
		goto err_close;
	}

	if (__pgsql_exec(upi, "set synchronous_commit to off", NULL) < 0) {
		upi_log(upi, ULOGD_ERROR, "error enabling async commit\n");

		goto err_close;
	}

	free(connstr);

	upi_log(upi, ULOGD_INFO, "database connection opened\n");

	return 0;

err_close:
	pgsql_close_db(upi);

	free(connstr);

	return errret;
}

static int
__pgsql_commit_row(struct ulogd_pluginstance *pi, struct db_row *row)
{
	struct pgsql_priv *priv = upi_priv(pi);
	struct db_instance *di = &priv->db_inst;
	int i, pgret;

	pr_fn_debug("pi=%p\n", pi);

	for (i = 0; i < di->num_cols; i++) {
		const struct ulogd_value *val = &row->value[i];

		BUG_ON(row->value[i].type > __ULOGD_RET_MAX);
		if (row->value[i].type != ULOGD_RET_NONE)
			ulogd_value_to_ascii(val, priv->param_val[i], PARAM_LEN);
		else {
			/*
			 * this may not be correct with string type columns, but may be 
			 * easier to solve when using the binary encoding.
			 */
			strcpy(priv->param_val[i], "0");
		}
	}

	priv->pgres = PQexecPrepared(priv->dbh, "insert",
								 di->num_cols,
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
	.execute = &pgsql_execute,
};

static int
pgsql_configure(struct ulogd_pluginstance *upi)
{
	struct pgsql_priv *pi = upi_priv(upi);

	pi->db_inst.driver = &db_driver_pgsql;

	return ulogd_db_configure(upi);
}

static int
pgsql_start(struct ulogd_pluginstance *pi)
{
	struct pgsql_priv *priv = upi_priv(pi);
	struct db_instance *di = &priv->db_inst;
	int i;

	for (i = 0; i < di->num_cols; i++)
		priv->param_val[i] = malloc(PARAM_LEN);

	return ulogd_db_start(pi);
}

static int
pgsql_stop(struct ulogd_pluginstance *pi)
{
	struct pgsql_priv *priv = upi_priv(pi);
	struct db_instance *di = &priv->db_inst;
	int i, ret;

	ret = ulogd_db_stop(pi);

	for (i = 0; i < di->num_cols; i++) {
		if (priv->param_val[i]) {
			free(priv->param_val[i]);
			priv->param_val[i] = NULL;
		}
	}

	return ret;
}

static struct ulogd_plugin pgsql_plugin = { 
	.name = "PGSQL",
	.flags = ULOGD_PF_RECONF,
	.input = {
		.keys = NULL,
		.num_keys = 0,
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.config_kset = &pgsql_kset,
	.priv_size = sizeof(struct pgsql_priv),
	.configure = &pgsql_configure,
	.start = &pgsql_start,
	.stop = &pgsql_stop,
	.interp = &ulogd_db_interp,
	.rev = ULOGD_PLUGIN_REVISION,
};

void __upi_ctor init(void);

void init(void)
{
	ulogd_register_plugin(&pgsql_plugin);
}
