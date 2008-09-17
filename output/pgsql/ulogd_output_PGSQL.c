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
#include <ulogd/conffile.h>
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
			.options = CONFIG_OPT_MANDATORY,
		},
		{
			.key = "pass", 
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
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

#define PGSQL_HAVE_NAMESPACE_TEMPLATE 			\
	"SELECT nspname FROM pg_namespace n WHERE n.nspname='%s'"

/* Determine if server support schemas */
static int
pgsql_namespace(struct ulogd_pluginstance *upi)
{
	struct pgsql_priv *pi = upi_priv(upi);
	char pgbuf[strlen(PGSQL_HAVE_NAMESPACE_TEMPLATE) + 
		   strlen(schema_ce(upi->config_kset).u.string) + 1];

	pr_fn_debug("pi=%p\n", pi);

	if (!pi->dbh)
		return 1;

	sprintf(pgbuf, PGSQL_HAVE_NAMESPACE_TEMPLATE,
		schema_ce(upi->config_kset).u.string);
	ulogd_log(ULOGD_DEBUG, "%s\n", pgbuf);
	
	pi->pgres = PQexec(pi->dbh, pgbuf);
	if (!pi->pgres) {
		ulogd_log(ULOGD_DEBUG, "\n result false");
		return 1;
	}

	if (PQresultStatus(pi->pgres) == PGRES_TUPLES_OK) {
		ulogd_log(ULOGD_DEBUG, "using schema %s\n",
			  schema_ce(upi->config_kset).u.string);
		pi->db_inst.schema = schema_ce(upi->config_kset).u.string;
	} else {
		pi->db_inst.schema = NULL;
	}

	PQclear(pi->pgres);
	
	return 0;
}

#define PGSQL_GETCOLUMN_TEMPLATE 			\
	"SELECT  a.attname FROM pg_class c, pg_attribute a WHERE c.relname ='%s' AND a.attnum>0 AND a.attrelid=c.oid ORDER BY a.attnum"

#define PGSQL_GETCOLUMN_TEMPLATE_SCHEMA 		\
	"SELECT a.attname FROM pg_attribute a, pg_class c LEFT JOIN pg_namespace n ON c.relnamespace=n.oid WHERE c.relname ='%s' AND n.nspname='%s' AND a.attnum>0 AND a.attrelid=c.oid AND a.attisdropped=FALSE ORDER BY a.attnum"

/* find out which columns the table has */
static int
pgsql_get_columns(struct ulogd_pluginstance *upi)
{
	struct pgsql_priv *pi = upi_priv(upi);
	char pgbuf[strlen(PGSQL_GETCOLUMN_TEMPLATE_SCHEMA)
		   + strlen(table_ce(upi->config_kset).u.string) 
		   + strlen(pi->db_inst.schema) + 2];
	int i;

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

	ulogd_log(ULOGD_DEBUG, "%s\n", pgbuf);

	pi->pgres = PQexec(pi->dbh, pgbuf);
	if (!pi->pgres) {
		ulogd_log(ULOGD_DEBUG, "result false (%s)",
			  PQerrorMessage(pi->dbh));
		return -1;
	}

	if (PQresultStatus(pi->pgres) != PGRES_TUPLES_OK) {
		ulogd_log(ULOGD_DEBUG, "pres_command_not_ok (%s)",
			  PQerrorMessage(pi->dbh));
		PQclear(pi->pgres);
		return -1;
	}

	if (upi->input.keys)
		free(upi->input.keys);

	upi->input.num_keys = PQntuples(pi->pgres);
	ulogd_log(ULOGD_DEBUG, "%u fields in table\n", upi->input.num_keys);

	upi->input.keys = calloc(upi->input.num_keys, sizeof(struct ulogd_key));
	if (upi->input.keys == NULL) {
		upi->input.num_keys = 0;
		ulogd_log(ULOGD_ERROR, "ENOMEM\n");
		PQclear(pi->pgres);

		return -ENOMEM;
	}

	for (i = 0; i < PQntuples(pi->pgres); i++) {
		char buf[ULOGD_MAX_KEYLEN+1];

		/* replace all underscores with dots */
		strncpy(buf, PQgetvalue(pi->pgres, i, 0), ULOGD_MAX_KEYLEN);
		strntr(buf, '_', '.');

		pr_fn_debug("field '%s' found: ", buf);

		/* add it to list of input keys */
		strncpy(upi->input.keys[i].name, buf, ULOGD_MAX_KEYLEN);
	}

	PQclear(pi->pgres);
	return 0;
}

static int
pgsql_prepare(struct ulogd_pluginstance *pi)
{
	struct pgsql_priv *priv = upi_priv(pi);
	struct db_instance *di = &priv->db_inst;
	char *table = table_ce(pi->config_kset).u.string;
	char *query, *pch;
	int i;

	pr_fn_debug("pi=%p\n", pi);

	if ((pch = query = malloc(1024)) == NULL)
		return -1;

	if (di->schema != NULL)
		pch += sprintf(pch, "INSERT INTO %s.%s VALUES (",
				di->schema, table);
	else
		pch += sprintf(pch, "INSERT INTO %s VALUES (", table);

	/* the prepared insert statement has the form
	 *
	 *   INSERT INTO mytable VALUES ($1,$2,...);
	 *
	 * where $1,$2,... are the placeholders for the actual values which
	 * are inserted.
	 */
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
	if (priv->pgres == NULL
		|| PQresultStatus(priv->pgres) != PGRES_COMMAND_OK) {
		ulogd_log(ULOGD_ERROR, "%s: prepare: %s\n",
				  PQerrorMessage(priv->dbh));
		goto err_free;
	}

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

/* make connection and select database */
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
	int len;

	pr_fn_debug("pi=%p\n", upi);

	/* 80 is more than what we need for the fixed parts below */
	len = 80 + strlen(user) + strlen(db);

	/* hostname and  and password are the only optionals */
	if (server)
		len += strlen(server);
	if (pass)
		len += strlen(pass);
	if (port)
		len += 20;

	if ((connstr = malloc(len)) == NULL)
		return -ENOMEM;

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
	strcat(connstr, " user=");
	strcat(connstr, user);

	if (pass != NULL) {
		strcat(connstr, " password=");
		strcat(connstr, pass);
	}
	
	pi->dbh = PQconnectdb(connstr);
	if (PQstatus(pi->dbh) != CONNECTION_OK) {
		ulogd_log(ULOGD_ERROR, "unable to connect to db (%s): %s\n",
			  connstr, PQerrorMessage(pi->dbh));
		pgsql_close_db(upi);
		goto err_free;
	}

	if (pgsql_namespace(upi)) {
		ulogd_log(ULOGD_ERROR, "unable to test for pgsql schemas\n");
		pgsql_close_db(upi);
		goto err_free;
	}

	free(connstr);

	return 0;

err_free:
	free(connstr);

	return -1;
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
pgsql_interp(struct ulogd_pluginstance *pi)
{
	struct pgsql_priv *priv = upi_priv(pi);
	struct db_instance *di = &priv->db_inst;
	int i;

	assert(priv->dbh != NULL);
	pr_fn_debug("pi=%p\n", pi);

	for (i = 0; i < pi->input.num_keys; i++) {
		struct ulogd_key *key = pi->input.keys[i].u.source;

		if (key->flags & ULOGD_KEYF_INACTIVE)
			continue;

		switch (key->type) {
		case ULOGD_RET_INT32:
			sprintf(priv->param_val[i], "%hhd", IS_VALID(*key) ?
				key->u.value.i32 : 0);
			break;

		case ULOGD_RET_UINT8:
			sprintf(priv->param_val[i], "%hhu", IS_VALID(*key) ?
				key->u.value.ui8 : 0U);
			break;

		case ULOGD_RET_UINT16:
			sprintf(priv->param_val[i], "%hu", IS_VALID(*key) ?
				key->u.value.ui16 : 0U);
			break;

		case ULOGD_RET_IPADDR:
		case ULOGD_RET_UINT32:
			sprintf(priv->param_val[i], "%u", IS_VALID(*key) ?
				key->u.value.ui32 : 0U);
			break;

		default:
			ulogd_log(ULOGD_ERROR, "%s: key type %d not supported\n",
					  pi->id, key->type);
		}
	}

	priv->pgres = PQexecPrepared(priv->dbh, "insert",
								 pi->input.num_keys,
								 (const char * const *)priv->param_val,
								 NULL, NULL /* param_fmts */,
								 0 /* want result in text format */);
	if (priv->pgres == NULL
		|| PQresultStatus(priv->pgres) != PGRES_COMMAND_OK) {
		ulogd_log(ULOGD_ERROR, "execute: %s\n",
				  PQerrorMessage(priv->dbh));
		goto err_clear;
	}

	PQclear(priv->pgres);

	return 0;

err_clear:
	PQclear(priv->pgres);
	return -1;
}

static int
pgsql_execute(struct ulogd_pluginstance *upi,
			  const char *stmt, unsigned int len)
{
	struct pgsql_priv *priv = upi_priv(upi);

	priv->pgres = PQexec(priv->dbh, stmt);
	if (priv->pgres == NULL
		|| PQresultStatus(priv->pgres) != PGRES_COMMAND_OK) {
		ulogd_log(ULOGD_ERROR, "execute: %s\n",
				  PQerrorMessage(priv->dbh));
		return -1;
	}

	PQclear(priv->pgres);

	return 0;
}

static struct db_driver db_driver_pgsql = {
	.get_columns = &pgsql_get_columns,
	.prepare = &pgsql_prepare,
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
	.interp		= &pgsql_interp,
	.version	= ULOGD_VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&pgsql_plugin);
}
