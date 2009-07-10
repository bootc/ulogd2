/* ulogd_SYSLOG.c, Version $Revision$
 *
 * ulogd output target for real syslog() logging
 *
 * This target produces a syslog entries identical to the LOG target.
 *
 * (C) 2003-2005 by Harald Welte <laforge@gnumonks.org>
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
 * $Id$
 *
 */
#include "config.h"
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/plugin.h>
#include <unistd.h>
#include <syslog.h>

#define SYSLOG_FACILITY_DEFAULT	"LOG_KERN"
#define SYSLOG_LEVEL_DEFAULT "LOG_NOTICE"

#define NV_INITIALIZER(val)		{ STRINGIFY(val), val }


static struct ulogd_key syslog_inp[] = {
	{
		.type = ULOGD_RET_STRING,
		.name = "print",
	},
};

static const struct config_keyset syslog_kset = {
	.num_ces = 2,
	.ces = {
		CONFIG_KEY_STR("facility", SYSLOG_FACILITY_DEFAULT),
		CONFIG_KEY_STR("level", SYSLOG_LEVEL_DEFAULT),
	},
};

struct syslog_instance {
	int syslog_level;
	int syslog_facility;
};

static int syslog_interp(struct ulogd_pluginstance *upi, unsigned *flags)
{
	struct syslog_instance *li = upi_priv(upi);
	struct ulogd_key *res = upi->input.keys;

	if (res[0].u.source->flags & ULOGD_RETF_VALID)
		syslog(li->syslog_level | li->syslog_facility, "%s",
				res[0].u.source->u.value.str);

	return 0;
}

static const struct syslog_nv {
	const char *name;
	int val;
} str2facility[] = {
	NV_INITIALIZER(LOG_DAEMON),
	NV_INITIALIZER(LOG_KERN),
	NV_INITIALIZER(LOG_LOCAL0),
	NV_INITIALIZER(LOG_LOCAL1),
	NV_INITIALIZER(LOG_LOCAL2),
	NV_INITIALIZER(LOG_LOCAL3),
	NV_INITIALIZER(LOG_LOCAL4),
	NV_INITIALIZER(LOG_LOCAL5),
	NV_INITIALIZER(LOG_LOCAL6),
	NV_INITIALIZER(LOG_LOCAL7),
	NV_INITIALIZER(LOG_USER),
};
static const struct syslog_nv str2loglevel[] = {
	NV_INITIALIZER(LOG_EMERG),
	NV_INITIALIZER(LOG_ALERT),
	NV_INITIALIZER(LOG_CRIT),
	NV_INITIALIZER(LOG_ERR),
	NV_INITIALIZER(LOG_WARNING),
	NV_INITIALIZER(LOG_NOTICE),
	NV_INITIALIZER(LOG_INFO),
	NV_INITIALIZER(LOG_DEBUG),
};

static int syslog_configure(struct ulogd_pluginstance *pi)
{
	struct syslog_instance *priv = upi_priv(pi);
	char *facility, *level;
	int i;

	facility = pi->config_kset->ces[0].u.string;
	level = pi->config_kset->ces[1].u.string;

	for (i = 0; i < ARRAY_SIZE(str2facility); i++) {
		if (strcmp(facility, str2facility[i].name) == 0)
			break;
	}

	if (i >= ARRAY_SIZE(str2facility)) {
		upi_log(pi, ULOGD_FATAL, "unknown facility '%s'\n", facility);
		return ULOGD_IRET_ERR;
	}

	priv->syslog_facility = str2facility[i].val;

	for (i = 0; i < ARRAY_SIZE(str2loglevel); i++) {
		if (strcmp(facility, str2loglevel[i].name) == 0)
			break;
	}

	if (i >= ARRAY_SIZE(str2loglevel)) {
		upi_log(pi, ULOGD_FATAL, "unknown level '%s'\n", level);
		return ULOGD_IRET_ERR;
	}

	priv->syslog_level = str2loglevel[i].val;

	return 0;
}

static int syslog_start(struct ulogd_pluginstance *pi)
{
	openlog("ulogd", LOG_NDELAY|LOG_PID, LOG_DAEMON);

	return 0;
}

static int
syslog_stop(struct ulogd_pluginstance *pi)
{
	closelog();

	return ULOGD_IRET_OK;
}

static struct ulogd_plugin syslog_plugin = {
	.name = "SYSLOG",
	.flags = ULOGD_PF_RECONF,
	.input = {
		.keys = syslog_inp,
		.num_keys = ARRAY_SIZE(syslog_inp),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.config_kset	= &syslog_kset,
	.priv_size	= sizeof(struct syslog_instance),
	.configure	= syslog_configure,
	.start		= syslog_start,
	.stop		= syslog_stop,
	.interp		= syslog_interp,
	.rev		= ULOGD_PLUGIN_REVISION,
};

void __upi_ctor init(void);

void init(void)
{
	ulogd_register_plugin(&syslog_plugin);
}
