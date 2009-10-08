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

static struct ulogd_key syslog_inp[] = {
	KEY(STRING, "print"),
};

static const struct config_keyset syslog_kset = {
	.num_ces = 2,
	.ces = {
		CONFIG_KEY_STR("facility",  "LOG_KERN"),
		CONFIG_KEY_STR("level", "LOG_NOTICE"),
	},
};

struct syslog_instance {
	int level;
	int facility;
};

static int syslog_interp(struct ulogd_pluginstance *upi, unsigned *flags)
{
	struct syslog_instance *li = upi_priv(upi);
	struct ulogd_key *res = upi->input.keys;

	if (res[0].u.source->flags & ULOGD_RETF_VALID)
		syslog(li->level | li->facility, "%s", key_str(&res[0]));

	return 0;
}

static int syslog_configure(struct ulogd_pluginstance *pi)
{
	struct syslog_instance *priv = upi_priv(pi);
	const char *facility, *level;

	facility = pi->config_kset->ces[0].u.string;
	level = pi->config_kset->ces[1].u.string;

	priv->facility = nv_get_value(nv_facility, FACILITY_LEN, facility);
	priv->level = nv_get_value(nv_level, LEVEL_LEN, level);
	if (priv->facility < 0 || priv->level < 0) {
		upi_log(pi, ULOGD_FATAL, "invalid syslog facility or level\n");
		return ULOGD_IRET_ERR;
	}

	return ULOGD_IRET_OK;
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
