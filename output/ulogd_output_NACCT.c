/*
 * ulogd_outpout_NACCT.c
 *
 * ulogd output plugin for accounting which tries to stay mostly
 * compatible with nacct output.
 *
 * (C) 2006, H. Eitzenberger  Astaro AG
 *
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
 */
#include "config.h"
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/plugin.h>
#include <arpa/inet.h>

#define NACCT_FILE_DEFAULT	"/var/log/nacctdata.log"

#define HIPQUAD(addr) \
        ((unsigned char *)&addr)[3], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]

/* config accessors (lazy me...) */
#define NACCT_CFG_FILE(pi)	((pi)->config_kset->ces[0].u.string)
#define NACCT_CFG_SYNC(pi)	((pi)->config_kset->ces[1].u.value)

#define KEY(pi,idx)		((pi)->input.keys[(idx)].u.source)

/* input keys */
#define KEY_IP_SADDR(pi)		KEY(pi, 0)
#define KEY_IP_DADDR(pi)		KEY(pi, 1)
#define KEY_IP_PROTO(pi)		KEY(pi, 2)
#define KEY_L4_SPORT(pi)		KEY(pi, 3)
#define KEY_L4_DPORT(pi)		KEY(pi, 4)
#define KEY_RAW_PKTLEN(pi)		KEY(pi, 5)
#define KEY_RAW_PKTCNT(pi)		KEY(pi, 6)
#define KEY_ICMP_CODE(pi)		KEY(pi, 7)
#define KEY_ICMP_TYPE(pi)		KEY(pi, 8)
#define KEY_FLOW_START(pi)		KEY(pi, 11)
#define KEY_FLOW_END(pi)		KEY(pi, 13)

struct nacct_priv {
	FILE *of;
};


static int
nacct_interp(struct ulogd_pluginstance *pi)
{
	struct nacct_priv *priv = (struct nacct_priv *)&pi->private;
	static char buf[80];

	/* try to be as close to nacct as possible.  Instead of nacct's
	   'timestamp' value use 'flow.end.sec' */
	if (KEY_IP_PROTO(pi)->u.value.ui8 == IPPROTO_ICMP) {
		snprintf(buf, sizeof(buf),
				 "%u\t%u\t%u.%u.%u.%u\t%u\t%u.%u.%u.%u\t%u\t%u\t%u",
				 KEY_FLOW_END(pi)->u.value.ui32,
				 KEY_IP_PROTO(pi)->u.value.ui8,
				 HIPQUAD(KEY_IP_SADDR(pi)->u.value.ui32),
				 KEY_ICMP_TYPE(pi)->u.value.ui8,
				 HIPQUAD(KEY_IP_DADDR(pi)->u.value.ui32),
				 KEY_ICMP_CODE(pi)->u.value.ui8,
				 KEY_RAW_PKTCNT(pi)->u.value.ui32,
				 KEY_RAW_PKTLEN(pi)->u.value.ui32);
	} else {
		snprintf(buf, sizeof(buf),
				 "%u\t%u\t%u.%u.%u.%u\t%u\t%u.%u.%u.%u\t%u\t%u\t%u",
				 KEY_FLOW_END(pi)->u.value.ui32,
				 KEY_IP_PROTO(pi)->u.value.ui8,
				 HIPQUAD(KEY_IP_SADDR(pi)->u.value.ui32),
				 KEY_L4_SPORT(pi)->u.value.ui8,
				 HIPQUAD(KEY_IP_DADDR(pi)->u.value.ui32),
				 KEY_L4_DPORT(pi)->u.value.ui8,
				 KEY_RAW_PKTCNT(pi)->u.value.ui32,
				 KEY_RAW_PKTLEN(pi)->u.value.ui32);
	}

	fprintf(priv->of, "%s\n", buf);

	if (NACCT_CFG_SYNC(pi) != 0)
		fflush(priv->of);

	return 0;
}

static struct config_keyset nacct_kset = {
	.num_ces = 2,
	.ces = {
		{
			.key = "file", 
			.type = CONFIG_TYPE_STRING, 
			.options = CONFIG_OPT_NONE,
			.u = {.string = NACCT_FILE_DEFAULT },
		},
		{
			.key = "sync",
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u = { .value = 0 },
		},
	},
};

static int
nacct_conf(struct ulogd_pluginstance *pi)
{
	int ret;

	if ((ret = ulogd_wildcard_inputkeys(pi)) < 0)
		return ret;

	return 0;
}

static int
nacct_init(struct ulogd_pluginstance *pi)
{
	struct nacct_priv *op = (struct nacct_priv *)&pi->private;

	if ((op->of = fopen(NACCT_CFG_FILE(pi), "a")) == NULL) {
		upi_log(pi, ULOGD_FATAL, "%s: %s\n",
				NACCT_CFG_FILE(pi), strerror(errno));
		return -1;
	}		
	return 0;
}

static int
nacct_fini(struct ulogd_pluginstance *pi)
{
	struct nacct_priv *op = (struct nacct_priv *)&pi->private;

	if (op->of != stdout)
		fclose(op->of);

	return 0;
}

static struct ulogd_plugin nacct_plugin = {
	.name = "NACCT", 
	.input = {
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.configure = &nacct_conf,
	.interp	= &nacct_interp,
	.start 	= &nacct_init,
	.stop	= &nacct_fini,
	.config_kset = &nacct_kset,
	.rev = ULOGD_PLUGIN_REVISION,
	.priv_size = sizeof(struct nacct_priv),
};

void __attribute__ ((constructor)) init(void);

void
init(void)
{
	ulogd_register_plugin(&nacct_plugin);
}
