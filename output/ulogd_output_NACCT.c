/*
 * ulogd_outpout_NACCT.c
 *
 * ulogd output plugin for accounting which tries to stay mostly
 * compatible with nacct output.
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Holger Eitzenberger <holger@eitzenberger.org>  Astaro AG 2008
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>

#define NACCT_FILE_DEFAULT	"/var/log/nacctdata.log"

/* config accessors (lazy me...) */
#define NACCT_CFG_FILE(pi)	((pi)->config_kset->ces[0].u.string)
#define NACCT_CFG_SYNC(pi)	((pi)->config_kset->ces[1].u.value)

enum input_keys {
	KEY_IP_SADDR,
	KEY_IP_DADDR,
	KEY_IP_PROTO,
	KEY_L4_SPORT,
	KEY_L4_DPORT,
	KEY_RAW_PKTLEN,
	KEY_RAW_PKTCNT,
	KEY_ICMP_CODE,
	KEY_ICMP_TYPE,
	KEY_FLOW_START,
	KEY_FLOW_END,
};

/* input keys */
static struct ulogd_key nacct_inp[] = {
	[KEY_IP_SADDR] = {
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_NONE,
		.name = "orig.ip.saddr.str",
	},
	[KEY_IP_DADDR] = {
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_NONE,
		.name = "orig.ip.daddr.str",
	},
	[KEY_IP_PROTO] = {
			.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "orig.ip.protocol",

	},
	[KEY_L4_SPORT] = {
	.type	= ULOGD_RET_UINT16,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "orig.l4.sport",

	},
	[KEY_L4_DPORT] = {
		.type	= ULOGD_RET_UINT16,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "orig.l4.dport",
	},
	/* Assume we're interested more in download than upload */
	[KEY_RAW_PKTLEN] = {
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_RETF_NONE,
		.name	= "reply.raw.pktlen",
	},
	[KEY_RAW_PKTCNT] = {
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_RETF_NONE,
		.name	= "reply.raw.pktcount",
	},
	[KEY_ICMP_CODE] = {
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "icmp.code",
	},
	[KEY_ICMP_TYPE] = { 
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "icmp.type",
	},
	[KEY_FLOW_START] = {
		.type 	= ULOGD_RET_UINT32,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "flow.start.sec",
	},
	[KEY_FLOW_END] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "flow.end.sec",
	},
};

struct nacct_priv {
	FILE *of;
};


static int
nacct_interp(struct ulogd_pluginstance *pi)
{
	struct nacct_priv *priv = (struct nacct_priv *)&pi->private;
	struct ulogd_key *inp = pi->input.keys;
	static char buf[256];

	/* try to be as close to nacct as possible.  Instead of nacct's
	   'timestamp' value use 'flow.end.sec' */
	if (ikey_get_u8(&inp[KEY_IP_PROTO]) == IPPROTO_ICMP) {
		snprintf(buf, sizeof(buf),
				 "%u\t%u\t%s\t%u\t%s\t%u\t%llu\t%llu",
				 ikey_get_u32(&inp[KEY_FLOW_END]),
				 ikey_get_u8(&inp[KEY_IP_PROTO]),
				 (char *) ikey_get_ptr(&inp[KEY_IP_SADDR]),
				 ikey_get_u8(&inp[KEY_ICMP_TYPE]),
				 (char *) ikey_get_ptr(&inp[KEY_IP_DADDR]),
				 ikey_get_u8(&inp[KEY_ICMP_CODE]),
				 ikey_get_u64(&inp[KEY_RAW_PKTCNT]),
				 ikey_get_u64(&inp[KEY_RAW_PKTLEN]));
	} else {
		snprintf(buf, sizeof(buf),
				 "%u\t%u\t%s\t%u\t%s\t%u\t%llu\t%llu",
				 ikey_get_u32(&inp[KEY_FLOW_END]),
				 ikey_get_u8(&inp[KEY_IP_PROTO]),
				 (char *) ikey_get_ptr(&inp[KEY_IP_SADDR]),
				 ikey_get_u16(&inp[KEY_L4_SPORT]),
				 (char *) ikey_get_ptr(&inp[KEY_IP_DADDR]),
				 ikey_get_u16(&inp[KEY_L4_DPORT]),
				 ikey_get_u64(&inp[KEY_RAW_PKTCNT]),
				 ikey_get_u64(&inp[KEY_RAW_PKTLEN]));
	}

	fprintf(priv->of, "%s\n", buf);

	if (NACCT_CFG_SYNC(pi) != 0)
		fflush(priv->of);

	return ULOGD_IRET_OK;
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

static void
sighup_handler_print(struct ulogd_pluginstance *pi, int signal)
{
	struct nacct_priv *oi = (struct nacct_priv *)&pi->private;

	switch (signal) {
	case SIGHUP:
	{
		ulogd_log(ULOGD_NOTICE, "NACCT: reopening logfile\n");
		fclose(oi->of);
		oi->of = fopen(NACCT_CFG_FILE(pi), "a");
		if (!oi->of)
			ulogd_log(ULOGD_ERROR, "%s: %s\n", NACCT_CFG_FILE(pi),
					  strerror(errno));
		break;
	}

	default:
		break;
	}
}

static int
nacct_conf(struct ulogd_pluginstance *pi,
		   struct ulogd_pluginstance_stack *stack)
{
	int ret;

	if ((ret = config_parse_file(pi->id, pi->config_kset)) < 0)
		return ret;

	return 0;
}

static int
nacct_init(struct ulogd_pluginstance *pi)
{
	struct nacct_priv *op = (struct nacct_priv *)&pi->private;

	if ((op->of = fopen(NACCT_CFG_FILE(pi), "a")) == NULL) {
		ulogd_log(ULOGD_FATAL, "%s: %s\n", 
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
		.keys = nacct_inp,
		.num_keys = ARRAY_SIZE(nacct_inp),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.configure = &nacct_conf,
	.interp	= &nacct_interp,
	.start 	= &nacct_init,
	.stop	= &nacct_fini,
	.signal = &sighup_handler_print,
	.config_kset = &nacct_kset,
	.version = VERSION,
};

void __attribute__ ((constructor)) init(void);

void
init(void)
{
	ulogd_register_plugin(&nacct_plugin);
}
