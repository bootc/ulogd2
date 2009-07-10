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

/* config accessors (lazy me...) */
#define NACCT_CFG_FILE(pi)	((pi)->config_kset->ces[0].u.string)
#define NACCT_CFG_SYNC(pi)	((pi)->config_kset->ces[1].u.value)

struct nacct_priv {
	FILE *of;
	struct ulogd_timer timer;
};

/* input keys */
enum InKeys {
	InIpSAddr = 0,
	InIpDAddr,
	InIpProto,
	InL4SPort,
	InL4DPort,
	InRawInPktLen,
	InRawInPktCnt,
	InIcmpCode,
	InIcmpType,
	InFlowStartSec,
	InFlowEndSec,
};

static struct ulogd_key in_keys[] = {
	[InIpSAddr] = KEY(IPADDR, "ip.saddr"),
	[InIpDAddr] = KEY(IPADDR, "ip.daddr"),
	[InIpProto] = KEY(UINT8, "ip.protocol"),
	[InL4SPort] = KEY(UINT16, "l4.sport"),
	[InL4DPort] = KEY(UINT16, "l4.dport"),
	[InRawInPktLen] = KEY(UINT32, "raw.in.pktlen"),
	[InRawInPktCnt] = KEY(UINT32, "raw.in.pktcount"),
	[InIcmpCode] = KEY(UINT8, "icmp.code"),
	[InIcmpType] = KEY(UINT8, "icmp.type"),
	[InFlowStartSec] = KEY(UINT32, "flow.start.sec"),
	[InFlowEndSec] = KEY(UINT32, "flow.end.sec"),
};

static const struct config_keyset nacct_kset = {
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
nacct_interp(struct ulogd_pluginstance *pi, unsigned *flags)
{
	struct nacct_priv *priv = upi_priv(pi);
	struct ulogd_key *in = pi->input.keys;
	static char buf[80];
	int len;

	/* try to be as close to nacct as possible.  Instead of nacct's
	   'timestamp' value use 'flow.end.sec' */
	if (key_src_u8(&in[InIpProto]) == IPPROTO_ICMP) {
		len = sprintf(buf, "%u\t%u\t%s\t%u\t%s\t%u\t%u\t%u\n",
				key_src_u32(&in[InFlowEndSec]),
				key_src_u8(&in[InIpProto]),
				inet_ntoa((struct in_addr){ key_src_u32(&in[InIpSAddr]) }),
				key_src_u8(&in[InIcmpType]),
				inet_ntoa((struct in_addr){ key_src_u32(&in[InIpDAddr]) }),
				key_src_u8(&in[InIcmpCode]),
				key_src_u32(&in[InRawInPktCnt]),
				key_src_u32(&in[InRawInPktLen]));
	} else {
		len = sprintf(buf, "%u\t%u\t%s\t%u\t%s\t%u\t%u\t%u\n",
					  key_src_u32(&in[InFlowEndSec]),
					  key_src_u8(&in[InIpProto]),
					  inet_ntoa((struct in_addr){ key_src_u32(&in[InIpSAddr]) }),
					  key_src_u16(&in[InL4SPort]),
					  inet_ntoa((struct in_addr){ key_src_u32(&in[InIpDAddr]) }),
					  key_src_u16(&in[InL4DPort]),
					  key_src_u32(&in[InRawInPktCnt]),
					  key_src_u32(&in[InRawInPktLen]));
	}

	if (fwrite(buf, len, 1, priv->of) < 1) {
		upi_log(pi, ULOGD_ERROR, "write failed (short write)\n");
		return ULOGD_IRET_ERR;
	}

	if (NACCT_CFG_SYNC(pi) != 0)
		fflush(priv->of);

	return ULOGD_IRET_OK;
}

static void
nacct_timer_cb(struct ulogd_timer *t)
{
	struct ulogd_pluginstance *pi = t->data;
	struct nacct_priv *priv = upi_priv(pi);

	fflush(priv->of);
}

static int
nacct_configure(struct ulogd_pluginstance *pi)
{
	return 0;
}

static int
nacct_start(struct ulogd_pluginstance *pi)
{
	struct nacct_priv *priv = upi_priv(pi);

	if ((priv->of = fopen(NACCT_CFG_FILE(pi), "a")) == NULL) {
		upi_log(pi, ULOGD_FATAL, "%s: %s\n",
				NACCT_CFG_FILE(pi), strerror(errno));
		return ULOGD_IRET_ERR;
	}

	upi_log(pi, ULOGD_DEBUG, "log file '%s' opened\n", NACCT_CFG_FILE(pi));

	ulogd_init_timer(&priv->timer, 1 SEC, nacct_timer_cb, pi,
					TIMER_F_PERIODIC);
	ulogd_register_timer(&priv->timer);

	return ULOGD_IRET_OK;
}

static int
nacct_stop(struct ulogd_pluginstance *pi)
{
	struct nacct_priv *priv = upi_priv(pi);

	ulogd_unregister_timer(&priv->timer);

	if (priv->of != NULL) {
		fclose(priv->of);
		priv->of = NULL;
	}

	upi_log(pi, ULOGD_DEBUG, "log file closed\n");

	return 0;
}

static struct ulogd_plugin nacct_plugin = {
	.name = "NACCT",
	.flags = ULOGD_PF_RECONF,
	.input = {
		.keys = in_keys,
		.num_keys = ARRAY_SIZE(in_keys),
		.type = ULOGD_DTYPE_FLOW,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.configure = &nacct_configure,
	.start 	= &nacct_start,
	.stop	= &nacct_stop,
	.interp	= &nacct_interp,
	.config_kset = &nacct_kset,
	.rev = ULOGD_PLUGIN_REVISION,
	.priv_size = sizeof(struct nacct_priv),
};

void __upi_ctor init(void);

void
init(void)
{
	ulogd_register_plugin(&nacct_plugin);
}
