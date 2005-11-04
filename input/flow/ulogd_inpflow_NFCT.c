/* ulogd_input_CTNL.c, Version $Revision$
 *
 * ulogd input plugin for ctnetlink
 *
 * (C) 2005 by Harald Welte <laforge@gnumonks.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <ulogd/ulogd.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

struct nfct_pluginstance {
	struct nfct_handle *cth;
	struct ulogd_fd nfct_fd;
};


static struct ulogd_key nfct_okeys[] = {
	{
		.type 	= ULOGD_RET_IPADDR,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "ip.saddr",
		.ipfix	= { },
	},
	{
		.type	= ULOGD_RET_IPADDR,
		.flags	= ULOGD_RETF_NONE,
		.name	= "ip.daddr",
		.ipfix	= { },
	},
	{
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "ip.protocol",
		.ipfix	= { },
	},
	{
		.type	= ULOGD_RET_UINT16,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "tcp.sport",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= 7,
		},
	},
	{
		.type	= ULOGD_RET_UINT16,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "tcp.dport",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= 11,
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.pktlen",
		.ipfix = { 
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= 1,
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.pktcount",
		.ipfix = { 
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= 2,
		},
	},

};

static int propagate_ct_flow(struct ulogd_pluginstance *upi, 
		             struct nfct_conntrack *ct,
			     unsigned int flags,
			     int dir)
{
	struct ulogd_key *ret = upi->output;

	ret[0].u.value.ui32 = ct->tuple[dir].src.v4;
	ret[0].flags |= ULOGD_RETF_VALID;

	ret[1].u.value.ui32 = ct->tuple[dir].dst.v4;
	ret[1].flags |= ULOGD_RETF_VALID;

	ret[2].u.value.ui8 = ct->tuple[dir].protonum;
	ret[2].flags |= ULOGD_RETF_VALID;

	switch (ct->tuple[1].protonum) {
	case IPPROTO_TCP:
		ret[3].u.value.ui16 = ct->tuple[dir].l4src.tcp.port;
		ret[3].flags |= ULOGD_RETF_VALID;
		ret[4].u.value.ui16 = ct->tuple[dir].l4dst.tcp.port;
		ret[4].flags |= ULOGD_RETF_VALID;
		break;
	case IPPROTO_UDP:
		break;
	case IPPROTO_SCTP:
		break;
	}

	if ((dir == NFCT_DIR_ORIGINAL && flags & NFCT_COUNTERS_ORIG) ||
	    (dir == NFCT_DIR_REPLY && flags & NFCT_COUNTERS_RPLY)) {
		ret[5].u.value.ui64 = ct->counters[dir].bytes;
		ret[5].flags |= ULOGD_RETF_VALID;

		ret[6].u.value.ui64 = ct->counters[dir].packets;
		ret[6].flags |= ULOGD_RETF_VALID;
	}
	
	ulogd_propagate_results(upi);

	return 0;
}

static int propagate_ct(struct ulogd_pluginstance *upi,
			struct nfct_conntrack *ct,
			unsigned int flags)
{
	int rc;

	rc = propagate_ct_flow(upi, ct, flags, NFCT_DIR_ORIGINAL);
	if (rc < 0)
		return rc;
	return propagate_ct_flow(upi, ct, flags, NFCT_DIR_REPLY);
}

static int event_handler(void *arg, unsigned int flags, int type,
			 void *data)
{
	struct nfct_conntrack *ct = arg;
	struct ulogd_pluginstance *upi = data;

	if (type == NFCT_MSG_NEW) {
		/* FIXME: build hash table with timestamp of start of
		 * connection */
	} else if (type == NFCT_MSG_DESTROY) {
		/* We have the final count of bytes for this connection */
		return propagate_ct(upi, ct, flags);
	}

	return 0;
}

static int read_cb_nfct(int fd, unsigned int what, void *param)
{
	struct nfct_pluginstance *cpi = 
				(struct nfct_pluginstance *) param;

	if (!(what & ULOGD_FD_READ))
		return 0;

	/* FIXME: implement this */
	nfct_event_conntrack(cpi->cth);
	return 0;
}

static int constructor_nfct(struct ulogd_pluginstance *upi)
{
	struct nfct_pluginstance *cpi = 
			(struct nfct_pluginstance *)upi->private;

	memset(cpi, 0, sizeof(*cpi));

	/* FIXME: make eventmask configurable */
	cpi->cth = nfct_open(NFNL_SUBSYS_CTNETLINK, NF_NETLINK_CONNTRACK_NEW|
			     NF_NETLINK_CONNTRACK_DESTROY);
	if (!cpi->cth) {
		ulogd_log(ULOGD_FATAL, "error opening ctnetlink\n");
		return -1;
	}

	nfct_register_callback(cpi->cth, &event_handler, upi);

	cpi->nfct_fd.fd = nfct_fd(cpi->cth);
	cpi->nfct_fd.cb = &read_cb_nfct;
	cpi->nfct_fd.data = cpi;
	cpi->nfct_fd.when = ULOGD_FD_READ;

	ulogd_register_fd(&cpi->nfct_fd);
	
	return 0;
}


static int destructor_nfct(struct ulogd_pluginstance *pi)
{
	struct nfct_pluginstance *cpi = (void *) pi;
	int rc;

	rc = nfct_close(cpi->cth);
	if (rc < 0)
		return rc;

	return 0;
}

static struct ulogd_plugin nfct_plugin = {
	.name = "CTNL",
	.input = {
		.type = ULOGD_DTYPE_SOURCE,
	},
	.output = {
		.keys = nfct_okeys,
		.num_keys = ARRAY_SIZE(nfct_okeys),
		.type = ULOGD_DTYPE_FLOW,
	},
	.config_kset 	= NULL,
	.interp 	= NULL,
	.configure	= NULL,
	.start		= &constructor_nfct,
	.stop		= &destructor_nfct,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&nfct_plugin);
}

