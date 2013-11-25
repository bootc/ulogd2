/* ulogd_input_CTNL.c, Version $Revision$
 *
 * ulogd input plugin for ctnetlink
 *
 * (C) 2005 by Harald Welte <laforge@netfilter.org>
 * (C) 2008-2010 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * 10 Jan 2005, Christian Hentschel <chentschel@people.netfilter.org>
 *      Added timestamp accounting support of the conntrack entries,
 *      reworked by Harald Welte.
 *
 * 11 May 2008, Pablo Neira Ayuso <pablo@netfilter.org>
 * 	Use a generic hashtable to store the existing flows
 * 	Add netlink overrun handling
 *
 * TODO:
 * 	- add nanosecond-accurate packet receive timestamp of event-changing
 * 	  packets to {ip,nf}_conntrack_netlink, so we can have accurate IPFIX
 *	  flowStart / flowEnd NanoSeconds.
 *	- SIGHUP for reconfiguration without loosing hash table contents, but
 *	  re-read of config and reallocation / rehashing of table, if required
 *	- Split hashtable code into separate [filter] plugin, so we can run 
 * 	  small non-hashtable ulogd installations on the firewall boxes, send
 * 	  the messages via IPFX to one aggregator who then runs ulogd with a 
 * 	  network wide connection hash table.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/time.h>
#include <time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ulogd/linuxlist.h>
#include <ulogd/jhash.h>
#include <ulogd/hash.h>

#include <ulogd/ulogd.h>
#include <ulogd/timer.h>
#include <ulogd/ipfix_protocol.h>
#include <ulogd/addr.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC    1000000000L
#endif

typedef enum TIMES_ { START, STOP, __TIME_MAX } TIMES;

struct ct_timestamp {
	struct hashtable_node hashnode;
	struct timeval time[__TIME_MAX];
	struct nf_conntrack *ct;
};

struct nfct_pluginstance {
	struct nfct_handle *cth;
	struct nfct_handle *ovh;	/* overrun handler */
	struct nfct_handle *pgh;	/* purge handler */
	struct ulogd_fd nfct_fd;
	struct ulogd_fd nfct_ov;
	struct ulogd_timer timer;
	struct ulogd_timer ov_timer;	/* overrun retry timer */
	struct hashtable *ct_active;
	int nlbufsiz;			/* current netlink buffer size */
	struct nf_conntrack *ct;
};

#define HTABLE_SIZE	(8192)
#define MAX_ENTRIES	(4 * HTABLE_SIZE)
#define EVENT_MASK	NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_DESTROY

static struct config_keyset nfct_kset = {
	.num_ces = 12,
	.ces = {
		{
			.key	 = "pollinterval",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		{
			.key	 = "hash_enable",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 1,
		},
		{
			.key	 = "hash_buckets",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = HTABLE_SIZE,
		},
		{
			.key	 = "hash_max_entries",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = MAX_ENTRIES,
		},
		{
			.key	 = "event_mask",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = EVENT_MASK,
		},
		{
			.key	 = "netlink_socket_buffer_size",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		{
			.key	 = "netlink_socket_buffer_maxsize",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		{
			.key	 = "netlink_resync_timeout",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 60,
		},
		{
			.key	 = "reliable",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		{
			.key	 = "accept_src_filter",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
		{
			.key	 = "accept_dst_filter",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
		{
			.key	 = "accept_proto_filter",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
	},
};
#define pollint_ce(x)	(x->ces[0])
#define usehash_ce(x)	(x->ces[1])
#define buckets_ce(x)	(x->ces[2])
#define maxentries_ce(x) (x->ces[3])
#define eventmask_ce(x) (x->ces[4])
#define nlsockbufsize_ce(x) (x->ces[5])
#define nlsockbufmaxsize_ce(x) (x->ces[6])
#define nlresynctimeout_ce(x) (x->ces[7])
#define reliable_ce(x)	(x->ces[8])
#define src_filter_ce(x)	((x)->ces[9])
#define dst_filter_ce(x)	((x)->ces[10])
#define proto_filter_ce(x)	((x)->ces[11])

enum nfct_keys {
	NFCT_ORIG_IP_SADDR = 0,
	NFCT_ORIG_IP_DADDR,
	NFCT_ORIG_IP_PROTOCOL,
	NFCT_ORIG_L4_SPORT,
	NFCT_ORIG_L4_DPORT,
	NFCT_ORIG_RAW_PKTLEN,
	NFCT_ORIG_RAW_PKTCOUNT,
	NFCT_REPLY_IP_SADDR,
	NFCT_REPLY_IP_DADDR,
	NFCT_REPLY_IP_PROTOCOL,
	NFCT_REPLY_L4_SPORT,
	NFCT_REPLY_L4_DPORT,
	NFCT_REPLY_RAW_PKTLEN,
	NFCT_REPLY_RAW_PKTCOUNT,
	NFCT_ICMP_CODE,
	NFCT_ICMP_TYPE,
	NFCT_CT_MARK,
	NFCT_CT_ID,
	NFCT_CT_EVENT,
	NFCT_FLOW_START_SEC,
	NFCT_FLOW_START_USEC,
	NFCT_FLOW_END_SEC,
	NFCT_FLOW_END_USEC,
	NFCT_OOB_FAMILY,
	NFCT_OOB_PROTOCOL,
	NFCT_CT,
};

static struct ulogd_key nfct_okeys[] = {
	{
		.type 	= ULOGD_RET_IPADDR,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "orig.ip.saddr",
		.ipfix	= {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_sourceIPv4Address,
		},
	},
	{
		.type	= ULOGD_RET_IPADDR,
		.flags	= ULOGD_RETF_NONE,
		.name	= "orig.ip.daddr",
		.ipfix	= {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_destinationIPv4Address,
		},
	},
	{
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "orig.ip.protocol",
		.ipfix	= {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_protocolIdentifier,
		},
	},
	{
		.type	= ULOGD_RET_UINT16,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "orig.l4.sport",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_sourceTransportPort,
		},
	},
	{
		.type	= ULOGD_RET_UINT16,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "orig.l4.dport",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_destinationTransportPort,
		},
	},
	{
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_RETF_NONE,
		.name	= "orig.raw.pktlen",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_octetTotalCount,
			/* FIXME: this could also be octetDeltaCount */
		},
	},
	{
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_RETF_NONE,
		.name	= "orig.raw.pktcount",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_packetTotalCount,
			/* FIXME: this could also be packetDeltaCount */
		},
	},
	{
		.type 	= ULOGD_RET_IPADDR,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "reply.ip.saddr",
		.ipfix	= {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_sourceIPv4Address,
		},
	},
	{
		.type	= ULOGD_RET_IPADDR,
		.flags	= ULOGD_RETF_NONE,
		.name	= "reply.ip.daddr",
		.ipfix	= {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_destinationIPv4Address,
		},
	},
	{
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "reply.ip.protocol",
		.ipfix	= {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_protocolIdentifier,
		},
	},
	{
		.type	= ULOGD_RET_UINT16,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "reply.l4.sport",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_sourceTransportPort,
		},
	},
	{
		.type	= ULOGD_RET_UINT16,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "reply.l4.dport",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_destinationTransportPort,
		},
	},
	{
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_RETF_NONE,
		.name	= "reply.raw.pktlen",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_octetTotalCount,
			/* FIXME: this could also be octetDeltaCount */
		},
	},
	{
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_RETF_NONE,
		.name	= "reply.raw.pktcount",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_packetTotalCount,
			/* FIXME: this could also be packetDeltaCount */
		},
	},
	{
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "icmp.code",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_icmpCodeIPv4,
		},
	},
	{
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "icmp.type",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_icmpTypeIPv4,
		},
	},
	{
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "ct.mark",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_NETFILTER,
			.field_id	= IPFIX_NF_mark,
		},
	},
	{
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "ct.id",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_NETFILTER,
			.field_id	= IPFIX_NF_conntrack_id,
		},
	},
	{
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "ct.event",
	},

	{
		.type 	= ULOGD_RET_UINT32,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "flow.start.sec",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_flowStartSeconds,
		},
	},
	{
		.type 	= ULOGD_RET_UINT32,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "flow.start.usec",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_flowStartMicroSeconds,
		},
	},
	{
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "flow.end.sec",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_flowEndSeconds,
		},
	},
	{
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "flow.end.usec",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_flowEndSeconds,
		},
	},
	{
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "oob.family",
	},
	{
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "oob.protocol",
	},
	{
		.type	= ULOGD_RET_RAW,
		.flags	= ULOGD_RETF_NONE,
		.name	= "ct",
	},
};

static uint32_t
__hash4(const struct nf_conntrack *ct, const struct hashtable *table)
{
	unsigned int a, b;

	a = jhash(nfct_get_attr(ct, ATTR_ORIG_IPV4_SRC), sizeof(uint32_t),
		  ((nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO) << 16) |
		   (nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO))));

	b = jhash(nfct_get_attr(ct, ATTR_ORIG_IPV4_DST), sizeof(uint32_t),
		  ((nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC) << 16) |
		   (nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST))));

	/*
	 * Instead of returning hash % table->hashsize (implying a divide)
	 * we return the high 32 bits of the (hash * table->hashsize) that will
	 * give results between [0 and hashsize-1] and same hash distribution,
	 * but using a multiply, less expensive than a divide. See:
	 * http://www.mail-archive.com/netdev@vger.kernel.org/msg56623.html
	 */
	return ((uint64_t)jhash_2words(a, b, 0) * table->hashsize) >> 32;
}

static uint32_t
__hash6(const struct nf_conntrack *ct, const struct hashtable *table)
{
	unsigned int a, b;

	a = jhash(nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC), sizeof(uint32_t)*4,
		  ((nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO) << 16) |
		   (nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO))));

	b = jhash(nfct_get_attr(ct, ATTR_ORIG_IPV6_DST), sizeof(uint32_t)*4,
		  ((nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC) << 16) |
		   (nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST))));

	return ((uint64_t)jhash_2words(a, b, 0) * table->hashsize) >> 32;
}

static uint32_t hash(const void *data, const struct hashtable *table)
{
	int ret = 0;
	const struct nf_conntrack *ct = data;

	switch(nfct_get_attr_u8(ct, ATTR_L3PROTO)) {
		case AF_INET:
			ret = __hash4(ct, table);
			break;
		case AF_INET6:
			ret = __hash6(ct, table);
			break;
		default:
			break;
	}

	return ret;
}

static int compare(const void *data1, const void *data2)
{
	const struct ct_timestamp *u1 = data1;
	const struct nf_conntrack *ct = data2;

	return nfct_cmp(u1->ct, ct, NFCT_CMP_ORIG | NFCT_CMP_REPL);
}

/* only the main_upi plugin instance contains the correct private data. */
static int propagate_ct(struct ulogd_pluginstance *main_upi,
			struct ulogd_pluginstance *upi,
			struct nf_conntrack *ct,
			int type,
			struct ct_timestamp *ts)
{
	struct ulogd_key *ret = upi->output.keys;
	struct nfct_pluginstance *cpi =
			(struct nfct_pluginstance *) main_upi->private;

	okey_set_u32(&ret[NFCT_CT_EVENT], type);
	okey_set_u8(&ret[NFCT_OOB_FAMILY], nfct_get_attr_u8(ct, ATTR_L3PROTO));
	okey_set_u8(&ret[NFCT_OOB_PROTOCOL], 0); /* FIXME */

	switch (nfct_get_attr_u8(ct, ATTR_L3PROTO)) {
	case AF_INET:
		okey_set_u32(&ret[NFCT_ORIG_IP_SADDR],
			     nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC));
		okey_set_u32(&ret[NFCT_ORIG_IP_DADDR],
			     nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST));
		okey_set_u32(&ret[NFCT_REPLY_IP_SADDR],
			     nfct_get_attr_u32(ct, ATTR_REPL_IPV4_SRC));
		okey_set_u32(&ret[NFCT_REPLY_IP_DADDR],
			     nfct_get_attr_u32(ct, ATTR_REPL_IPV4_DST));
		break;
	case AF_INET6:
		okey_set_u128(&ret[NFCT_ORIG_IP_SADDR],
			      nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC));
		okey_set_u128(&ret[NFCT_ORIG_IP_DADDR],
			      nfct_get_attr(ct, ATTR_ORIG_IPV6_DST));
		okey_set_u128(&ret[NFCT_REPLY_IP_SADDR],
			      nfct_get_attr(ct, ATTR_REPL_IPV6_SRC));
		okey_set_u128(&ret[NFCT_REPLY_IP_DADDR],
			      nfct_get_attr(ct, ATTR_REPL_IPV6_DST));
		break;
	default:
		ulogd_log(ULOGD_NOTICE, "Unknown protocol family (%d)\n",
			  nfct_get_attr_u8(ct, ATTR_L3PROTO));
	}
	okey_set_u8(&ret[NFCT_ORIG_IP_PROTOCOL],
		    nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO));
	okey_set_u8(&ret[NFCT_REPLY_IP_PROTOCOL],
		    nfct_get_attr_u8(ct, ATTR_REPL_L4PROTO));

	switch (nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO)) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
	case IPPROTO_SCTP:
	case IPPROTO_DCCP:
		okey_set_u16(&ret[NFCT_ORIG_L4_SPORT],
			     htons(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC)));
		okey_set_u16(&ret[NFCT_ORIG_L4_DPORT],
			     htons(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST)));
		break;
	case IPPROTO_ICMP:
		okey_set_u16(&ret[NFCT_ICMP_CODE],
			     nfct_get_attr_u8(ct, ATTR_ICMP_CODE));
		okey_set_u16(&ret[NFCT_ICMP_TYPE],
			     nfct_get_attr_u8(ct, ATTR_ICMP_TYPE));
		break;
	}

	switch (nfct_get_attr_u8(ct, ATTR_REPL_L4PROTO)) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
	case IPPROTO_SCTP:
	case IPPROTO_DCCP:
		okey_set_u16(&ret[NFCT_REPLY_L4_SPORT],
			     htons(nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC)));
		okey_set_u16(&ret[NFCT_REPLY_L4_DPORT],
			     htons(nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST)));
	}

	okey_set_u64(&ret[NFCT_ORIG_RAW_PKTLEN],
		     nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_BYTES));
	okey_set_u64(&ret[NFCT_ORIG_RAW_PKTCOUNT],
		     nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_PACKETS));
	okey_set_u64(&ret[NFCT_REPLY_RAW_PKTLEN],
		     nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_BYTES));
	okey_set_u64(&ret[NFCT_REPLY_RAW_PKTCOUNT],
		     nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_PACKETS));

	okey_set_u32(&ret[NFCT_CT_MARK], nfct_get_attr_u32(ct, ATTR_MARK));
	okey_set_u32(&ret[NFCT_CT_ID], nfct_get_attr_u32(ct, ATTR_ID));

	if (ts) {
		if (ts->time[START].tv_sec) {
			okey_set_u32(&ret[NFCT_FLOW_START_SEC],
				     ts->time[START].tv_sec);
			okey_set_u32(&ret[NFCT_FLOW_START_USEC],
				     ts->time[START].tv_usec);
		}
		if (ts->time[STOP].tv_sec) {
			okey_set_u32(&ret[NFCT_FLOW_END_SEC],
				     ts->time[STOP].tv_sec);
			okey_set_u32(&ret[NFCT_FLOW_END_USEC],
				     ts->time[STOP].tv_usec);
		}
	}
	okey_set_ptr(&ret[NFCT_CT], cpi->ct);

	ulogd_propagate_results(upi);

	return 0;
}

static void
do_propagate_ct(struct ulogd_pluginstance *upi,
		struct nf_conntrack *ct,
		int type,
		struct ct_timestamp *ts)
{
	struct ulogd_pluginstance *npi = NULL;
	struct nfct_pluginstance *cpi =
			(struct nfct_pluginstance *) upi->private;

	/* we copy the conntrack object to the plugin cache.
	 * Thus, we only copy the object once, then it is used 
	 * by the several output plugin instance that reference 
	 * it by means of a pointer. */
	nfct_copy(cpi->ct, ct, NFCT_CP_OVERRIDE);

	/* since we support the re-use of one instance in
	 * several different stacks, we duplicate the message
	 * to let them know */
	llist_for_each_entry(npi, &upi->plist, plist) {
		if (propagate_ct(upi, npi, ct, type, ts) != 0)
			break;
	}

	propagate_ct(upi, upi, ct, type, ts);
}

static void set_timestamp_from_ct(struct ct_timestamp *ts,
				   struct nf_conntrack *ct, int name)
{
	int attr_name;

	if (name == START)
		attr_name = ATTR_TIMESTAMP_START;
	else
		attr_name = ATTR_TIMESTAMP_STOP;

	if (nfct_attr_is_set(ct, attr_name)) {
		ts->time[name].tv_sec =
		     nfct_get_attr_u64(ct, attr_name) / NSEC_PER_SEC;
		ts->time[name].tv_usec =
		     (nfct_get_attr_u64(ct, attr_name) % NSEC_PER_SEC) / 1000;
	} else
		gettimeofday(&ts->time[name], NULL);
}

static int
event_handler_hashtable(enum nf_conntrack_msg_type type,
			struct nf_conntrack *ct, void *data)
{
	struct ulogd_pluginstance *upi = data;
	struct nfct_pluginstance *cpi =
				(struct nfct_pluginstance *) upi->private;
	struct ct_timestamp *ts;
	int ret, id;

	switch(type) {
	case NFCT_T_NEW:
		ts = calloc(sizeof(struct ct_timestamp), 1);
		if (ts == NULL)
			return NFCT_CB_CONTINUE;

		ts->ct = ct;

		set_timestamp_from_ct(ts, ct, START);
		id = hashtable_hash(cpi->ct_active, ct);
		ret = hashtable_add(cpi->ct_active, &ts->hashnode, id);
		if (ret < 0) {
			free(ts);
			return NFCT_CB_CONTINUE;
		}
		return NFCT_CB_STOLEN;
	case NFCT_T_UPDATE:
		id = hashtable_hash(cpi->ct_active, ct);
		ts = (struct ct_timestamp *)
			hashtable_find(cpi->ct_active, ct, id);
		if (ts)
			nfct_copy(ts->ct, ct, NFCT_CP_META);
		else {
			ts = calloc(sizeof(struct ct_timestamp), 1);
			if (ts == NULL)
				return NFCT_CB_CONTINUE;

			ts->ct = ct;
			set_timestamp_from_ct(ts, ct, START);
			ret = hashtable_add(cpi->ct_active, &ts->hashnode, id);
			if (ret < 0) {
				free(ts);
				return NFCT_CB_CONTINUE;
			}
			return NFCT_CB_STOLEN;
		}
		break;
	case NFCT_T_DESTROY:
		id = hashtable_hash(cpi->ct_active, ct);
		ts = (struct ct_timestamp *)
			hashtable_find(cpi->ct_active, ct, id);
		if (ts) {
			set_timestamp_from_ct(ts, ct, STOP);
			do_propagate_ct(upi, ct, type, ts);
			hashtable_del(cpi->ct_active, &ts->hashnode);
			nfct_destroy(ts->ct);
			free(ts);
		} else {
			struct ct_timestamp tmp = {
				.ct = ct,
			};
			set_timestamp_from_ct(&tmp, ct, STOP);
			tmp.time[START].tv_sec = 0;
			tmp.time[START].tv_usec = 0;
			do_propagate_ct(upi, ct, type, &tmp);
		}
		break;
	default:
		ulogd_log(ULOGD_NOTICE, "unknown netlink message type\n");
		break;
	}

	return NFCT_CB_CONTINUE;
}

static int
event_handler_no_hashtable(enum nf_conntrack_msg_type type,
			   struct nf_conntrack *ct, void *data)
{
	struct ulogd_pluginstance *upi = data;
	struct ct_timestamp tmp = {
		.ct = ct,
	};

	switch(type) {
	case NFCT_T_NEW:
		set_timestamp_from_ct(&tmp, ct, START);
		tmp.time[STOP].tv_sec = 0;
		tmp.time[STOP].tv_usec = 0;
		break;
	case NFCT_T_DESTROY:
		set_timestamp_from_ct(&tmp, ct, STOP);
		tmp.time[START].tv_sec = 0;
		tmp.time[START].tv_usec = 0;
		break;
	default:
		ulogd_log(ULOGD_NOTICE, "unsupported message type\n");
		return NFCT_CB_CONTINUE;
	}
	do_propagate_ct(upi, ct, type, &tmp);
	return NFCT_CB_CONTINUE;
}

static int
polling_handler(enum nf_conntrack_msg_type type,
		struct nf_conntrack *ct, void *data)
{
	struct ulogd_pluginstance *upi = data;
	struct nfct_pluginstance *cpi =
				(struct nfct_pluginstance *) upi->private;
	struct ct_timestamp *ts;
	int ret, id;

	switch(type) {
	case NFCT_T_UPDATE:
		id = hashtable_hash(cpi->ct_active, ct);
		ts = (struct ct_timestamp *)
			hashtable_find(cpi->ct_active, ct, id);
		if (ts)
			nfct_copy(ts->ct, ct, NFCT_CP_META);
		else {
			ts = calloc(sizeof(struct ct_timestamp), 1);
			if (ts == NULL)
				return NFCT_CB_CONTINUE;

			ts->ct = ct;
			set_timestamp_from_ct(ts, ct, START);

			ret = hashtable_add(cpi->ct_active, &ts->hashnode, id);
			if (ret < 0) {
				free(ts);
				return NFCT_CB_CONTINUE;
			}
			return NFCT_CB_STOLEN;
		}
		break;
	default:
		ulogd_log(ULOGD_NOTICE, "unknown netlink message type\n");
		break;
	}

	return NFCT_CB_CONTINUE;
}

static int setnlbufsiz(struct ulogd_pluginstance *upi, int size)
{
	struct nfct_pluginstance *cpi =
			(struct nfct_pluginstance *)upi->private;
	static int warned = 0;

	if (size < nlsockbufmaxsize_ce(upi->config_kset).u.value) {
		cpi->nlbufsiz = nfnl_rcvbufsiz(nfct_nfnlh(cpi->cth), size);
		return 1;
	}

	/* we have already warned the user, do not keep spamming */
	if (warned)
		return 0;

	warned = 1;
	ulogd_log(ULOGD_NOTICE, "Maximum buffer size (%d) in NFCT has been "
				"reached. Please, consider rising "
				"`netlink_socket_buffer_size` and "
				"`netlink_socket_buffer_maxsize` "
				"clauses.\n", cpi->nlbufsiz);
	return 0;
}

static int read_cb_nfct(int fd, unsigned int what, void *param)
{
	struct nfct_pluginstance *cpi = (struct nfct_pluginstance *) param;
	struct ulogd_pluginstance *upi = container_of(param,
						      struct ulogd_pluginstance,
						      private);
	static int warned = 0;

	if (!(what & ULOGD_FD_READ))
		return 0;

	if (nfct_catch(cpi->cth) == -1) {
		if (errno == ENOBUFS) {
			if (nlsockbufmaxsize_ce(upi->config_kset).u.value) {
				int s = cpi->nlbufsiz * 2;
				if (setnlbufsiz(upi, s)) {
					ulogd_log(ULOGD_NOTICE,
						  "We are losing events, "
						  "increasing buffer size "
						  "to %d\n", cpi->nlbufsiz);
				}
			} else if (!warned) {
				warned = 1;
				ulogd_log(ULOGD_NOTICE,
					  "We are losing events. Please, "
					  "consider using the clauses "
					  "`netlink_socket_buffer_size' and "
					  "`netlink_socket_buffer_maxsize'\n");
			}

			/* internal hash can deal with refresh */
			if (usehash_ce(upi->config_kset).u.value != 0) {
				/* schedule a resynchronization in N
				 * seconds, this parameter is configurable
				 * via config. Note that we don't re-schedule
				 * a resync if it's already in progress. */
				if (!ulogd_timer_pending(&cpi->ov_timer)) {
					ulogd_add_timer(&cpi->ov_timer,
							nlresynctimeout_ce(upi->config_kset).u.value);
				}
			}
		}
	}

	return 0;
}

static int do_free(void *data1, void *data2)
{
	struct ct_timestamp *ts = data2;
	nfct_destroy(ts->ct);
	free(ts);
	return 0;
}


static int do_purge(void *data1, void *data2)
{
	int ret;
	struct ulogd_pluginstance *upi = data1;
	struct ct_timestamp *ts = data2;
	struct nfct_pluginstance *cpi =
				(struct nfct_pluginstance *) upi->private;

	/* if it is not in kernel anymore, purge it */
	ret = nfct_query(cpi->pgh, NFCT_Q_GET, ts->ct);
	if (ret == -1 && errno == ENOENT) {
		do_propagate_ct(upi, ts->ct, NFCT_T_DESTROY, ts);
		hashtable_del(cpi->ct_active, &ts->hashnode);
		nfct_destroy(ts->ct);
		free(ts);
	}

	return 0;
}

static int overrun_handler(enum nf_conntrack_msg_type type,
			   struct nf_conntrack *ct,
			   void *data)
{
	struct ulogd_pluginstance *upi = data;
	struct nfct_pluginstance *cpi =
				(struct nfct_pluginstance *) upi->private;
	struct ct_timestamp *ts;
	int id, ret;

	id = hashtable_hash(cpi->ct_active, ct);
	ts = (struct ct_timestamp *)
		hashtable_find(cpi->ct_active, ct, id);
	if (ts == NULL) {
		ts = calloc(sizeof(struct ct_timestamp), 1);
		if (ts == NULL)
			return NFCT_CB_CONTINUE;

		ts->ct = ct;
		set_timestamp_from_ct(ts, ct, START);

		ret = hashtable_add(cpi->ct_active, &ts->hashnode, id);
		if (ret < 0) {
			free(ts);
			return NFCT_CB_CONTINUE;
		}
		return NFCT_CB_STOLEN;
	}

	return NFCT_CB_CONTINUE;
}

static int read_cb_ovh(int fd, unsigned int what, void *param)
{
	struct nfct_pluginstance *cpi = (struct nfct_pluginstance *) param;
	struct ulogd_pluginstance *upi = container_of(param,
						      struct ulogd_pluginstance,
						      private);

	if (!(what & ULOGD_FD_READ))
		return 0;

	/* handle the resync request, update our hashtable */
	if (nfct_catch(cpi->ovh) == -1) {
		/* enobufs in the overrun buffer? very rare */
		if (errno == ENOBUFS) {
			if (!ulogd_timer_pending(&cpi->ov_timer)) {
				ulogd_add_timer(&cpi->ov_timer,
						nlresynctimeout_ce(upi->config_kset).u.value);
			}
		}
	}

	/* purge unexistent entries */
	hashtable_iterate(cpi->ct_active, upi, do_purge);

	return 0;
}

static int
dump_reset_handler(enum nf_conntrack_msg_type type,
		   struct nf_conntrack *ct, void *data)
{
	struct ulogd_pluginstance *upi = data;
	struct nfct_pluginstance *cpi =
			(struct nfct_pluginstance *)upi->private;
	int ret = NFCT_CB_CONTINUE, rc, id;
	struct ct_timestamp *ts;

	switch(type) {
	case NFCT_T_UPDATE:
		id = hashtable_hash(cpi->ct_active, ct);
		ts = (struct ct_timestamp *)
			hashtable_find(cpi->ct_active, ct, id);
		if (ts)
			nfct_copy(ts->ct, ct, NFCT_CP_META);
		else {
			ts = calloc(sizeof(struct ct_timestamp), 1);
			if (ts == NULL)
				return NFCT_CB_CONTINUE;

			ts->ct = ct;
			set_timestamp_from_ct(ts, ct, START);

			rc = hashtable_add(cpi->ct_active, &ts->hashnode, id);
			if (rc < 0) {
				free(ts);
				return NFCT_CB_CONTINUE;
			}
			ret = NFCT_CB_STOLEN;
		}
		do_propagate_ct(upi, ct, type, ts);
		break;
	default:
		ulogd_log(ULOGD_NOTICE, "unknown netlink message type\n");
		break;
	}
	return ret;
}

static void get_ctr_zero(struct ulogd_pluginstance *upi)
{
	struct nfct_handle *h;
	int family = AF_UNSPEC;

	h = nfct_open(CONNTRACK, 0);
	if (h == NULL) {
		ulogd_log(ULOGD_FATAL, "Cannot dump and reset counters\n");
		return;
	}
	nfct_callback_register(h, NFCT_T_ALL, &dump_reset_handler, upi);
	if (nfct_query(h, NFCT_Q_DUMP_RESET, &family) == -1)
		ulogd_log(ULOGD_FATAL, "Cannot dump and reset counters\n");

	nfct_close(h);
}

static void polling_timer_cb(struct ulogd_timer *t, void *data)
{
	struct ulogd_pluginstance *upi = data;
	struct nfct_pluginstance *cpi =
			(struct nfct_pluginstance *)upi->private;
	int family = AF_UNSPEC;

	nfct_query(cpi->pgh, NFCT_Q_DUMP, &family);
	hashtable_iterate(cpi->ct_active, upi, do_purge);
	ulogd_add_timer(&cpi->timer, pollint_ce(upi->config_kset).u.value);
}

static int configure_nfct(struct ulogd_pluginstance *upi,
			  struct ulogd_pluginstance_stack *stack)
{
	int ret;

	ret = config_parse_file(upi->id, upi->config_kset);
	if (ret < 0)
		return ret;

	return 0;
}

static void overrun_timeout(struct ulogd_timer *a, void *data)
{
	int family = AF_UNSPEC;
	struct ulogd_pluginstance *upi = data;
	struct nfct_pluginstance *cpi =
			(struct nfct_pluginstance *)upi->private;

	nfct_send(cpi->ovh, NFCT_Q_DUMP, &family);
}


#define NFCT_SRC_DIR 1
#define NFCT_DST_DIR 2

static inline int nfct_set_dir(int dir, int *filter_dir_ipv4, int *filter_dir_ipv6)
{
	switch (dir) {
		case NFCT_DST_DIR:
			*filter_dir_ipv4 = NFCT_FILTER_DST_IPV4;
			*filter_dir_ipv6 = NFCT_FILTER_DST_IPV6;
			break;
		case NFCT_SRC_DIR:
			*filter_dir_ipv4 = NFCT_FILTER_SRC_IPV4;
			*filter_dir_ipv6 = NFCT_FILTER_SRC_IPV6;
			break;
		default:
			ulogd_log(ULOGD_FATAL,
					"Invalid direction %d\n",
					dir);
			return -1;
	}
	return 0;
}

static int nfct_add_to_filter(struct nfct_filter *filter,
			      struct ulogd_addr *addr,
			      int l3, int dir)
{
	int filter_dir_ipv4;
	int filter_dir_ipv6;

	if (nfct_set_dir(dir, &filter_dir_ipv4, &filter_dir_ipv6) == -1)
		return -1;

	switch (l3) {
		case AF_INET6:
			{
				struct nfct_filter_ipv6 filter_ipv6;
				/* BSF always wants data in host-byte order */
				ulogd_ipv6_addr2addr_host(addr->in.ipv6, filter_ipv6.addr);
				ulogd_ipv6_cidr2mask_host(addr->netmask, filter_ipv6.mask);

				nfct_filter_set_logic(filter,
						filter_dir_ipv6,
						NFCT_FILTER_LOGIC_POSITIVE);
				nfct_filter_add_attr(filter,
						filter_dir_ipv6,
						&filter_ipv6);
			}
			break;
		case AF_INET:
			{
				/* BSF always wants data in host-byte order */
				struct nfct_filter_ipv4 filter_ipv4 = {
					.addr = ntohl(addr->in.ipv4),
					.mask = ulogd_bits2netmask(addr->netmask),
				};

				nfct_filter_set_logic(filter,
						filter_dir_ipv4,
						NFCT_FILTER_LOGIC_POSITIVE);
				nfct_filter_add_attr(filter, filter_dir_ipv4,
						&filter_ipv4);
			}
			break;
		default:
			ulogd_log(ULOGD_FATAL, "Invalid protocol %d\n", l3);
			return -1;
	}
	return 0;
}

static int build_nfct_filter_dir(struct nfct_filter *filter, char* filter_string, int dir)
{
	char *from = filter_string;
	char *comma;
	struct ulogd_addr addr;
	int has_ipv4 = 0;
	int has_ipv6 = 0;

	while ((comma = strchr(from, ',')) != NULL) {
		size_t len = comma - from;
		switch(ulogd_parse_addr(from, len, &addr)) {
			case AF_INET:
				nfct_add_to_filter(filter, &addr, AF_INET, dir);
				has_ipv4 = 1;
				break;
			case AF_INET6:
				nfct_add_to_filter(filter, &addr, AF_INET6, dir);
				has_ipv6 = 1;
				break;
			default:
				return -1;
		}
		from += len + 1;
	}
	switch(ulogd_parse_addr(from, strlen(from), &addr)) {
		case AF_INET:
			nfct_add_to_filter(filter, &addr, AF_INET, dir);
			has_ipv4 = 1;
			break;
		case AF_INET6:
			nfct_add_to_filter(filter, &addr, AF_INET6, dir);
			has_ipv6 = 1;
			break;
		default:
			return -1;
	}

	if (!has_ipv6) {
		struct nfct_filter_ipv6 filter_ipv6;
		int filter_dir_ipv4;
		int filter_dir_ipv6;
		if (nfct_set_dir(dir, &filter_dir_ipv4, &filter_dir_ipv6) == -1)
			return -1;
		nfct_filter_set_logic(filter,
				filter_dir_ipv6,
				NFCT_FILTER_LOGIC_NEGATIVE);
		nfct_filter_add_attr(filter, filter_dir_ipv6,
				&filter_ipv6);
	}
	if (!has_ipv4) {
		struct nfct_filter_ipv4 filter_ipv4;
		int filter_dir_ipv4;
		int filter_dir_ipv6;
		if (nfct_set_dir(dir, &filter_dir_ipv4, &filter_dir_ipv6) == -1)
			return -1;
		nfct_filter_set_logic(filter,
				filter_dir_ipv4,
				NFCT_FILTER_LOGIC_NEGATIVE);
		nfct_filter_add_attr(filter, filter_dir_ipv4,
				&filter_ipv4);
	}

	return 0;
}

static int build_nfct_filter_proto(struct nfct_filter *filter, char* filter_string)
{
	char *from = filter_string;
	char *comma;
	struct protoent * pent = NULL;

	while ((comma = strchr(from, ',')) != NULL) {
		size_t len = comma - from;
		*comma = 0;
		pent = getprotobyname(from);
		if (pent == NULL) {
			ulogd_log(ULOGD_FATAL, "Unknown protocol\n");
			endprotoent();
			return -1;
		}
		ulogd_log(ULOGD_NOTICE, "adding proto to filter: \"%s\" (%d)\n",
			  pent->p_name, pent->p_proto
		 );
		nfct_filter_add_attr_u32(filter, NFCT_FILTER_L4PROTO,
					 pent->p_proto);
		from += len + 1;
	}
	pent = getprotobyname(from);
	if (pent == NULL) {
		ulogd_log(ULOGD_FATAL, "Unknown protocol %s\n", from);
		endprotoent();
		return -1;
	}
	ulogd_log(ULOGD_NOTICE, "adding proto to filter: \"%s (%d)\"\n",
			pent->p_name, pent->p_proto
		 );
	nfct_filter_add_attr_u32(filter, NFCT_FILTER_L4PROTO,
			pent->p_proto);


	endprotoent();
	return 0;
}


static int build_nfct_filter(struct ulogd_pluginstance *upi)
{
	struct nfct_pluginstance *cpi =
			(struct nfct_pluginstance *)upi->private;
	struct nfct_filter *filter = NULL;

	if (!cpi->cth) {
		ulogd_log(ULOGD_FATAL, "Refusing to attach NFCT filter to NULL handler\n");
		goto err_init;
	}

	filter = nfct_filter_create();
	if (!filter) {
		ulogd_log(ULOGD_FATAL, "error creating NFCT filter\n");
		goto err_init;
	}

	if (strlen(src_filter_ce(upi->config_kset).u.string) != 0) {
		char *filter_string = src_filter_ce(upi->config_kset).u.string;
		if (build_nfct_filter_dir(filter, filter_string, NFCT_SRC_DIR) != 0) {
			ulogd_log(ULOGD_FATAL,
					"Unable to create src filter\n");
			goto err_filter;
		}
	}
	if (strlen(dst_filter_ce(upi->config_kset).u.string) != 0) {
		char *filter_string = dst_filter_ce(upi->config_kset).u.string;
		if (build_nfct_filter_dir(filter, filter_string, NFCT_DST_DIR) != 0) {
			ulogd_log(ULOGD_FATAL,
					"Unable to create dst filter\n");
			goto err_filter;
		}
	}
	if (strlen(proto_filter_ce(upi->config_kset).u.string) != 0) {
		char *filter_string = proto_filter_ce(upi->config_kset).u.string;
		if (build_nfct_filter_proto(filter, filter_string) != 0) {
			ulogd_log(ULOGD_FATAL,
					"Unable to create proto filter\n");
			goto err_filter;
		}
	}

	if (filter) {
		if (nfct_filter_attach(nfct_fd(cpi->cth), filter) == -1) {
			ulogd_log(ULOGD_FATAL, "nfct_filter_attach");
		}

		/* release the filter object, this does not detach the filter */
		nfct_filter_destroy(filter);
	}

	return 0;

err_filter:
	nfct_filter_destroy(filter);
err_init:
	return -1;
}

static int constructor_nfct_events(struct ulogd_pluginstance *upi)
{
	struct nfct_pluginstance *cpi =
			(struct nfct_pluginstance *)upi->private;


	cpi->cth = nfct_open(NFNL_SUBSYS_CTNETLINK,
			     eventmask_ce(upi->config_kset).u.value);
	if (!cpi->cth) {
		ulogd_log(ULOGD_FATAL, "error opening ctnetlink\n");
		goto err_cth;
	}

	if ((strlen(src_filter_ce(upi->config_kset).u.string) != 0) ||
		(strlen(dst_filter_ce(upi->config_kset).u.string) != 0) ||
		(strlen(proto_filter_ce(upi->config_kset).u.string) != 0)
	   ) {
		if (build_nfct_filter(upi) != 0) {
			ulogd_log(ULOGD_FATAL, "error creating NFCT filter\n");
			goto err_cth;
		}
	}


	if (usehash_ce(upi->config_kset).u.value != 0) {
		nfct_callback_register(cpi->cth, NFCT_T_ALL,
				&event_handler_hashtable, upi);
	} else {
		nfct_callback_register(cpi->cth, NFCT_T_ALL,
				       &event_handler_no_hashtable, upi);
	}

	if (nlsockbufsize_ce(upi->config_kset).u.value) {
		setnlbufsiz(upi, nlsockbufsize_ce(upi->config_kset).u.value);
		ulogd_log(ULOGD_NOTICE, "NFCT netlink buffer size has been "
					"set to %d\n", cpi->nlbufsiz);
	}

	if (reliable_ce(upi->config_kset).u.value != 0) {
		int on = 1;

		setsockopt(nfct_fd(cpi->cth), SOL_NETLINK,
				NETLINK_BROADCAST_SEND_ERROR, &on, sizeof(int));
		setsockopt(nfct_fd(cpi->cth), SOL_NETLINK,
				NETLINK_NO_ENOBUFS, &on, sizeof(int));
		ulogd_log(ULOGD_NOTICE, "NFCT reliable logging "
					"has been enabled.");
	}
	cpi->nfct_fd.fd = nfct_fd(cpi->cth);
	cpi->nfct_fd.cb = &read_cb_nfct;
	cpi->nfct_fd.data = cpi;
	cpi->nfct_fd.when = ULOGD_FD_READ;

	ulogd_register_fd(&cpi->nfct_fd);

	cpi->ct = nfct_new();
	if (cpi->ct == NULL)
		goto err_nfctobj;

	if (usehash_ce(upi->config_kset).u.value != 0) {
		int family = AF_UNSPEC;
		struct nfct_handle *h;

		/* we use a hashtable to cache entries in userspace. */
		cpi->ct_active =
		     hashtable_create(buckets_ce(upi->config_kset).u.value,
				      maxentries_ce(upi->config_kset).u.value,
				      hash,
				      compare);
		if (!cpi->ct_active) {
			ulogd_log(ULOGD_FATAL, "error allocating hash\n");
			goto err_hashtable;
		}

		/* populate the hashtable: we use a disposable handler, we
		 * may hit overrun if we use cpi->cth. This ensures that the
		 * initial dump is successful. */
		h = nfct_open(CONNTRACK, 0);
		if (!h) {
			ulogd_log(ULOGD_FATAL, "error opening ctnetlink\n");
			goto err_ovh;
		}
		nfct_callback_register(h, NFCT_T_ALL,
				       &event_handler_hashtable, upi);
		nfct_query(h, NFCT_Q_DUMP, &family);
		nfct_close(h);

		/* the overrun handler only make sense with the hashtable,
		 * if we hit overrun, we resync with ther kernel table. */
		cpi->ovh = nfct_open(NFNL_SUBSYS_CTNETLINK, 0);
		if (!cpi->ovh) {
			ulogd_log(ULOGD_FATAL, "error opening ctnetlink\n");
			goto err_ovh;
		}

		nfct_callback_register(cpi->ovh, NFCT_T_ALL,
				       &overrun_handler, upi);

		ulogd_init_timer(&cpi->ov_timer, upi, overrun_timeout);

		cpi->nfct_ov.fd = nfct_fd(cpi->ovh);
		cpi->nfct_ov.cb = &read_cb_ovh;
		cpi->nfct_ov.data = cpi;
		cpi->nfct_ov.when = ULOGD_FD_READ;

		ulogd_register_fd(&cpi->nfct_ov);

		/* we use this to purge old entries during overruns.*/
		cpi->pgh = nfct_open(NFNL_SUBSYS_CTNETLINK, 0);
		if (!cpi->pgh) {
			ulogd_log(ULOGD_FATAL, "error opening ctnetlink\n");
			goto err_pgh;
		}
	}

	ulogd_log(ULOGD_NOTICE, "NFCT plugin working in event mode\n");
	return 0;

err_pgh:
	ulogd_unregister_fd(&cpi->nfct_ov);
	nfct_close(cpi->ovh);
err_ovh:
	hashtable_destroy(cpi->ct_active);
err_hashtable:
	nfct_destroy(cpi->ct);
err_nfctobj:
	ulogd_unregister_fd(&cpi->nfct_fd);
	nfct_close(cpi->cth);
err_cth:
	return -1;
}

static int constructor_nfct_polling(struct ulogd_pluginstance *upi)
{
	struct nfct_pluginstance *cpi =
			(struct nfct_pluginstance *)upi->private;

	if (usehash_ce(upi->config_kset).u.value == 0) {
		ulogd_log(ULOGD_FATAL, "NFCT polling mode requires "
				       "the hashtable\n");
		goto err;
	}

	cpi->pgh = nfct_open(NFNL_SUBSYS_CTNETLINK, 0);
	if (!cpi->pgh) {
		ulogd_log(ULOGD_FATAL, "error opening ctnetlink\n");
		goto err;
	}
	nfct_callback_register(cpi->pgh, NFCT_T_ALL, &polling_handler, upi);

	cpi->ct_active =
	     hashtable_create(buckets_ce(upi->config_kset).u.value,
			      maxentries_ce(upi->config_kset).u.value,
			      hash,
			      compare);
	if (!cpi->ct_active) {
		ulogd_log(ULOGD_FATAL, "error allocating hash\n");
		goto err_hashtable;
	}

	cpi->ct = nfct_new();
	if (cpi->ct == NULL)
		goto err_ct_cache;

	ulogd_init_timer(&cpi->timer, upi, polling_timer_cb);
	if (pollint_ce(upi->config_kset).u.value != 0)
		ulogd_add_timer(&cpi->timer,
				pollint_ce(upi->config_kset).u.value);

	ulogd_log(ULOGD_NOTICE, "NFCT working in polling mode\n");
	return 0;

err_ct_cache:
	hashtable_destroy(cpi->ct_active);
err_hashtable:
	nfct_close(cpi->pgh);
err:
	return -1;
}

static int constructor_nfct(struct ulogd_pluginstance *upi)
{
	if (pollint_ce(upi->config_kset).u.value == 0) {
		/* listen to ctnetlink events. */
		return constructor_nfct_events(upi);
	} else {
		/* poll from ctnetlink periodically. */
		return constructor_nfct_polling(upi);
	}
	/* should not ever happen. */
	ulogd_log(ULOGD_FATAL, "invalid NFCT configuration\n");
	return -1;
}

static int destructor_nfct_events(struct ulogd_pluginstance *upi)
{
	struct nfct_pluginstance *cpi = (void *) upi->private;
	int rc;

	ulogd_unregister_fd(&cpi->nfct_fd);

	rc = nfct_close(cpi->cth);
	if (rc < 0)
		return rc;

	nfct_destroy(cpi->ct);

	if (usehash_ce(upi->config_kset).u.value != 0) {
		ulogd_del_timer(&cpi->ov_timer);
		ulogd_unregister_fd(&cpi->nfct_ov);

		rc = nfct_close(cpi->ovh);
		if (rc < 0)
			return rc;

		rc = nfct_close(cpi->pgh);
		if (rc < 0)
			return rc;

		hashtable_iterate(cpi->ct_active, NULL, do_free);
		hashtable_destroy(cpi->ct_active);
	}
	return 0;
}

static int destructor_nfct_polling(struct ulogd_pluginstance *upi)
{
	int rc;
	struct nfct_pluginstance *cpi = (void *)upi->private;

	rc = nfct_close(cpi->pgh);
	if (rc < 0)
		return rc;

	return 0;
}

static int destructor_nfct(struct ulogd_pluginstance *upi)
{
	if (pollint_ce(upi->config_kset).u.value == 0) {
		return destructor_nfct_events(upi);
	} else {
		return destructor_nfct_polling(upi);
	}
	/* should not ever happen. */
	ulogd_log(ULOGD_FATAL, "invalid NFCT configuration\n");
	return -1;
}

static void signal_nfct(struct ulogd_pluginstance *pi, int signal)
{
	switch (signal) {
	case SIGUSR2:
		get_ctr_zero(pi);
		break;
	}
}

static struct ulogd_plugin nfct_plugin = {
	.name = "NFCT",
	.input = {
		.type = ULOGD_DTYPE_SOURCE,
	},
	.output = {
		.keys = nfct_okeys,
		.num_keys = ARRAY_SIZE(nfct_okeys),
		.type = ULOGD_DTYPE_FLOW,
	},
	.config_kset 	= &nfct_kset,
	.interp 	= NULL,
	.configure	= &configure_nfct,
	.start		= &constructor_nfct,
	.stop		= &destructor_nfct,
	.signal		= &signal_nfct,
	.priv_size	= sizeof(struct nfct_pluginstance),
	.version	= VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&nfct_plugin);
}

