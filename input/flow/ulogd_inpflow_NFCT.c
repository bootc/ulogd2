/* ulogd_input_CTNL.c, Version $Revision$
 *
 * ulogd input plugin for ctnetlink
 *
 * (C) 2005 by Harald Welte <laforge@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * 10 Jan 2005, Christian Hentschel <chentschel@people.netfilter.org>
 *      Added timestamp accounting support of the conntrack entries,
 *      reworked by Harald Welte.
 *
 * TODO:
 * 	- add nanosecond-accurate packet receive timestamp of event-changing
 * 	  packets to {ip,nf}_conntrack_netlink, so we can have accurate IPFIX
 *	  flowStart / flowEnd NanoSeconds.
 *	- if using preallocated data structure, get rid of all list heads and
 *	  use per-bucket arrays instead.
 *	- SIGHUP for reconfiguration without loosing hash table contents, but
 *	  re-read of config and reallocation / rehashing of table, if required
 *	- Split hashtable code into separate [filter] plugin, so we can run 
 * 	  small non-hashtable ulogd installations on the firewall boxes, send
 * 	  the messages via IPFX to one aggregator who then runs ulogd with a 
 * 	  network wide connection hash table.
 */

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <sys/time.h>
#include <time.h>

#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/linuxlist.h>
#include <ulogd/ipfix_protocol.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include "linux_jhash.h"

#define CT_EVENTS		(NF_NETLINK_CONNTRACK_NEW \
						 | NF_NETLINK_CONNTRACK_UPDATE \
						 | NF_NETLINK_CONNTRACK_DESTROY)

#undef INADDR_LOOPBACK
#define INADDR_LOOPBACK		0x0100007f /* 127.0.0.1 */
#define INADDR_CLUSTER		0x00fa13c6 /* 198.19.250.0/24 */

#define CLASS_C_CMP(a,net)	(((a) & 0x00ffffff) == (net))


typedef enum TIMES_ { START, STOP, __TIME_MAX } TIMES;
typedef unsigned conntrack_hash_t;

struct ct_timestamp {
	struct llist_head list;
	struct nfct_tuple tuple;
	unsigned last_seq;
	struct timeval time[__TIME_MAX];
};

struct ct_htable {
	struct llist_head *buckets;
	unsigned num_buckets;
	unsigned curr_bucket;
	unsigned used;
};

struct nfct_pluginstance {
	struct nfct_handle *cth;
	struct ulogd_fd nfct_fd;
	struct ct_htable *htable;
	struct ulogd_timer timer;
	struct {
		unsigned nl_err;
		unsigned nl_ovr;
	} stats;
};

#define HTABLE_SIZE	(512)

static struct config_keyset nfct_kset = {
	.num_ces = 3,
	.ces = {
		{
			.key	 = "pollinterval",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
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
			.u.value = 0,
		},
	},
};
#define pollint_ce(x)	(x->ces[0])
#define buckets_ce(x)	(x->ces[1])

enum {
	O_IP_SADDR = 0,
	O_IP_DADDR,
	O_IP_PROTO,
	O_L4_SPORT,
	O_L4_DPORT,
	O_RAW_IN_PKTLEN,
	O_RAW_IN_PKTCOUNT,
	O_RAW_OUT_PKTLEN,
	O_RAW_OUT_PKTCOUNT,
	O_ICMP_CODE,
	O_ICMP_TYPE,
	O_CT_MARK,
	O_CT_ID,
	O_FLOW_START_SEC,
	O_FLOW_START_USEC,
	O_FLOW_START_DAY,
	O_FLOW_END_SEC,
	O_FLOW_END_USEC,
	O_FLOW_DURATION,
	__O_MAX
};

static struct ulogd_key nfct_okeys[__O_MAX] = {
	{
		.type 	= ULOGD_RET_IPADDR,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "ip.saddr",
		.ipfix	= { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_sourceIPv4Address,
		},
	},
	{
		.type	= ULOGD_RET_IPADDR,
		.flags	= ULOGD_RETF_NONE,
		.name	= "ip.daddr",
		.ipfix	= {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_destinationIPv4Address,
		},
	},
	{
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "ip.protocol",
		.ipfix	= { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_protocolIdentifier,
		},
	},
	{
		.type	= ULOGD_RET_UINT16,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "l4.sport",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_sourceTransportPort,
		},
	},
	{
		.type	= ULOGD_RET_UINT16,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "l4.dport",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_destinationTransportPort,
		},
	},
	{
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "raw.in.pktlen",
		.ipfix	= { 
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_octetTotalCount,
			/* FIXME: this could also be octetDeltaCount */
		},
	},
	{
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "raw.in.pktcount",
		.ipfix	= { 
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_packetTotalCount,
			/* FIXME: this could also be packetDeltaCount */
		},
	},
	{
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "raw.out.pktlen",
		.ipfix	= { 
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_octetTotalCount,
			/* FIXME: this could also be octetDeltaCount */
		},
	},
	{
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "raw.out.pktcount",
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
		.type 	= ULOGD_RET_UINT16,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "flow.start.day",
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
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "flow.duration",
	},
};


/* forward declarations */
static struct ct_timestamp * ct_hash_find_seq(const struct ct_htable *,
											  unsigned);
static void ct_hash_free(struct ct_htable *, struct ct_timestamp *);


static int
nl_error(struct ulogd_pluginstance *pi, struct nlmsghdr *nlh, int *err)
{
	struct nfct_pluginstance *priv = (void *)pi->private;
	struct nlmsgerr *e = NLMSG_DATA(nlh);
	struct ct_timestamp *ts;

	ts = ct_hash_find_seq(priv->htable, e->msg.nlmsg_seq);
	if (ts == NULL)
		return 0;						/* already gone */

	switch (-e->error) {
	case ENOENT:
		/* destroy message was lost (FIXME log all what we got) */
		ct_hash_free(priv->htable, ts);
		break;

	case 0:								/* "Success" */
		break;

	default:
		ulogd_log(ULOGD_ERROR, "netlink error: %s (seq %u)\n",
				  strerror(-e->error), e->msg.nlmsg_seq);
		break;
	}

	*err = -e->error;

	return 0;
}


/* this should go into its own file */
static int
nfnl_recv_msgs(struct nfnl_handle *nfnlh,
			   int (* cb)(struct nlmsghdr *, void *arg), void *arg)
{
	static unsigned char buf[NFNL_BUFFSIZE];
	struct ulogd_pluginstance *pi = arg;
	struct nfct_pluginstance *priv = (void *)pi->private;

	for (;;) {
		struct nlmsghdr *nlh = (void *)buf;
		ssize_t nread;

		nread = nfnl_recv(nfct_nfnlh(priv->cth), buf, sizeof(buf));
		if (nread < 0) {
			if (errno == EWOULDBLOCK)
				break;

			return -1;
		}

		while (NLMSG_OK(nlh, nread)) {
			int err;

			if (nlh->nlmsg_type == NLMSG_ERROR) {
				if (nl_error(pi, nlh, &err) == 0 && err != 0)
					priv->stats.nl_err++;

				break;
			}

			if (nlh->nlmsg_type == NLMSG_OVERRUN)
				priv->stats.nl_ovr++;	/* continue?  payload? */
				
			(cb)(nlh, pi);

			nlh = NLMSG_NEXT(nlh, nread);
		}
	}

	return 0;
}


static int
nfct_msg_type(const struct nlmsghdr *nlh)
{
	uint16_t type = NFNL_MSG_TYPE(nlh->nlmsg_type);
	int nfct_type;

	if (type == IPCTNL_MSG_CT_NEW) {
		if (nlh->nlmsg_flags & (NLM_F_CREATE | NLM_F_EXCL))
			nfct_type = NFCT_MSG_NEW;
		else
			nfct_type = NFCT_MSG_UPDATE;
	} else if (type == IPCTNL_MSG_CT_DELETE)
		nfct_type = NFCT_MSG_DESTROY;
	else
		nfct_type = NFCT_MSG_UNKNOWN;

	return nfct_type;
}


/* seq: sequence number used for the request */
static int
nfct_get_conntrack_x(struct nfct_handle *cth, struct nfct_tuple *t,
					 int dir, uint32_t *seq)
{
	static char buf[NFNL_BUFFSIZE];
	struct nfnlhdr *req = (void *)buf;
	int cta_dir, nbytes;

	memset(buf, 0, sizeof(buf));

	/* intendedly do not set NLM_F_ACK in order to skip the
	   ACK message (but NACKs are still send) */
	nfnl_fill_hdr(nfct_subsys_ct(cth), &req->nlh, 0, t->l3protonum,
				  0, IPCTNL_MSG_CT_GET, NLM_F_REQUEST);

	if (seq != NULL)
		*seq = req->nlh.nlmsg_seq;

	cta_dir = (dir == NFCT_DIR_ORIGINAL) ? CTA_TUPLE_ORIG : CTA_TUPLE_REPLY;

	nfct_build_tuple(req, sizeof(buf), t, cta_dir);

	nbytes = nfnl_send(nfct_nfnlh(cth), &req->nlh);

	return nbytes;
}


static conntrack_hash_t
hash_conntrack(const struct nfct_tuple *t, size_t hash_sz)
{
	static unsigned rnd;

	if (rnd == 0U)
		rnd = rand();

	return jhash_3words(t->src.v4, t->dst.v4 ^ t->protonum,
						t->l4src.all | (t->l4dst.all << 16), rnd) % hash_sz;
}

static inline bool
ct_cmp(const struct nfct_tuple *t1, const struct nfct_tuple *t2)
{
	return memcmp(t1, t2, sizeof(struct nfct_tuple)) == 0;
}


static struct ct_htable *
htable_alloc(int htable_size)
{
	struct ct_htable *htable;
	int i;

	htable = malloc(sizeof(*htable)
			+ sizeof(struct llist_head) * htable_size);
	if (!htable)
		return NULL;

	htable->buckets = (void *)htable + sizeof(*htable);
	htable->num_buckets = htable_size;
	htable->curr_bucket = 0;
	htable->used = 0;

	for (i = 0; i < htable->num_buckets; i++)
		INIT_LLIST_HEAD(&htable->buckets[i]);
	
	return htable;
}

static void
htable_free(struct ct_htable *htable)
{
	struct llist_head *ptr, *ptr2;
	int i;

	for (i = 0; i < htable->num_buckets; i++) {
		llist_for_each_safe(ptr, ptr2, &htable->buckets[i])
			free(container_of(ptr, struct ct_timestamp, list));
	}

	free(htable);
}

static struct ct_timestamp *
ct_hash_add(struct ct_htable *htable, const struct nfct_tuple *t)
{
	struct ct_timestamp *ts;
	conntrack_hash_t h;

	h = hash_conntrack(t, htable->num_buckets);

	if ((ts = calloc(1, sizeof(struct ct_timestamp))) == NULL) {
		ulogd_log(ULOGD_ERROR, "Out of memory\n");
		return NULL;
	}

	memcpy(&ts->tuple, t, sizeof(struct nfct_tuple));

	llist_add(&ts->list, &htable->buckets[h]);
	htable->used++;

	return ts;
}

static struct ct_timestamp *
ct_hash_find(struct ct_htable *htable, const struct nfct_tuple *t)
{  
	struct llist_head *ptr;
	conntrack_hash_t h = hash_conntrack(t, htable->num_buckets);

	llist_for_each(ptr, &htable->buckets[h]) {
		struct ct_timestamp *ts = container_of(ptr, struct ct_timestamp, list);

		if (ct_cmp(t, &ts->tuple))
			return ts;
	}

	return NULL;
}


static struct ct_timestamp *
ct_hash_find_seq(const struct ct_htable *htable, unsigned seq)
{
	int i;

	for (i = 0; i < htable->num_buckets; i++) {
		struct ct_timestamp *ts;

		llist_for_each_entry(ts, &htable->buckets[i], list) {
			if (ts->last_seq == seq)
				return ts;
		}
	}

	return NULL;
}


/* time diff with second resolution */
static inline unsigned
tv_diff_sec(const struct ct_timestamp *ts)
{
	if (ts->time[STOP].tv_sec >= ts->time[START].tv_sec)
		return max(ts->time[STOP].tv_sec - ts->time[START].tv_sec, 1);

	return ts->time[START].tv_sec - ts->time[STOP].tv_sec;
}

static void
ct_hash_free(struct ct_htable *htable, struct ct_timestamp *ts)
{
	llist_del(&ts->list);

	free(ts);
	htable->used--;
}

static int
propagate_ct_flow(struct ulogd_pluginstance *upi, 
				  struct nfct_conntrack *ct, unsigned int flags,
				  int dir, struct ct_timestamp *ts)
{
	struct ulogd_key *ret = upi->output.keys;

	ret[O_IP_SADDR].u.value.ui32 = htonl(ct->tuple[dir].src.v4);
	ret[O_IP_SADDR].flags |= ULOGD_RETF_VALID;

	ret[O_IP_DADDR].u.value.ui32 = htonl(ct->tuple[dir].dst.v4);
	ret[O_IP_DADDR].flags |= ULOGD_RETF_VALID;

	ret[O_IP_PROTO].u.value.ui8 = ct->tuple[dir].protonum;
	ret[O_IP_PROTO].flags |= ULOGD_RETF_VALID;

	switch (ct->tuple[dir].protonum) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_SCTP:
		/* FIXME: DCCP */
		ret[O_L4_SPORT].u.value.ui16 = htons(ct->tuple[dir].l4src.tcp.port);
		ret[O_L4_SPORT].flags |= ULOGD_RETF_VALID;
		ret[O_L4_DPORT].u.value.ui16 = htons(ct->tuple[dir].l4dst.tcp.port);
		ret[O_L4_DPORT].flags |= ULOGD_RETF_VALID;
		break;
	case IPPROTO_ICMP:
		ret[O_ICMP_CODE].u.value.ui8 = ct->tuple[dir].l4src.icmp.code;
		ret[O_ICMP_CODE].flags |= ULOGD_RETF_VALID;
		ret[O_ICMP_TYPE].u.value.ui8 = ct->tuple[dir].l4src.icmp.type;
		ret[O_ICMP_TYPE].flags |= ULOGD_RETF_VALID;
		break;
	}

	if (flags & NFCT_COUNTERS_ORIG) {
		ret[O_RAW_IN_PKTLEN].u.value.ui32 = ct->counters[0].bytes;
		ret[O_RAW_IN_PKTLEN].flags |= ULOGD_RETF_VALID;
		ret[O_RAW_IN_PKTCOUNT].u.value.ui32 = ct->counters[0].packets;
		ret[O_RAW_IN_PKTCOUNT].flags |= ULOGD_RETF_VALID;

		ret[O_RAW_OUT_PKTLEN].u.value.ui32 = ct->counters[1].bytes;
		ret[O_RAW_OUT_PKTLEN].flags |= ULOGD_RETF_VALID;
		ret[O_RAW_OUT_PKTCOUNT].u.value.ui32 = ct->counters[1].packets;
		ret[O_RAW_OUT_PKTCOUNT].flags |= ULOGD_RETF_VALID;
	}

	if (flags & NFCT_MARK) {
		ret[O_CT_MARK].u.value.ui32 = ct->mark;
		ret[O_CT_MARK].flags |= ULOGD_RETF_VALID;
	}

	if (flags & NFCT_ID) {
		ret[O_CT_ID].u.value.ui32 = ct->id;
		ret[O_CT_ID].flags |= ULOGD_RETF_VALID;
	}

	ret[O_FLOW_START_SEC].u.value.ui32 = ts->time[START].tv_sec;
	ret[O_FLOW_START_SEC].flags |= ULOGD_RETF_VALID;
	ret[O_FLOW_START_USEC].u.value.ui32 = ts->time[START].tv_usec;
	ret[O_FLOW_START_USEC].flags |= ULOGD_RETF_VALID;
	ret[O_FLOW_START_DAY].u.value.ui16 = ts->time[START].tv_sec / (1 DAY);
	ret[O_FLOW_START_DAY].flags |= ULOGD_RETF_VALID;

	ret[O_FLOW_END_SEC].u.value.ui32 = ts->time[STOP].tv_sec;
	ret[O_FLOW_END_SEC].flags |= ULOGD_RETF_VALID;
	ret[O_FLOW_END_USEC].u.value.ui32 = ts->time[STOP].tv_usec;
	ret[O_FLOW_END_USEC].flags |= ULOGD_RETF_VALID;

	ret[O_FLOW_DURATION].u.value.ui32 = tv_diff_sec(ts);
	ret[O_FLOW_DURATION].flags |= ULOGD_RETF_VALID;

	ulogd_propagate_results(upi);

	return 0;
}

static int
propagate_ct(struct ulogd_pluginstance *upi, struct nfct_conntrack *ct,
			 struct ct_timestamp *ts, unsigned int flags)
{
	struct nfct_pluginstance *priv = (void *)upi->private;

	do {
		if (ct->tuple[NFCT_DIR_ORIGINAL].src.v4 == INADDR_LOOPBACK
			|| ct->tuple[NFCT_DIR_ORIGINAL].dst.v4 == INADDR_LOOPBACK)
			break;

		if (CLASS_C_CMP(ct->tuple[NFCT_DIR_ORIGINAL].src.v4, INADDR_CLUSTER)
			|| CLASS_C_CMP(ct->tuple[NFCT_DIR_ORIGINAL].dst.v4,
						   INADDR_CLUSTER))
			break;

		gettimeofday(&ts->time[STOP], NULL);
		
		propagate_ct_flow(upi, ct, flags, NFCT_DIR_ORIGINAL, ts);
	} while (0);

	ct_hash_free(priv->htable, ts);

	return 0;
}


static int
do_nfct_msg(struct nlmsghdr *nlh, void *arg)
{
	struct ulogd_pluginstance *pi = arg;
	struct nfct_pluginstance *priv = (void *)pi->private;
	struct nfgenmsg *nfh = NLMSG_DATA(nlh);
	struct nfct_conntrack ct;
	struct ct_timestamp *ts;
	int flags, type = nfct_msg_type(nlh);

	if (type == NFCT_MSG_UNKNOWN)
		return 0;

	bzero(&ct, sizeof(ct));

	ct.tuple[NFCT_DIR_ORIGINAL].l3protonum = 
		ct.tuple[NFCT_DIR_REPLY].l3protonum = nfh->nfgen_family;

	if (nfct_netlink_to_conntrack(nlh, &ct, &flags) < 0)
		return -1;

	switch (type) { 
	case NFCT_MSG_NEW:
		ts = ct_hash_add(priv->htable, &ct.tuple[NFCT_DIR_ORIGINAL]);
		if (ts != NULL) {
			gettimeofday(&ts->time[START], NULL);
		}
		break;

	case NFCT_MSG_UPDATE:
		ts = ct_hash_find(priv->htable, &ct.tuple[NFCT_DIR_ORIGINAL]);
		if (ts == NULL) {
			/* do not add CT to cache, as there would be no start
			   information */
			break;
		}

		/* handle TCP connections differently in order not to bloat CT
		   hash with many TIME_WAIT connections */
		if (ct.tuple[NFCT_DIR_ORIGINAL].protonum == IPPROTO_TCP) {
			if (ct.protoinfo.tcp.state == TCP_CONNTRACK_TIME_WAIT)
				return propagate_ct(pi, &ct, ts, flags);
		}
		break;
		
	case NFCT_MSG_DESTROY:
		ts = ct_hash_find(priv->htable, &ct.tuple[NFCT_DIR_ORIGINAL]);
		if (ts != NULL)
			return propagate_ct(pi, &ct, ts, flags);
		break;
		
	default:
		break;
	}

	return 0;
}


static int
read_cb_nfct(int fd, unsigned what, void *param)
{
	struct ulogd_pluginstance *pi = param;
	struct nfct_pluginstance *priv = (void *)pi->private;

	if (!(what & ULOGD_FD_READ))
		return 0;

	return nfnl_recv_msgs(nfct_nfnlh(priv->cth), do_nfct_msg, pi);
}


/* choosing powers of two for all values helps here */
#define STOP_HERE(h)	(((h)->curr_bucket + 16) % (h)->num_buckets)

static void
nfct_timer_cb(struct ulogd_timer *t)
{
	struct ulogd_pluginstance *pi = t->data;
	struct nfct_pluginstance *priv = (void *)pi->private;
	struct ct_htable *ht = priv->htable;
	struct ct_timestamp *ts;
	int end = STOP_HERE(ht);

	do {
		assert(ht->curr_bucket < ht->num_buckets);

		llist_for_each_entry(ts, &ht->buckets[ht->curr_bucket], list) {
			/* check if its still there */
			nfct_get_conntrack_x(priv->cth, &ts->tuple, NFCT_DIR_ORIGINAL,
								 &ts->last_seq);
		}

		ht->curr_bucket = (ht->curr_bucket + 1) % ht->num_buckets;
	} while (ht->curr_bucket != end);

	pr_debug("%s: now=%ld\n", __func__, t_now);
}

static int
nfct_configure(struct ulogd_pluginstance *upi,
			   struct ulogd_pluginstance_stack *stack)
{
	struct nfct_pluginstance *priv = (void *)upi->private;
	int ret;

	pr_debug("%s: pi=%p\n", __func__, upi);

	memset(priv, 0, sizeof(struct nfct_pluginstance));
	
	ret = config_parse_file(upi->id, upi->config_kset);
	if (ret < 0)
		return ret;

	return 0;
}


static int
nfct_start(struct ulogd_pluginstance *upi)
{
	struct nfct_pluginstance *priv = (void *)upi->private;

	pr_debug("%s: pi=%p\n", __func__, upi);

	priv->htable = htable_alloc(buckets_ce(upi->config_kset).u.value);
	if (priv->htable == NULL) {
		ulogd_log(ULOGD_FATAL, "%s: out of memory\n", upi->id);
		return -1;
	}

	priv->cth = nfct_open(NFNL_SUBSYS_CTNETLINK, CT_EVENTS);
	if (priv->cth == NULL) {
		ulogd_log(ULOGD_FATAL, "error opening ctnetlink\n");
		goto err_free;
	}

	priv->nfct_fd.fd = nfct_fd(priv->cth);
	priv->nfct_fd.cb = &read_cb_nfct;
	priv->nfct_fd.data = upi;
	priv->nfct_fd.when = ULOGD_FD_READ;

	if (ulogd_register_fd(&priv->nfct_fd) < 0)
		goto err_nfct_close;

	priv->timer.cb = nfct_timer_cb;
	priv->timer.ival = 1 SEC;
	priv->timer.flags = TIMER_F_PERIODIC;
	priv->timer.data = upi;

	if (ulogd_register_timer(&priv->timer) < 0)
		goto err_unreg_fd;

	ulogd_log(ULOGD_INFO, "%s: started\n", upi->id);

	return 0;

 err_unreg_fd:
	ulogd_unregister_fd(&priv->nfct_fd);
 err_nfct_close:
	nfct_close(priv->cth);
	priv->cth = NULL;
 err_free:
	htable_free(priv->htable);
	priv->htable = NULL;

	return -1;
}

static int
nfct_stop(struct ulogd_pluginstance *pi)
{
	struct nfct_pluginstance *priv = (void *)pi->private;

	pr_debug("%s: pi=%p\n", __func__, pi);

	if (priv->htable == NULL)
		return 0;				/* already stopped */

	ulogd_unregister_timer(&priv->timer);

	ulogd_unregister_fd(&priv->nfct_fd);

	if (priv->cth != NULL) {
		nfct_close(priv->cth);
		priv->cth = NULL;
	}

	if (priv->htable != NULL) {
		htable_free(priv->htable);
		priv->htable = NULL;
	}

	return 0;
}

static struct ulogd_plugin nfct_plugin = {
	.name = "NFCT",
	.flags = ULOGD_PF_RECONF,
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
	.configure	= nfct_configure,
	.start		= nfct_start,
	.stop		= nfct_stop,
	.priv_size	= sizeof(struct nfct_pluginstance),
	.version	= ULOGD_VERSION,
};

void __attribute__ ((constructor)) init(void);

void
init(void)
{
	ulogd_register_plugin(&nfct_plugin);
}

