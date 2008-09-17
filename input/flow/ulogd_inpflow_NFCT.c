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
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/linuxlist.h>
#include <ulogd/plugin.h>
#include <ulogd/ipfix_protocol.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include "linux_jhash.h"

#define CT_EVENTS		(NF_NETLINK_CONNTRACK_NEW \
						 | NF_NETLINK_CONNTRACK_UPDATE \
						 | NF_NETLINK_CONNTRACK_DESTROY)

/* configuration defaults */
#define TCACHE_SIZE		8192
#define SCACHE_SIZE	    512
#define TCACHE_REQ_MAX	100
#define TIMEOUT			30 SEC

#define RCVBUF_LEN		(1 << 18)
#define SNDBUF_LEN		RCVBUF_LEN

#define INADDR_CLUSTER		0x00fa13c6 /* 198.19.250.0/24 */

#define CLASS_C_CMP(a,net)	(((a) & 0x00ffffff) == (net))


typedef enum TIMES_ { START, UPDATE, STOP, __TIME_MAX } TIMES;
typedef unsigned conntrack_hash_t;

struct conntrack {
	struct llist_head list;
	struct llist_head seq_link;
	struct nfct_tuple tuple;
	unsigned last_seq;
	struct timeval time[__TIME_MAX];
	time_t t_req;
	unsigned used;
};

struct cache_head {
	struct llist_head link;
	unsigned cnt;
};

struct cache {
	struct cache_head *c_head;
	unsigned c_num_heads;
	unsigned c_curr_head;
	unsigned c_cnt;
	conntrack_hash_t (* c_hash)(struct cache *, struct conntrack *);
	int (* c_add)(struct cache *, struct conntrack *);
	int (* c_del)(struct cache *, struct conntrack *);
};

struct nfct_pluginstance {
	struct nfct_handle *cth;
	struct ulogd_fd nfct_fd;
	struct cache *tcache;		/* tuple cache */
	struct cache *scache;		/* sequence cache */
	struct ulogd_timer timer;
	struct {
		unsigned nl_err;
		unsigned nl_ovr;
	} stats;
};

static unsigned num_conntrack;
static struct config_keyset nfct_kset = {
	.num_ces = 3,
	.ces = {
		{
			.key	 = "hash_buckets",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = TCACHE_SIZE,
		},
		{
			.key	 = "disable",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		{
			.key	 = "timeout",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = TIMEOUT,
		},
	},
};
#define buckets_ce(pi)	((pi)->config_kset->ces[0].u.value)
#define disable_ce(pi)	((pi)->config_kset->ces[1].u.value)
#define timeout_ce(pi)	((pi)->config_kset->ces[2].u.value)

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
static int cache_del(struct cache *, struct conntrack *);
static struct conntrack *tcache_find(const struct ulogd_pluginstance *,
									 const struct nfct_tuple *);
static struct conntrack *scache_find(const struct ulogd_pluginstance *,
									 unsigned);


static int
nl_error(struct ulogd_pluginstance *pi, struct nlmsghdr *nlh, int *err)
{
	struct nfct_pluginstance *priv = (void *)pi->private;
	struct nlmsgerr *e = NLMSG_DATA(nlh);
	struct conntrack *ct;

	if (e->msg.nlmsg_seq == 0)
		return 0;

	ct = scache_find(pi, e->msg.nlmsg_seq);
	if (ct == NULL)
		return 0;						/* already gone */

	switch (-e->error) {
	case ENOENT:
		/* destroy message was lost (FIXME log all what we got) */
		if (ct->used > 1) {
			struct conntrack *ct_tmp = tcache_find(pi, &ct->tuple);

			if (ct == ct_tmp)
				cache_del(priv->tcache, ct);
		}
		cache_del(priv->scache, ct);
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
	int cta_dir;

	memset(buf, 0, sizeof(buf));

	/* intendedly do not set NLM_F_ACK in order to skip the
	   ACK message (but NACKs are still send) */
	nfnl_fill_hdr(nfct_subsys_ct(cth), &req->nlh, 0, t->l3protonum,
				  0, IPCTNL_MSG_CT_GET, NLM_F_REQUEST);

	if (seq != NULL)
		*seq = req->nlh.nlmsg_seq;

	cta_dir = (dir == NFCT_DIR_ORIGINAL) ? CTA_TUPLE_ORIG : CTA_TUPLE_REPLY;

	nfct_build_tuple(req, sizeof(buf), t, cta_dir);

	return nfnl_send(nfct_nfnlh(cth), &req->nlh);
}

/* time diff with second resolution */
static inline unsigned
tv_diff_sec(const struct timeval *tv1, const struct timeval *tv2)
{
	if (tv2->tv_sec >= tv1->tv_sec)
		return max(tv2->tv_sec - tv1->tv_sec, 1);

	return tv1->tv_sec - tv2->tv_sec;
}

struct conntrack *
ct_alloc(const struct nfct_tuple *tuple)
{
	struct conntrack *ct;

	if ((ct = calloc(1, sizeof(struct conntrack))) == NULL)
		return NULL;

	memcpy(&ct->tuple, tuple, sizeof(struct nfct_tuple));

	num_conntrack++;

	return ct;
}

static inline void
ct_get(struct conntrack *ct)
{
	ct->used++;
}

static inline void
ct_put(struct conntrack *ct)
{
	if (--ct->used == 0) {
		assert(num_conntrack > 0);

		free(ct);

		num_conntrack--;
	}
}

static struct cache *
cache_alloc(int cache_size)
{
	struct cache *c;
	int i;

	c = malloc(sizeof(*c) + sizeof(struct cache_head) * cache_size);
	if (c == NULL)
		return NULL;

	c->c_head = (void *)c + sizeof(*c);
	c->c_num_heads = cache_size;
	c->c_curr_head = 0;
	c->c_cnt = 0;

	for (i = 0; i < c->c_num_heads; i++) {
		INIT_LLIST_HEAD(&c->c_head[i].link);
		c->c_head[i].cnt = 0;
	}
	
	return c;
}

static void
cache_free(struct cache *c)
{
	int i;

	for (i = 0; i < c->c_num_heads; i++) {
		struct llist_head *ptr, *ptr2;

		llist_for_each_safe(ptr, ptr2, &c->c_head[i].link)
			free(container_of(ptr, struct conntrack, list));
	}

	free(c);
}

int
cache_add(struct cache *c, struct conntrack *ct)
{
	ct_get(ct);

	ct->time[UPDATE].tv_sec = ct->time[START].tv_sec = t_now_local;

	/* order of these two is important for debugging purposes */
	c->c_cnt++;
	c->c_add(c, ct);

	return 0;
}

int
cache_del(struct cache *c, struct conntrack *ct)
{
	assert(c->c_cnt > 0);
	assert(ct->used > 0);

	/* order of these two is important for debugging purposes */
	c->c_del(c, ct);
	c->c_cnt--;

	ct_put(ct);

	return 0;
}

static inline conntrack_hash_t
cache_head_next(const struct cache *c)
{
	return (c->c_curr_head + 1) % c->c_num_heads;
}

static inline conntrack_hash_t
cache_slice_end(const struct cache *c, unsigned n)
{
	return (c->c_curr_head + n) % c->c_num_heads;
}

/* tuple cache */
static struct conntrack ct_search;		/* used by scache too */

static conntrack_hash_t
tcache_hash(struct cache *c, struct conntrack *ct)
{
	static unsigned rnd;
	struct nfct_tuple *t = &ct->tuple;

	if (rnd == 0U)
		rnd = rand();

	return jhash_3words(t->src.v4, t->dst.v4 ^ t->protonum,	t->l4src.all
						| (t->l4dst.all << 16), rnd) % c->c_num_heads;
}

static int
tcache_add(struct cache *c, struct conntrack *ct)
{
	conntrack_hash_t h = c->c_hash(c, ct);

	llist_add(&ct->list, &c->c_head[h].link);
	c->c_head[h].cnt++;

	pr_debug("%s: ct=%p (h %u, %u/%u)\n", __func__, ct, h,
			 c->c_head[h].cnt, c->c_cnt);

	return 0;
}

static int
tcache_del(struct cache *c, struct conntrack *ct)
{
	conntrack_hash_t h = c->c_hash(c, ct);

	assert(c->c_head[h].cnt > 0);

	pr_debug("%s: ct=%p (h %u, %u/%u)\n", __func__, ct, h,
			 c->c_head[h].cnt, c->c_cnt);

	llist_del(&ct->list);
	c->c_head[h].cnt--;

	return 0;
}

static struct conntrack *
tcache_find(const struct ulogd_pluginstance *pi,
			const struct nfct_tuple *tuple)
{
	struct nfct_pluginstance *priv = (void *)pi->private;
	struct cache *c = priv->tcache;
	struct conntrack *ct;
	conntrack_hash_t h;

	memcpy(&ct_search.tuple, tuple, sizeof(struct nfct_tuple));
	h = c->c_hash(c, &ct_search);

	llist_for_each_entry(ct, &c->c_head[h].link, list) {
		if (memcmp(&ct->tuple, tuple, sizeof(*tuple)) == 0)
			return ct;
	}

	return NULL;
}

/* check entries in tuple cache */
static int
tcache_cleanup(struct ulogd_pluginstance *pi)
{
	struct nfct_pluginstance *priv = (void *)pi->private;
	struct cache *c = priv->tcache;
	conntrack_hash_t end = cache_slice_end(c, 32);
	struct conntrack *ct;
	int ret, req = 0;
	
	do {
		llist_for_each_entry_reverse(ct, &c->c_head[c->c_curr_head].link,
									 list) {
			if (tv_diff_sec(&ct->time[UPDATE], &tv_now) < timeout_ce(pi))
				continue;

			/* check if its still there */
			ret = nfct_get_conntrack_x(priv->cth, &ct->tuple,
									   NFCT_DIR_ORIGINAL, &ct->last_seq);
			if (ret < 0) {
				if (errno == EWOULDBLOCK)
					break;

				ulogd_log(ULOGD_ERROR, "nfct_get_conntrack: ct=%p: %m\n",
						  ct);
				break;
			}

			if (&ct->last_seq != 0) {
				ct->t_req = t_now;

				assert(scache_find(pi, ct->last_seq) == NULL);

				cache_add(priv->scache, ct);
			}

			if (++req > TCACHE_REQ_MAX)
				break;
		}

		c->c_curr_head = cache_head_next(c);

		if (req > TCACHE_REQ_MAX)
			break;
	} while (c->c_curr_head != end);

	return req;
}

/* sequence cache */
static conntrack_hash_t
scache_hash(struct cache *c, struct conntrack *ct)
{
	static unsigned rnd;

	if (rnd == 0U)
		rnd = rand();

	return (ct->last_seq ^ rnd) % c->c_num_heads;
}

static int
scache_add(struct cache *c, struct conntrack *ct)
{
	conntrack_hash_t h = c->c_hash(c, ct);

	llist_add(&ct->seq_link, &c->c_head[h].link);
	c->c_head[h].cnt++;

	pr_debug("%s: ct=%p (h %u, %u/%u)\n", __func__, ct, h,
			 c->c_head[h].cnt, c->c_cnt);

	return 0;
}

static int
scache_del(struct cache *c, struct conntrack *ct)
{
	conntrack_hash_t h = c->c_hash(c, ct);

	assert(c->c_head[h].cnt > 0);

	pr_debug("%s: ct=%p (h %u, %u/%u)\n", __func__, ct, h,
			 c->c_head[h].cnt, c->c_cnt);

	llist_del(&ct->seq_link);
	ct->last_seq = 0;

	c->c_head[h].cnt--;

	return 0;
}

static struct conntrack *
scache_find(const struct ulogd_pluginstance *pi, unsigned seq)
{
	struct nfct_pluginstance *priv = (void *)pi->private;
	struct cache *c = priv->scache;
	struct conntrack *ct;
	conntrack_hash_t h;

	ct_search.last_seq = seq;
	h = c->c_hash(c, &ct_search);

	llist_for_each_entry(ct, &c->c_head[h].link, seq_link) {
		if (ct->last_seq == ct_search.last_seq)
			return ct;
	}

	return NULL;
}

static int
scache_cleanup(struct ulogd_pluginstance *pi)
{
	struct nfct_pluginstance *priv = (void *)pi->private;
	struct cache *c = priv->scache;
	conntrack_hash_t end = cache_slice_end(c, 16);
	struct conntrack *ct;
	int del = 0;

	if (c->c_cnt == 0)
		return 0;

	do {
		struct llist_head *curr, *tmp;

		assert(c->c_curr_head < c->c_num_heads);

		llist_for_each_prev_safe(curr, tmp, &c->c_head[c->c_curr_head].link) {
			ct = container_of(curr, struct conntrack, seq_link);

			assert(ct->t_req != 0);

			if ((t_now - ct->t_req) < 5 SEC)
				break;

			cache_del(priv->scache, ct);
			del++;
		}

		c->c_curr_head = cache_head_next(c);
	} while (c->c_curr_head != end);

	return del;
}

static int
propagate_ct_flow(struct ulogd_pluginstance *upi, 
				  struct nfct_conntrack *nfct, unsigned int flags,
				  int dir, struct conntrack *ct)
{
	struct ulogd_key *ret = upi->output.keys;

	key_u32(&ret[O_IP_SADDR], htonl(nfct->tuple[0].src.v4));
	key_u32(&ret[O_IP_DADDR], htonl(nfct->tuple[1].src.v4));
	key_u8(&ret[O_IP_PROTO], nfct->tuple[dir].protonum);

	switch (nfct->tuple[dir].protonum) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_SCTP:
		/* FIXME: DCCP */
		key_u16(&ret[O_L4_SPORT], htons(nfct->tuple[0].l4src.tcp.port));
		key_u16(&ret[O_L4_DPORT], htons(nfct->tuple[1].l4src.tcp.port));
		break;
	case IPPROTO_ICMP:
		key_u8(&ret[O_ICMP_CODE], nfct->tuple[dir].l4src.icmp.code);
		key_u8(&ret[O_ICMP_TYPE], nfct->tuple[dir].l4src.icmp.type);
		break;
	}

	if (flags & NFCT_COUNTERS_ORIG) {
		key_u32(&ret[O_RAW_IN_PKTLEN], nfct->counters[0].bytes);
		key_u32(&ret[O_RAW_IN_PKTCOUNT], nfct->counters[0].packets);

		key_u32(&ret[O_RAW_OUT_PKTLEN], nfct->counters[1].bytes);
		key_u32(&ret[O_RAW_OUT_PKTCOUNT], nfct->counters[1].packets);
	}

	if (flags & NFCT_MARK)
		key_u32(&ret[O_CT_MARK], nfct->mark);

	if (flags & NFCT_ID)
		key_u32(&ret[O_CT_ID], nfct->id);

	key_u32(&ret[O_FLOW_START_SEC], ct->time[START].tv_sec);
	key_u32(&ret[O_FLOW_START_USEC], ct->time[START].tv_usec);

	key_u32(&ret[O_FLOW_END_SEC], ct->time[STOP].tv_sec);
	key_u32(&ret[O_FLOW_END_USEC], ct->time[STOP].tv_usec);

	key_u32(&ret[O_FLOW_DURATION], tv_diff_sec(&ct->time[START],
											   &ct->time[STOP]));

	ulogd_propagate_results(upi);

	return 0;
}

static int
propagate_ct(struct ulogd_pluginstance *upi, struct nfct_conntrack *nfct,
			 struct conntrack *ct, unsigned int flags)
{
	struct nfct_pluginstance *priv = (void *)upi->private;

	do {
		if (nfct->tuple[NFCT_DIR_ORIGINAL].src.v4 == INADDR_LOOPBACK
			|| nfct->tuple[NFCT_DIR_ORIGINAL].dst.v4 == INADDR_LOOPBACK)
			break;

		if (CLASS_C_CMP(nfct->tuple[NFCT_DIR_ORIGINAL].src.v4, INADDR_CLUSTER)
			|| CLASS_C_CMP(nfct->tuple[NFCT_DIR_ORIGINAL].dst.v4,
						   INADDR_CLUSTER))
			break;

		ct->time[STOP].tv_sec = t_now_local;
		
		propagate_ct_flow(upi, nfct, flags, NFCT_DIR_ORIGINAL, ct);
	} while (0);

	cache_del(priv->tcache, ct);

	return 0;
}


static int
do_nfct_msg(struct nlmsghdr *nlh, void *arg)
{
	struct ulogd_pluginstance *pi = arg;
	struct nfct_pluginstance *priv = (void *)pi->private;
	struct nfgenmsg *nfh = NLMSG_DATA(nlh);
	struct nfct_conntrack nfct;
	struct conntrack *ct;
	int flags, type = nfct_msg_type(nlh);

	if (type == NFCT_MSG_UNKNOWN)
		return 0;

	bzero(&nfct, sizeof(nfct));

	nfct.tuple[NFCT_DIR_ORIGINAL].l3protonum = 
		nfct.tuple[NFCT_DIR_REPLY].l3protonum = nfh->nfgen_family;

	if (nfct_netlink_to_conntrack(nlh, &nfct, &flags) < 0)
		return -1;

	/* TODO handle NFCT_COUNTER_FILLING */

	switch (type) { 
	case NFCT_MSG_NEW:
		if ((ct = ct_alloc(&nfct.tuple[NFCT_DIR_ORIGINAL])) == NULL)
			return -1;

		if (cache_add(priv->tcache, ct) < 0)
			return -1;
		break;

	case NFCT_MSG_UPDATE:
		ct = tcache_find(pi, &nfct.tuple[NFCT_DIR_ORIGINAL]);
		if (ct == NULL) {
			/* do not add CT to cache, as there would be no start
			   information */
			break;
		}

		ct->time[UPDATE].tv_sec = t_now_local;

		if (ct->used > 1) {
			struct conntrack *ct_tmp = scache_find(pi, nlh->nlmsg_seq);

			if (ct_tmp != NULL) {
				assert(ct_tmp == ct);

				cache_del(priv->scache, ct);
			}
		}

		/* handle TCP connections differently in order not to bloat CT
		   hash with many TIME_WAIT connections */
		if (nfct.tuple[NFCT_DIR_ORIGINAL].protonum == IPPROTO_TCP) {
			if (nfct.protoinfo.tcp.state == TCP_CONNTRACK_TIME_WAIT)
				return propagate_ct(pi, &nfct, ct, flags);
		}
		break;
		
	case NFCT_MSG_DESTROY:
		ct = tcache_find(pi, &nfct.tuple[NFCT_DIR_ORIGINAL]);
		if (ct != NULL)
			return propagate_ct(pi, &nfct, ct, flags);
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

/*
  nfct_timer_cb()

  This is a synchronous timer, do whatever you want.
*/
static void
nfct_timer_cb(struct ulogd_timer *t)
{
	struct ulogd_pluginstance *pi = t->data;
	struct nfct_pluginstance *priv = (void *)pi->private;
	unsigned sc_start, sc_end, tc_start, tc_end;

	sc_start = priv->scache->c_curr_head;
	tc_start = priv->tcache->c_curr_head;

	scache_cleanup(pi);
	tcache_cleanup(pi);

	sc_end = priv->scache->c_curr_head;
	tc_end = priv->tcache->c_curr_head;

	ulogd_log(ULOGD_DEBUG, "%s: ct=%u t=%u [%u,%u[ s=%u [%u,%u[\n",
			  pi->id, num_conntrack,
			  priv->tcache->c_cnt, tc_start, tc_end,
			  priv->scache->c_cnt, sc_start, sc_end);
}

static int
nfct_configure(struct ulogd_pluginstance *upi,
			   struct ulogd_pluginstance_stack *stack)
{
	struct nfct_pluginstance *priv = (void *)upi->private;
	int ret;

	memset(priv, 0, sizeof(struct nfct_pluginstance));
	
	ret = config_parse_file(upi->id, upi->config_kset);
	if (ret < 0)
		return ret;

	return 0;
}

static int
init_caches(struct ulogd_pluginstance *pi)
{
	struct nfct_pluginstance *priv = (void *)pi->private;
	struct cache *c;

	assert(priv->tcache == NULL && priv->scache == NULL);

	/* tuple cache */
	c = priv->tcache = cache_alloc(buckets_ce(pi));
	if (priv->tcache == NULL) {
		ulogd_log(ULOGD_FATAL, "%s: out of memory\n", pi->id);
		return -1;
	}

	c->c_hash = tcache_hash;
	c->c_add = tcache_add;
	c->c_del = tcache_del;

	/* sequence cache */
	c = priv->scache = cache_alloc(SCACHE_SIZE);
	if (priv->scache == NULL) {
		ulogd_log(ULOGD_FATAL, "%s: out of memory\n", pi->id);

		cache_free(priv->tcache);
		priv->tcache = NULL;

		return -1;
	}

	c->c_hash = scache_hash;
	c->c_add = scache_add;
	c->c_del = scache_del;

	return 0;
}

static int
nfct_start(struct ulogd_pluginstance *upi)
{
	struct nfct_pluginstance *priv = (void *)upi->private;

	pr_debug("%s: pi=%p\n", __func__, upi);

	if (disable_ce(upi) != 0) {
		ulogd_log(ULOGD_INFO, "%s: disabled\n", upi->id);
		return 0;
	}

	if (init_caches(upi) < 0)
		return -1;

	priv->cth = nfct_open(NFNL_SUBSYS_CTNETLINK, CT_EVENTS);
	if (priv->cth == NULL) {
		ulogd_log(ULOGD_FATAL, "error opening ctnetlink\n");
		goto err_free;
	}

	if (set_sockbuf_len(nfct_fd(priv->cth), RCVBUF_LEN, SNDBUF_LEN) < 0)
		goto err_free;

	ulogd_log(ULOGD_DEBUG, "%s: ctnetlink connection opened\n", upi->id);

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

	ulogd_log(ULOGD_INFO, "%s: started (tcache %u, scache %u)\n", upi->id,
			  priv->tcache->c_num_heads, priv->scache->c_num_heads);

	return 0;

 err_unreg_fd:
	ulogd_unregister_fd(&priv->nfct_fd);
 err_nfct_close:
	nfct_close(priv->cth);
	priv->cth = NULL;
 err_free:
	cache_free(priv->tcache);
	priv->tcache = NULL;

	return -1;
}

static int
nfct_stop(struct ulogd_pluginstance *pi)
{
	struct nfct_pluginstance *priv = (void *)pi->private;

	pr_debug("%s: pi=%p\n", __func__, pi);

	if (disable_ce(pi) != 0)
		return 0;				/* wasn't started */

	if (priv->tcache == NULL)
		return 0;				/* already stopped */

	ulogd_unregister_timer(&priv->timer);

	ulogd_unregister_fd(&priv->nfct_fd);

	if (priv->cth != NULL) {
		nfct_close(priv->cth);
		priv->cth = NULL;
	}

	ulogd_log(ULOGD_DEBUG, "%s: ctnetlink connection closed\n", pi->id);

	if (priv->tcache != NULL) {
		cache_free(priv->tcache);
		priv->tcache = NULL;
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

