/*
 * ulogd_input_NFCT.c
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
 *	  re-read of config and reallocation / rehashing of table, if required
 *	- Split hashtable code into separate [filter] plugin, so we can run 
 * 	  small non-hashtable ulogd installations on the firewall boxes, send
 * 	  the messages via IPFX to one aggregator who then runs ulogd with a 
 * 	  network wide connection hash table.
 *
 * Use libnl			Holger Eitzenberger <holger@eitzenberger.org> 2008
 */
#include "config.h"
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/plugin.h>
#include <ulogd/ipfix_protocol.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netlink/netfilter/nfnl.h>
#include <netlink/netfilter/ct.h>
#include <netlink/attr.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include "linux_jhash.h"

#define RCVBUF_LEN		(1 << 18)
#define SNDBUF_LEN		RCVBUF_LEN

/* configuration defaults */
#define TCACHE_MIN_SIZE	512
#define TCACHE_SIZE		1024
#define SCACHE_SIZE	    256
#define TCACHE_REQ_MAX	1000
#define TIMEOUT_MIN		30 SEC
#define TIMEOUT			TIMEOUT_MIN


typedef enum { START, UPDATE, STOP, __TIME_MAX } TIMES;

union ct_addr {
	struct in_addr in;
	struct in6_addr in6;
};

union ct_l4protoinfo {
	uint32_t all;
	struct {
		uint16_t sport;
		uint16_t dport;
	} tcp;
	struct {
		uint16_t sport;
		uint16_t dport;
	} udp;
	struct {
		uint8_t type, code;
	} icmp;
};

/* this is our key which identifies the conntracks in the hash */
struct ct_tuple {
	union ct_addr src;
	union ct_addr dst;
	uint8_t family;
	uint8_t l4proto;
	union ct_l4protoinfo l4info;
};

struct conntrack {
	struct llist_head link;
	struct llist_head seq_link;
	struct ct_tuple tuple;
	struct nfnl_ct *nfnl_ct;
	unsigned refcnt;
	struct timeval time[__TIME_MAX];
	time_t t_req;
	unsigned last_seq;
};

typedef unsigned ct_hash_t;

struct cache_head {
	struct llist_head link;
	unsigned cnt;
};

struct cache {
	struct cache_head *c_head;
	int (* c_add)(struct cache *, struct conntrack *);
	int (* c_del)(struct cache *, struct conntrack *);
	unsigned c_curr_head;
	unsigned c_cnt;
	unsigned c_num_heads;
};

struct nfct_priv {
	struct nl_handle *nlh;
	struct ulogd_fd ufd;
	struct ulogd_timer timer;
	struct cache *tcache;
	struct cache *scache;

	/* number of overruns, will be decremented by GC timer */
	unsigned overruns;
};

enum {
	O_IP_SADDR = 0,
	O_IP_DADDR,
	O_IP6_SADDR,
	O_IP6_DADDR,
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
};


static unsigned num_conntrack;
static struct ulogd_key nfct_okeys[] = {
	[O_IP_SADDR] = KEY_IPFIX(IPADDR, "ip.saddr", IETF, sourceIPv4Address),
	[O_IP_DADDR] = KEY_IPFIX(IPADDR, "ip.daddr", IETF,destinationIPv4Address),
	[O_IP6_SADDR] = KEY(IP6ADDR, "ip6.saddr"),
	[O_IP6_DADDR] = KEY(IP6ADDR, "ip6.daddr"),
	[O_IP_PROTO] = KEY_IPFIX(UINT8, "ip.protocol", IETF, protocolIdentifier),
	[O_L4_SPORT] = KEY_IPFIX(UINT16, "l4.sport", IETF, sourceTransportPort),
	[O_L4_DPORT] = KEY_IPFIX(UINT16, "l4.dport", IETF,
							 destinationTransportPort),
	/* FIXME: this could also be octetDeltaCount */
	[O_RAW_IN_PKTLEN] = KEY_IPFIX(UINT64, "raw.in.pktlen", IETF,
								  octetTotalCount),
	/* FIXME: this could also be packetDeltaCount */
	[O_RAW_IN_PKTCOUNT] = KEY_IPFIX(UINT64, "raw.in.pktcount", IETF,
									packetTotalCount),
	/* FIXME: this could also be octetDeltaCount */
	[O_RAW_OUT_PKTLEN] = KEY_IPFIX(UINT64, "raw.out.pktlen", IETF,
								   octetTotalCount),
	/* FIXME: this could also be packetDeltaCount */
	[O_RAW_OUT_PKTCOUNT] = KEY_IPFIX(UINT64, "raw.out.pktcount",
									 IETF, packetTotalCount),
	[O_ICMP_CODE] = KEY_IPFIX(UINT8, "icmp.code", IETF, icmpCodeIPv4),
	[O_ICMP_TYPE] = KEY_IPFIX(UINT8, "icmp.type", IETF, icmpTypeIPv4),
	[O_CT_MARK] = KEY_IPFIX(UINT32, "ct.mark",NETFILTER, NF_mark),
	[O_CT_ID] = KEY_IPFIX(UINT32, "ct.id", NETFILTER, NF_conntrack_id),
	[O_FLOW_START_SEC] = KEY_IPFIX(UINT32, "flow.start.sec", IETF,
								   flowStartSeconds),
	[O_FLOW_START_USEC] = KEY_IPFIX(UINT32, "flow.start.usec", IETF,
									flowStartMicroSeconds),
	[O_FLOW_END_SEC] = KEY_IPFIX(UINT32, "flow.end.sec", IETF,
								 flowEndSeconds),
	[O_FLOW_END_USEC] = KEY_IPFIX(UINT32, "flow.end.usec", IETF,
								  flowEndSeconds),
	[O_FLOW_DURATION] = KEY(UINT32, "flow.duration"),
};

static const struct config_keyset nfct_kset = {
	.num_ces = 4,
	.ces = {
		CONFIG_KEY_INT("hash_buckets", TCACHE_SIZE),
		CONFIG_KEY("disable", INT, 0),
		CONFIG_KEY_INT("timeout", TIMEOUT),
		CONFIG_KEY_INT("gcmax", TCACHE_REQ_MAX),
	},
};

#define buckets_ce(pi)	((pi)->config_kset->ces[0].u.value)
#define disable_ce(pi)	((pi)->config_kset->ces[1].u.value)
#define timeout_ce(pi)	((pi)->config_kset->ces[2].u.value)
#define gcmax_ce(pi)	((pi)->config_kset->ces[3].u.value)


static void ct_dump_tuple(const struct ct_tuple *) __ulogd_unused;

static struct conntrack *
ct_alloc_init(struct nfnl_ct *nfnl_ct, const struct ct_tuple *t)
{
	struct conntrack *ct;

	if (nfnl_ct == NULL || t == NULL)
		return NULL;

	if ((ct = calloc(1, sizeof(struct conntrack))) == NULL)
		return NULL;

	num_conntrack++;

	nfnl_ct_get(nfnl_ct);
	ct->nfnl_ct = nfnl_ct;

	memcpy(&ct->tuple, t, sizeof(*t));

	return ct;
}

static inline void
ct_get(struct conntrack *ct)
{
	ct->refcnt++;
}

static inline void
ct_put(struct conntrack *ct)
{
	assert(num_conntrack > 0);

	if (--ct->refcnt == 0) {
		if (ct->nfnl_ct != NULL)
			nfnl_ct_put(ct->nfnl_ct);

		free(ct);

		num_conntrack--;
	}
}

static void
ct_update(struct conntrack *ct, const struct nfnl_ct *new_nfnl_ct)
{
	struct nfnl_ct *nfnl_ct = ct->nfnl_ct;

	assert(nfnl_ct != NULL);

	ct->time[UPDATE].tv_sec = t_now;

	nfnl_ct_set_packets(nfnl_ct, 0, nfnl_ct_get_packets(new_nfnl_ct, 0));
	nfnl_ct_set_bytes(nfnl_ct, 0, nfnl_ct_get_bytes(new_nfnl_ct, 0));

	nfnl_ct_set_packets(nfnl_ct, 1, nfnl_ct_get_packets(new_nfnl_ct, 1));
	nfnl_ct_set_bytes(nfnl_ct, 1, nfnl_ct_get_bytes(new_nfnl_ct, 1));
}

static int
ct_tuple_cmp(const struct ct_tuple *t1, const struct ct_tuple *t2)
{
	return memcmp(t1, t2, sizeof(struct ct_tuple));
}

static void
ct_dump_tuple(const struct ct_tuple *t)
{
	char src[64], dst[64];

	if (t->family == AF_INET || t->family == AF_INET6) {
		inet_ntop(t->family, &t->src.in, src, sizeof(src));
		inet_ntop(t->family, &t->dst.in, dst, sizeof(dst));
	} else {
		ulogd_log(ULOGD_NOTICE, "unsupported proto family %u\n", t->family);
		return;
	}

	printf("tuple: family=%u src=%s dst=%s l4proto=%u dport=%u\n",
		   t->family, src, dst, t->l4proto, htons(t->l4info.tcp.dport));
}

static int
nfnl_ct_to_tuple(const struct nfnl_ct *nfnl_ct, struct ct_tuple *t)
{
	struct nl_addr *nl_saddr, *nl_daddr;

	if (!t)
		return -1;

	memset(t, 0, sizeof(*t));

	t->family = nfnl_ct_get_family(nfnl_ct);
	if ((nl_saddr = nfnl_ct_get_src(nfnl_ct, 0 /* orig */)) == NULL)
		return -1;
	if ((nl_daddr = nfnl_ct_get_dst(nfnl_ct, 0 /* orig */)) == NULL)
		return -1;

	if (t->family == AF_INET) {
		memcpy(&t->src.in, nl_addr_get_binary_addr(nl_saddr),
			   sizeof(struct in_addr));
		memcpy(&t->dst.in, nl_addr_get_binary_addr(nl_daddr),
			   sizeof(struct in_addr));
	} else if (t->family == AF_INET6) {
		memcpy(&t->src.in6, nl_addr_get_binary_addr(nl_saddr),
			   sizeof(struct in6_addr));
		memcpy(&t->dst.in6, nl_addr_get_binary_addr(nl_daddr),
			   sizeof(struct in6_addr));
	}

	t->l4proto = nfnl_ct_get_proto(nfnl_ct);

	switch (t->l4proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		t->l4info.tcp.sport = ntohs(nfnl_ct_get_src_port(nfnl_ct, 0));
		t->l4info.tcp.dport = ntohs(nfnl_ct_get_src_port(nfnl_ct, 1));
		break;

	case IPPROTO_ICMP:
		t->l4info.icmp.type = nfnl_ct_get_icmp_type(nfnl_ct, 0);
		t->l4info.icmp.code = nfnl_ct_get_icmp_code(nfnl_ct, 0);
		break;

	default:
		break;
	}

#if 0
	ct_dump_tuple(t);
#endif /* 0 */

	return 0;
}

/* cache API */
struct cache *
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
            free(container_of(ptr, struct conntrack, link));
    }

    free(c);
}

static int
cache_add(struct cache *c, struct conntrack *ct)
{
	ct_get(ct);
	ct->time[UPDATE].tv_sec = ct->time[START].tv_sec = t_now;

    /* order of these two is important for debugging purposes */
    c->c_cnt++;
    c->c_add(c, ct);

	return 0;
}

static int
cache_del(struct cache *c, struct conntrack *ct)
{
    assert(c->c_cnt > 0);
    assert(ct->refcnt > 0);

    /* order of these two is important for debugging purposes */
    c->c_del(c, ct);
    c->c_cnt--;

    ct_put(ct);

	return 0;
}

static inline ct_hash_t
cache_slice_end(const struct cache *c, unsigned n)
{
    return (c->c_curr_head + n) % c->c_num_heads;
}

static inline ct_hash_t
cache_head_next(const struct cache *c)
{
    return (c->c_curr_head + 1) % c->c_num_heads;
}

/* sequence cache */
static ct_hash_t
scache_hash(const struct cache *c, unsigned seq)
{
	static unsigned rnd;

	if (rnd == 0U)
		rnd = rand();

	return (seq ^ rnd) % c->c_num_heads;
}

static int
scache_add(struct cache *c, struct conntrack *ct)
{
    ct_hash_t h;

	assert(ct->last_seq != 0);	/* is seq# 0 possible */

	h = scache_hash(c, ct->last_seq);

    llist_add(&ct->seq_link, &c->c_head[h].link);
    c->c_head[h].cnt++;

    pr_debug("%s: ct=%p (h %u, %u/%u)\n", __func__, ct, h,
             c->c_head[h].cnt, c->c_cnt);

    return 0;
}

static int
scache_del(struct cache *c, struct conntrack *ct)
{
    ct_hash_t h;

	assert(ct->last_seq != 0);

	h = scache_hash(c, ct->last_seq);

    assert(c->c_head[h].cnt > 0);

    pr_debug("%s: ct=%p (h %u, %u/%u)\n", __func__, ct, h,
             c->c_head[h].cnt, c->c_cnt);

    llist_del(&ct->seq_link);
    ct->last_seq = 0;

    c->c_head[h].cnt--;

    return 0;
}

static struct conntrack *
scache_find(struct cache *c, unsigned seq)
{
    ct_hash_t h = scache_hash(c, seq);
	struct conntrack *ct;

    llist_for_each_entry(ct, &c->c_head[h].link, seq_link) {
        if (ct->last_seq == seq)
            return ct;
    }

    return NULL;
}

static int
scache_cleanup(struct ulogd_pluginstance *pi)
{
	struct nfct_priv *priv = upi_priv(pi);
	struct cache *c = priv->scache;
	ct_hash_t end = cache_slice_end(c, 16);
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

/* tuple cache */
static ct_hash_t
tcache_hash(const struct cache *c, const struct ct_tuple *t)
{
	static unsigned rnd;
	uint32_t src, dst;

	if (!rnd)
		rnd = rand();

	src = (uint32_t)t->src.in.s_addr;
	dst = (uint32_t)t->dst.in.s_addr;
	return jhash_3words(src, dst ^ t->l4proto, t->l4info.all,
						rnd) % c->c_num_heads;
}

static int
tcache_add(struct cache *c, struct conntrack *ct)
{
	ct_hash_t h = tcache_hash(c, &ct->tuple);

    llist_add(&ct->link, &c->c_head[h].link);
    c->c_head[h].cnt++;

    pr_debug("%s: ct=%p (h %u, %u/%u)\n", __func__, ct, h,
             c->c_head[h].cnt, c->c_cnt);

	return 0;
}

static int
tcache_del(struct cache *c, struct conntrack *ct)
{
	ct_hash_t h = tcache_hash(c, &ct->tuple);

    assert(c->c_head[h].cnt > 0);

    pr_debug("%s: ct=%p (h %u, %u/%u)\n", __func__, ct, h,
             c->c_head[h].cnt, c->c_cnt);

    llist_del(&ct->link);
    c->c_head[h].cnt--;

	return 0;
}

static struct conntrack *
tcache_find(struct cache *c, const struct ct_tuple *t)
{
	ct_hash_t h = tcache_hash(c, t);
	struct conntrack *tmp;

	pr_fn_debug("cache=%p tuple=%p\n", c, t);

	llist_for_each_entry(tmp, &c->c_head[h].link, link) {
		if (ct_tuple_cmp(t, &tmp->tuple) == 0)
			return tmp;
    }

	return NULL;
}

static int
nfct_query(struct nl_handle *nlh, const struct nfnl_ct *nfnl_ct,
	unsigned *seq)
{
	struct nl_msg *msg;
	struct nlmsghdr *hdr;
	int ret;

	msg = nfnl_ct_build_query_request(nfnl_ct, 0 /* flags */);
	if (msg == NULL)
		return -1;

	hdr = nlmsg_hdr(msg);

	hdr->nlmsg_pid = nl_socket_get_local_port(nlh);
	hdr->nlmsg_seq = nl_socket_use_seq(nlh);
	hdr->nlmsg_flags |= NLM_F_REQUEST; /* no NLM_F_ACK */

	if (seq != NULL)
		*seq = hdr->nlmsg_seq;

	ret = nl_send(nlh, msg);

	nlmsg_free(msg);

	return ret;
}

static int
tcache_cleanup(struct ulogd_pluginstance *pi)
{
	struct nfct_priv *priv = upi_priv(pi);
	struct cache *c = priv->tcache;
    ct_hash_t end = cache_slice_end(c, 32);
    struct conntrack *ct;
    int req = 0;

	do {
		int ret;

		llist_for_each_entry_reverse(ct, &c->c_head[c->c_curr_head].link,
									 link) {
			if (tv_diff_sec(&ct->time[UPDATE], &tv_now) < timeout_ce(pi))
				continue;

			/* check if its still there */
			ret = nfct_query(priv->nlh, ct->nfnl_ct, &ct->last_seq);
			if (ret < 0) {
				if (errno == EWOULDBLOCK)
					break;

				upi_log(pi, ULOGD_ERROR, "nfct_query: ct=%p: %m\n",	ct);
				break;
			}

			if (&ct->last_seq != 0) {
				ct->t_req = t_now;

				assert(scache_find(priv->scache, ct->last_seq) == NULL);

				cache_add(priv->scache, ct);
			}

			if (++req > gcmax_ce(pi))
				break;
		}

		c->c_curr_head = cache_head_next(c);

		if (req > TCACHE_REQ_MAX)
			break;
	} while (c->c_curr_head != end);

	return req;
}

static int
propagate_ct(struct ulogd_pluginstance *pi, struct conntrack *ct)
{
	struct nfct_priv *priv = upi_priv(pi);
	struct ulogd_key *out = pi->output.keys;
	struct nfnl_ct *nfnl_ct = ct->nfnl_ct;
	unsigned flags = 0;

	pr_fn_debug("pi=%p ct=%p\n", pi, ct);

	ct->time[STOP].tv_sec = t_now;

	if (ct->tuple.family == AF_INET) {
		key_set_u32(&out[O_IP_SADDR], ct->tuple.src.in.s_addr);
		key_set_u32(&out[O_IP_DADDR], ct->tuple.dst.in.s_addr);
	} else if (ct->tuple.family == AF_INET6) {
		key_set_in6(&out[O_IP6_SADDR], &ct->tuple.src.in6);
		key_set_in6(&out[O_IP6_DADDR], &ct->tuple.dst.in6);
	} else
		BUG();
    key_set_u8(&out[O_IP_PROTO], ct->tuple.l4proto);

	switch (ct->tuple.l4proto) {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
    case IPPROTO_SCTP:
		key_set_u16(&out[O_L4_SPORT], ct->tuple.l4info.tcp.sport);
		key_set_u16(&out[O_L4_DPORT], ct->tuple.l4info.tcp.dport);
		break;

    case IPPROTO_ICMP:
		key_set_u8(&out[O_ICMP_CODE], nfnl_ct_get_icmp_code(nfnl_ct, 0));
        key_set_u8(&out[O_ICMP_TYPE], nfnl_ct_get_icmp_type(nfnl_ct, 0));
        break;

	default:
		break;
	}

	/* TODO check if counters are there */
	key_set_u64(&out[O_RAW_IN_PKTLEN], nfnl_ct_get_bytes(nfnl_ct, 0));
	key_set_u64(&out[O_RAW_IN_PKTCOUNT], nfnl_ct_get_packets(nfnl_ct, 0));

	key_set_u64(&out[O_RAW_OUT_PKTLEN], nfnl_ct_get_bytes(nfnl_ct, 1));
	key_set_u64(&out[O_RAW_OUT_PKTCOUNT], nfnl_ct_get_packets(nfnl_ct, 1));

	if (nfnl_ct_test_mark(nfnl_ct))
		key_set_u32(&out[O_CT_MARK], nfnl_ct_get_mark(nfnl_ct));
	if (nfnl_ct_test_id(nfnl_ct))
		key_set_u32(&out[O_CT_ID], nfnl_ct_get_id(nfnl_ct));

	key_set_u32(&out[O_FLOW_START_SEC], ct->time[START].tv_sec);
    key_set_u32(&out[O_FLOW_START_USEC], ct->time[START].tv_usec);
    key_set_u32(&out[O_FLOW_END_SEC], ct->time[STOP].tv_sec);
    key_set_u32(&out[O_FLOW_END_USEC], ct->time[STOP].tv_usec);
    key_set_u32(&out[O_FLOW_DURATION],
				tv_diff_sec(&ct->time[START], &ct->time[STOP]));

	ulogd_propagate_results(pi, &flags);

	if (ct->refcnt > 1)
		cache_del(priv->scache, ct);
	cache_del(priv->tcache, ct);

	return 0;
}

/**
 * Start garbage collection
 */
static int
gc_start(struct ulogd_pluginstance *pi)
{
	struct nfct_priv *priv = upi_priv(pi);

	/* we want at least two walks over the whole cache before GC
	   quits */
	if ((priv->overruns += 2) == 0)
		priv->overruns = 2;

	if (timer_running(&priv->timer))
		return 0;

	if (ulogd_register_timer(&priv->timer) < 0)
		return -1;

	upi_log(pi, ULOGD_DEBUG, "GC timer started\n");

	return 0;
}

static int
nfct_parse_valid_cb(struct nl_msg *msg, void *arg)
{
	struct ulogd_pluginstance *pi = arg;
	struct nfct_priv *priv = upi_priv(pi);
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct nfnl_ct *nfnl_ct;
	struct ct_tuple tuple;
	struct conntrack *ct;
	int grp;

	pr_fn_debug("msg=%p pi=%p\n", msg, pi);

	nfnl_ct = nfnlmsg_ct_parse(hdr);

	/* check if it's a response to our queries and remove the entry from
	   the scache.  Note that it's perfectly fine if this deletes the
	   conntrack. */
	if (hdr->nlmsg_seq != 0) {
		if ((ct = scache_find(priv->scache, hdr->nlmsg_seq)) != NULL)
			cache_del(priv->scache, ct);
	}

	nfnl_ct_to_tuple(nfnl_ct, &tuple);

	switch (grp = nfnlmsg_ct_group(hdr)) {
	case NFNLGRP_CONNTRACK_NEW:
		/* it is possible for a conntrack to be available if a _NEW
		   event comes in, e. g. ICMP echo request if the previous
		   echo reply was missed. */
		if ((ct = tcache_find(priv->tcache, &tuple)) == NULL) {
			if ((ct = ct_alloc_init(nfnl_ct, &tuple)) == NULL) {
				upi_log(pi, ULOGD_ERROR, "out of memory\n");
				goto err_put_ct;
			}

			cache_add(priv->tcache, ct);
		} else
			ct_update(ct, nfnl_ct);

		break;

	case NFNLGRP_CONNTRACK_UPDATE:
		if ((ct = tcache_find(priv->tcache, &tuple)) == NULL) {
			/* do not add CT to cache, as there would be no start
			   information */
			break;
		}

		ct_update(ct, nfnl_ct);

        /* handle TCP connections differently in order not to bloat CT
           hash with many TIME_WAIT connections */
        if (tuple.l4proto == IPPROTO_TCP) {
            if (nfnl_ct_get_tcp_state(nfnl_ct) == TCP_CONNTRACK_TIME_WAIT) {
                if (propagate_ct(pi, ct) < 0)
					goto err_put_ct;
			}
        }
        break;

	case NFNLGRP_CONNTRACK_DESTROY:
		if ((ct = tcache_find(priv->tcache, &tuple)) == NULL)
			break;

		ct_update(ct, nfnl_ct);

		if (propagate_ct(pi, ct) < 0)
			goto err_put_ct;
		break;

	default:
		upi_log(pi, ULOGD_ERROR, "unsupported group '%d'\n", grp);
		break;
	}

	nfnl_ct_put(nfnl_ct);

	return 0;

err_put_ct:
	nfnl_ct_put(nfnl_ct);

	return 0;
}

static int
nfct_overrun_cb(struct nl_msg *msg, void *arg)
{
	struct ulogd_pluginstance *pi = arg;

	return gc_start(pi);
}

/**
 * Netlink error handler.
 *
 * Called by libnl if NLMSG_ERROR is returned from the kernel. Then
 * nlmsgerr contains more detailed error information.
 */
static int
nfct_err_cb(struct sockaddr_nl *sa, struct nlmsgerr *e, void *arg)
{
	struct ulogd_pluginstance *pi = arg;
	struct nfct_priv *priv = upi_priv(pi);
	struct conntrack *ct;

	if (e->msg.nlmsg_seq == 0)
		return 0;

	ct = scache_find(priv->scache, e->msg.nlmsg_seq);
	if (ct == NULL)
		return 0;				/* already gone */

	switch (-e->error) {
	case ENOENT:				/* destroy message was lost */
        if (ct->refcnt > 1) {
            struct conntrack *ct_tmp = tcache_find(priv->tcache, &ct->tuple);

            if (ct == ct_tmp)
                cache_del(priv->tcache, ct);
        }
        cache_del(priv->scache, ct);
		break;

	default:
		upi_log(pi, ULOGD_ERROR, "netlink error: %s\n", strerror(-e->error));
		break;
	}

	return NL_SKIP;
}

static int
nfct_ufd_cb(int fd, unsigned what, void *arg)
{
	struct ulogd_pluginstance *pi = arg;
	struct nfct_priv *priv = upi_priv(pi);
	int ret;

	pr_fn_debug("fd=%d what=%u arg=%p\n", fd, what, arg);

	if (what & ULOGD_FD_READ) {
		if ((ret = nl_recvmsgs_default(priv->nlh)) < 0) {
			if (ret == -ENOBUFS || nl_get_errno() == ENOBUFS)
				gc_start(pi);
			else {
				upi_log(pi, ULOGD_ERROR, "nl_recvmsgs: %s\n", nl_geterror());
				goto out;
			}
		}
	}

	return 0;

out:
	return -1;
}

/**
 * Garbage collection timer
 *
 * The GC timer is started if there is some netlink overrun reported,
 * either via %ENOBUFS from nl_recvmsgs() or if nfct_overrun_cb()
 * gets called.
 *
 * Each time the GC timer is called only a small slice of cache heads
 * is checked, it therefore takes some time before the GC timer
 * is gone over the whole cache data.
 *
 * The GC timer is stopped if it went over the whole cache data and
 * no other overrun occured in the meantime.
 */
static void
nfct_gc_timer_cb(struct ulogd_timer *t)
{
	struct ulogd_pluginstance *pi = t->data;
	struct nfct_priv *priv = upi_priv(pi);
	unsigned tc_start, tc_end, sc_start, sc_end;

    tc_start = priv->tcache->c_curr_head;
	sc_start = priv->scache->c_curr_head;

	tcache_cleanup(pi);
	scache_cleanup(pi);

    tc_end = priv->tcache->c_curr_head;
	sc_end = priv->scache->c_curr_head;

	upi_log(pi, ULOGD_DEBUG, "ct=%u t=%u [%u,%u[ s=%u [%u,%u[\n",
            num_conntrack,
            priv->tcache->c_cnt, tc_start, tc_end,
            priv->scache->c_cnt, sc_start, sc_end);

	if (tc_end == 0) {
		if (--priv->overruns == 0) {
			ulogd_unregister_timer(&priv->timer);

			upi_log(pi, ULOGD_DEBUG, "GC timer stopped\n");
		}

		if (priv->overruns < 0)
			priv->overruns = 0;
	}
}

static int
nfct_configure(struct ulogd_pluginstance *pi)
{
	struct nfct_priv *priv = upi_priv(pi);

	pr_fn_debug("pi=%p\n", pi);

    if (disable_ce(pi) != 0) {
        upi_log(pi, ULOGD_INFO, "disabled on user request\n");
        return ULOGD_IRET_STOP;
    }

	if (buckets_ce(pi) < TCACHE_MIN_SIZE) {
		buckets_ce(pi) = TCACHE_MIN_SIZE;
		upi_log(pi, ULOGD_NOTICE, "cache too small, set to %d\n",
				TCACHE_MIN_SIZE);
	}

	if (timeout_ce(pi) < TIMEOUT) {
		timeout_ce(pi) = TIMEOUT;
		upi_log(pi, ULOGD_NOTICE, "timeout too small, set to %d\n",
				TCACHE_MIN_SIZE);
	}

	ulogd_init_fd(&priv->ufd, -1, ULOGD_FD_READ, nfct_ufd_cb, pi);

	return ULOGD_IRET_OK;
}

static int
init_caches(struct ulogd_pluginstance *pi)
{
	struct nfct_priv *priv = upi_priv(pi);
	struct cache *c;

	/* tuple cache */
	c = priv->tcache = cache_alloc(buckets_ce(pi));
	if (c == NULL) {
		upi_log(pi, ULOGD_FATAL, "out of memory\n");
		return ULOGD_IRET_ERR;
	}

	c->c_add = tcache_add;
	c->c_del = tcache_del;

	/* sequence cache */
	c = priv->scache = cache_alloc(SCACHE_SIZE);
	if (c == NULL) {
		cache_free(priv->tcache);
		priv->tcache = NULL;

		upi_log(pi, ULOGD_FATAL, "out of memory\n");
		return ULOGD_IRET_ERR;
	}

	c->c_add = scache_add;
	c->c_del = scache_del;

	return 0;
}

static int
netlink_init(struct ulogd_pluginstance *pi)
{
	struct nfct_priv *priv = upi_priv(pi);
	struct nl_cb *cb;

	if ((priv->nlh = nl_handle_alloc()) == NULL) {
		upi_log(pi, ULOGD_FATAL, "error allocating netlink handle");
		return -1;
	}

	nl_socket_modify_cb(priv->nlh, NL_CB_VALID, NL_CB_CUSTOM,
						nfct_parse_valid_cb, pi);
	nl_socket_modify_cb(priv->nlh, NL_CB_OVERRUN, NL_CB_CUSTOM,
						nfct_overrun_cb, pi);

	/* setup error handler */
	cb = nl_socket_get_cb(priv->nlh);
	nl_cb_err(cb, NL_CB_CUSTOM, nfct_err_cb, pi);

	nl_disable_sequence_check(priv->nlh);

	if (nfnl_connect(priv->nlh) < 0) {
		upi_log(pi, ULOGD_FATAL, "connect: %s\n", nl_geterror());
		goto err_handle_destroy;
    }

	if (set_sockbuf_len(nl_socket_get_fd(priv->nlh),
						RCVBUF_LEN, SNDBUF_LEN) < 0)
		goto err_handle_destroy;

	nl_socket_set_nonblocking(priv->nlh);

	nl_socket_add_membership(priv->nlh, NFNLGRP_CONNTRACK_NEW);
	nl_socket_add_membership(priv->nlh, NFNLGRP_CONNTRACK_UPDATE);
	nl_socket_add_membership(priv->nlh, NFNLGRP_CONNTRACK_DESTROY);

	return 0;

err_handle_destroy:
	nl_handle_destroy(priv->nlh);

	return -1;
}

static int
nfct_start(struct ulogd_pluginstance *pi)
{
	struct nfct_priv *priv = upi_priv(pi);

	pr_fn_debug("pi=%p\n", pi);

	if (init_caches(pi) < 0)
		goto err;

	if (netlink_init(pi) < 0)
		goto err;

	assert(priv->nlh != NULL);

	priv->ufd.fd = nl_socket_get_fd(priv->nlh);

	if (ulogd_register_fd(&priv->ufd) < 0)
		goto err;

    priv->timer.cb = nfct_gc_timer_cb;
    priv->timer.ival = 1 SEC;
    priv->timer.flags = TIMER_F_PERIODIC;
    priv->timer.data = pi;

	upi_log(pi, ULOGD_DEBUG, "ctnetlink connection opened\n");

	return ULOGD_IRET_OK;

err:
	return ULOGD_IRET_ERR;
}

static int
nfct_stop(struct ulogd_pluginstance *pi)
{
	struct nfct_priv *priv = upi_priv(pi);

	pr_fn_debug("pi=%p\n", pi);

    if (disable_ce(pi) != 0)
        return ULOGD_IRET_OK;               /* wasn't started */

	ulogd_unregister_timer(&priv->timer);

	ulogd_unregister_fd(&priv->ufd);

	if (priv->nlh != NULL) {
		nl_handle_destroy(priv->nlh);
		priv->nlh = NULL;
	}

	if (priv->tcache != NULL) {
		cache_free(priv->tcache);
		priv->tcache = NULL;
	}
	if (priv->scache != NULL) {
		cache_free(priv->scache);
		priv->scache = NULL;
	}

	upi_log(pi, ULOGD_DEBUG, "ctnetlink connection close\n");

	return ULOGD_IRET_OK;
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
	.configure	= nfct_configure,
	.start		= nfct_start,
	.stop		= nfct_stop,
	.config_kset 	= &nfct_kset,
	.rev		= ULOGD_PLUGIN_REVISION,
	.priv_size	= sizeof(struct nfct_priv),
};

void __upi_ctor init(void);

void
init(void)
{
	ulogd_register_plugin(&nfct_plugin);
}

