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

#include <netlink/netfilter/nfnl.h>
#include <netlink/netfilter/ct.h>
#include <netlink/attr.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include "linux_jhash.h"

#define RCVBUF_LEN		(1 << 18)
#define SNDBUF_LEN		RCVBUF_LEN

/* configuration defaults */
#define TCACHE_SIZE		8192
#define SCACHE_SIZE	    512
#define TCACHE_REQ_MAX	100
#define TIMEOUT			30 SEC


typedef enum { START, UPDATE, STOP, __TIME_MAX } TIMES;

union ct_protoinfo {
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
	uint32_t src;
	uint32_t dst;
	uint8_t family;
	uint8_t l4proto;
	union ct_protoinfo pinfo;
};

struct conntrack {
	struct llist_head link;
	struct ct_tuple tuple;
	struct nfnl_ct *nfnl_ct;
	unsigned refcnt;
	struct timeval time[__TIME_MAX];
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
};

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
};


static unsigned num_conntrack;
static struct ulogd_key nfct_okeys[] = {
	[O_IP_SADDR] = KEY_IPFIX(IPADDR, "ip.saddr", IETF, sourceIPv4Address),
	[O_IP_DADDR] = KEY_IPFIX(IPADDR, "ip.daddr", IETF,destinationIPv4Address),
	[O_IP_PROTO] = KEY_IPFIX(UINT8, "ip.protocol", IETF, protocolIdentifier),
	[O_L4_SPORT] = KEY_IPFIX(UINT16, "l4.sport", IETF, sourceTransportPort),
	[O_L4_DPORT] = KEY_IPFIX(UINT16, "l4.dport", IETF,
							 destinationTransportPort),
	/* FIXME: this could also be octetDeltaCount */
	[O_RAW_IN_PKTLEN] = KEY_IPFIX(UINT32, "raw.in.pktlen", IETF,
								  octetTotalCount),
	/* FIXME: this could also be packetDeltaCount */
	[O_RAW_IN_PKTCOUNT] = KEY_IPFIX(UINT32, "raw.in.pktcount", IETF,
									packetTotalCount),
	/* FIXME: this could also be octetDeltaCount */
	[O_RAW_OUT_PKTLEN] = KEY_IPFIX(UINT32, "raw.out.pktlen", IETF,
								   octetTotalCount),
	/* FIXME: this could also be packetDeltaCount */
	[O_RAW_OUT_PKTCOUNT] = KEY_IPFIX(UINT32, "raw.out.pktcount",
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

	ct->time[UPDATE].tv_sec = ct->time[START].tv_sec = t_now_local;

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

static void
ct_dump_tuple(const struct ct_tuple *t)
{
	printf("IP src=%lu dst=%lu family=%u l4proto=%u dport=%u\n",
		   (unsigned long)t->src, (unsigned long)t->dst,
		   t->family, t->l4proto, htons(t->pinfo.tcp.dport));
}

static int
nfnl_ct_to_tuple(const struct nfnl_ct *nfnl_ct, struct ct_tuple *t)
{
	struct nl_addr *nl_addr;

	if (t == NULL)
		return -1;

	memset(t, 0, sizeof(*t));

	if ((nl_addr = nfnl_ct_get_src(nfnl_ct, 0 /* orig */)) == NULL)
		return -1;
	t->src = *((uint32_t *)nl_addr_get_binary_addr(nl_addr));

	if ((nl_addr = nfnl_ct_get_dst(nfnl_ct, 0 /* orig */)) == NULL)
		return -1;
	t->dst = *((uint32_t *)nl_addr_get_binary_addr(nl_addr));

	t->family = nfnl_ct_get_family(nfnl_ct);
	t->l4proto = nfnl_ct_get_proto(nfnl_ct);

	switch (t->l4proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		t->pinfo.tcp.sport = nfnl_ct_get_src_port(nfnl_ct, 0);
		t->pinfo.tcp.dport = nfnl_ct_get_dst_port(nfnl_ct, 0);
		break;

	case IPPROTO_ICMP:
		t->pinfo.icmp.type = nfnl_ct_get_icmp_type(nfnl_ct, 0);
		t->pinfo.icmp.code = nfnl_ct_get_icmp_code(nfnl_ct, 0);
		break;

	default:
		break;
	}

#if 0
	ct_dump_tuple(t);
#endif /* 0 */

	return 0;
}

/* tuple cache */
static ct_hash_t
tcache_hash(const struct cache *c, const struct ct_tuple *t)
{
	static unsigned rnd;

	if (rnd == 0U)
		rnd = rand();

	return jhash_3words(t->src, t->dst ^ t->l4proto, t->pinfo.all,
						rnd) % c->c_num_heads;
}

static int
ct_tuple_cmp(const struct ct_tuple *t1, const struct ct_tuple *t2)
{
	return memcmp(t1, t2, sizeof(struct ct_tuple));
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
propagate_ct(struct ulogd_pluginstance *pi, struct conntrack *ct)
{
	struct nfct_priv *priv = upi_priv(pi);
	struct ulogd_key *out = pi->output.keys;
	struct nfnl_ct *nfnl_ct = ct->nfnl_ct;

	pr_fn_debug("pi=%p ct=%p\n", pi, ct);

	ct->time[STOP].tv_sec = t_now_local;

	key_u32(&out[O_IP_SADDR], ntohl(ct->tuple.src));
    key_u32(&out[O_IP_DADDR], ntohl(ct->tuple.dst));
    key_u8(&out[O_IP_PROTO], ct->tuple.l4proto);

	switch (ct->tuple.l4proto) {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
    case IPPROTO_SCTP:
        key_u16(&out[O_L4_SPORT], ntohs(nfnl_ct_get_src_port(nfnl_ct, 0)));
        key_u16(&out[O_L4_DPORT], ntohs(nfnl_ct_get_dst_port(nfnl_ct, 1)));
		break;

    case IPPROTO_ICMP:
		key_u8(&out[O_ICMP_CODE], nfnl_ct_get_icmp_code(nfnl_ct, 0));
        key_u8(&out[O_ICMP_TYPE], nfnl_ct_get_icmp_type(nfnl_ct, 0));
        break;

	default:
		break;
	}

	/* TODO check if counters are there */
	key_u32(&out[O_RAW_IN_PKTLEN], (uint32_t)nfnl_ct_get_bytes(nfnl_ct, 0));
	key_u32(&out[O_RAW_IN_PKTCOUNT],
			(uint32_t)nfnl_ct_get_packets(nfnl_ct, 0));

	key_u32(&out[O_RAW_OUT_PKTLEN], (uint32_t)nfnl_ct_get_bytes(nfnl_ct, 1));
	key_u32(&out[O_RAW_OUT_PKTCOUNT],
			(uint32_t)nfnl_ct_get_packets(nfnl_ct, 1));

	if (nfnl_ct_test_mark(nfnl_ct))
		key_u32(&out[O_CT_MARK], nfnl_ct_get_mark(nfnl_ct));
	if (nfnl_ct_test_id(nfnl_ct))
		key_u32(&out[O_CT_ID], nfnl_ct_get_id(nfnl_ct));

	key_u32(&out[O_FLOW_START_SEC], ct->time[START].tv_sec);
    key_u32(&out[O_FLOW_START_USEC], ct->time[START].tv_usec);
    key_u32(&out[O_FLOW_END_SEC], ct->time[STOP].tv_sec);
    key_u32(&out[O_FLOW_END_USEC], ct->time[STOP].tv_usec);
    key_u32(&out[O_FLOW_DURATION], tv_diff_sec(&ct->time[START],
                                               &ct->time[STOP]));

	ulogd_propagate_results(pi);

	cache_del(priv->tcache, ct);

	return 0;
}

static int
nfct_parse_valid_cb(struct nl_msg *msg, void *arg)
{
	struct ulogd_pluginstance *pi = arg;
	struct nfct_priv *priv = upi_priv(pi);
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nfnl_ct *nfnl_ct;
	struct ct_tuple tuple;
	struct conntrack *ct;
	int grp;

	pr_fn_debug("msg=%p pi=%p\n", msg, pi);

	nfnl_ct = nfnlmsg_ct_parse(nlh);

	nfnl_ct_to_tuple(nfnl_ct, &tuple);

	switch (grp = nfnlmsg_ct_group(nlh)) {
	case NFNLGRP_CONNTRACK_NEW:
		assert(tcache_find(priv->tcache, &tuple) == NULL);

		if ((ct = ct_alloc_init(nfnl_ct, &tuple)) == NULL) {
			upi_log(pi, ULOGD_ERROR, "out of memory\n");
			goto err_put_ct;
		}

		if (cache_add(priv->tcache, ct) < 0) {
			/* TODO cleanup */
		}
		break;

	case NFNLGRP_CONNTRACK_UPDATE:
		if ((ct = tcache_find(priv->tcache, &tuple)) == NULL) {
			/* do not add CT to cache, as there would be no start
			   information */
			break;
		}

        ct->time[UPDATE].tv_sec = t_now_local;

		/* TODO update conntrack */
		upi_log(pi, ULOGD_DEBUG, "update ct %p\n", ct);
		break;

	case NFNLGRP_CONNTRACK_DESTROY:
		ct = tcache_find(priv->tcache, &tuple);
		if (ct != NULL) {
            if (propagate_ct(pi, ct) < 0)
				goto err_put_ct;
		}

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

	/* TODO start timer */

	return 0;
}

static int
nfct_ufd_cb(int fd, unsigned what, void *arg)
{
	struct ulogd_pluginstance *pi = arg;
	struct nfct_priv *priv = upi_priv(pi);

	pr_fn_debug("fd=%d what=%u arg=%p\n", fd, what, arg);

	if (what & ULOGD_FD_READ) {
		if (nl_recvmsgs_default(priv->nlh) < 0) {
			upi_log(pi, ULOGD_ERROR, "nl_recvmsgs: %s\n", nl_geterror());
			goto out;
		}
	}

	return 0;

out:
	return -1;
}

static void
nfct_timer_cb(struct ulogd_timer *t)
{

}

static int
nfct_configure(struct ulogd_pluginstance *pi)
{
	pr_fn_debug("pi=%p\n", pi);

	return 0;
}

static int
init_caches(struct ulogd_pluginstance *pi)
{
	struct nfct_priv *priv = upi_priv(pi);
	struct cache *c;

	c = priv->tcache = cache_alloc(TCACHE_SIZE);
	if (c == NULL) {
		upi_log(pi, ULOGD_FATAL, "out of memory\n");
		return ULOGD_IRET_ERR;
	}

	c->c_add = tcache_add;
	c->c_del = tcache_del;

	return 0;
}

static int
nfct_start(struct ulogd_pluginstance *pi)
{
	struct nfct_priv *priv = upi_priv(pi);

	pr_fn_debug("pi=%p\n", pi);

	if (init_caches(pi) < 0)
		return ULOGD_IRET_ERR;

	if ((priv->nlh = nl_handle_alloc()) == NULL) {
		upi_log(pi, ULOGD_FATAL, "error allocating netlink handle");
		goto err;
	}

	nl_socket_modify_cb(priv->nlh, NL_CB_VALID, NL_CB_CUSTOM,
						nfct_parse_valid_cb, pi);
	nl_socket_modify_cb(priv->nlh, NL_CB_OVERRUN, NL_CB_CUSTOM,
						nfct_overrun_cb, pi);

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

	priv->ufd.fd = nl_socket_get_fd(priv->nlh);
	priv->ufd.cb = &nfct_ufd_cb;
	priv->ufd.data = pi;
	priv->ufd.when = ULOGD_FD_READ;

	if (ulogd_register_fd(&priv->ufd) < 0)
		goto err_handle_destroy;

    priv->timer.cb = nfct_timer_cb;
    priv->timer.ival = 1 SEC;
    priv->timer.flags = TIMER_F_PERIODIC;
    priv->timer.data = pi;

    if (ulogd_register_timer(&priv->timer) < 0)
		goto err_unreg_ufd;

	upi_log(pi, ULOGD_DEBUG, "ctnetlink connection opened\n");

	return ULOGD_IRET_OK;

err_unreg_ufd:
	ulogd_unregister_fd(&priv->ufd);
err_handle_destroy:
	nl_handle_destroy(priv->nlh);
err:
	return ULOGD_IRET_ERR;
}

static int
nfct_stop(struct ulogd_pluginstance *pi)
{
	struct nfct_priv *priv = upi_priv(pi);

	pr_fn_debug("pi=%p\n", pi);

	ulogd_unregister_fd(&priv->ufd);

	if (priv->nlh != NULL) {
		nl_handle_destroy(priv->nlh);
		priv->nlh = NULL;
	}

	if (priv->tcache != NULL) {
		cache_free(priv->tcache);
		priv->tcache = NULL;
	}

	upi_log(pi, ULOGD_DEBUG, "ctnetlink connection close\n");

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
#if 0
	.config_kset 	= &nfct_kset,
#endif /* 0 */
	.configure	= nfct_configure,
	.start		= nfct_start,
	.stop		= nfct_stop,
	.rev		= ULOGD_PLUGIN_REVISION,
	.priv_size	= sizeof(struct nfct_priv),
};

void __upi_ctor init(void);

void
init(void)
{
	ulogd_register_plugin(&nfct_plugin);
}

