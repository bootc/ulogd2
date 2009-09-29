/*
 * ulogd_inppkt_NFLOG.c
 *
 * (C) 2004-2005 by Harald Welte <laforge@gnumonks.org>
 */
#include "config.h"
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/plugin.h>

#include <netinet/ether.h>

#include <netinet/in.h>
#include <netlink/utils.h>
#include <netlink/msg.h>
#include <netlink/netfilter/nfnl.h>
#include <netlink/netfilter/log.h>

#define NFLOG_GROUP_DEFAULT	0

struct nflog_priv {
	struct nl_handle *nfnlh;
	struct ulogd_fd ufd;
};

/* configuration entries */
static const struct config_keyset nflog_kset = {
	.num_ces = 5,
	.ces = {
		CONFIG_KEY_INT("group", NFLOG_GROUP_DEFAULT),
		CONFIG_KEY_INT("af", AF_INET),
		CONFIG_KEY_INT("unbind", 1),
		CONFIG_KEY_INT("seq_local", 0),
		CONFIG_KEY_INT("seq_global", 0),
	}
};

#define group_ce(x)	(x->ces[0])
#define af_ce(x)	(x->ces[1])
#define unbind_ce(x)	(x->ces[2])
#define seq_ce(x)	(x->ces[3])
#define seq_global_ce(x)	(x->ces[4])


enum {
	K_RAW_MAC = 0,
	K_RAW_PKT,
	K_RAW_PKTLEN,
	K_RAW_PKTCNT,
	K_OOB_PREFIX,
	K_OOB_TIME_SEC,
	K_OOB_TIME_USEC,
	K_OOB_MARK,
	K_OOB_IFI_IN,
	K_OOB_IFI_OUT,
	K_OOB_HOOK,
	K_RAW_MAC_LEN,
	K_OOB_SEQ,
	K_OOB_SEQ_GLOBAL,
	K_OOB_LOGMARK,
	__K_LAST
};

static struct ulogd_key output_keys[] = {
	[K_RAW_MAC] = KEY_IPFIX(RAW, "raw.mac", IETF, sourceMacAddress),
	[K_RAW_PKT] = KEY_IPFIX(RAW,  "raw.pkt", NETFILTER, NF_rawpacket),
	[K_RAW_PKTLEN] KEY_IPFIX(RAW, "raw.pktlen", NETFILTER,
							 NF_rawpacket_length),
	[K_RAW_PKTCNT] = KEY_IPFIX(UINT32, "raw.pktcount", IETF, packetDeltaCount),
	[K_OOB_PREFIX] = KEY_IPFIX(STRING, "oob.prefix", NETFILTER, NF_prefix),
	[K_OOB_TIME_SEC] = KEY_IPFIX(UINT32, "oob.time.sec", IETF,
								 flowStartSeconds),
	[K_OOB_TIME_USEC] = KEY_IPFIX(UINT32, "oob.time.usec", IETF,
								  flowStartMicroSeconds),
	[K_OOB_MARK] = KEY_IPFIX(UINT32, "oob.mark", NETFILTER, NF_mark),
	[K_OOB_IFI_IN] = KEY_IPFIX(UINT32, "oob.ifindex_in", IETF,
							   ingressInterface),
	[K_OOB_IFI_OUT] = KEY_IPFIX(UINT32, "oob.ifindex_out", IETF,
								egressInterface),
	[K_OOB_HOOK] = KEY_IPFIX(UINT8, "oob.hook", NETFILTER, NF_hook),
	[K_RAW_MAC_LEN] = KEY(UINT16, "raw.mac_len"),
	[K_OOB_SEQ] = KEY_IPFIX(UINT32, "oob.seq.local", NETFILTER, NF_seq_local),
	[K_OOB_SEQ_GLOBAL] = KEY_IPFIX(UINT32, "oob.seq.global", NETFILTER,
								   NF_seq_global),
	[K_OOB_LOGMARK] = KEY(UINT32, "oob.logmark"),
};

void nflog_dump(const char *prefix, const struct nl_object *obj)
	__ulogd_unused;

/* the libnl nl_object_dump() may not be used, because of the lacking
   cache_mgr support here. */
void
nflog_dump(const char *prefix, const struct nl_object *obj)
{
	static char line[128], *end = line + sizeof(line);
	struct nfnl_log *nflog_obj = (struct nfnl_log *)obj;
	struct ether_addr *mac;
	char buf[64], *pch = line;
	const char *nflog_prefix;
	int len, family;

#define AVAIL	(end - pch)

	if (prefix)
		pch += snprintf(pch, AVAIL, "%s: ", prefix);

	if (nfnl_log_get_indev(nflog_obj))
		pch += snprintf(pch, AVAIL, "in=%u ", nfnl_log_get_indev(nflog_obj));
	if (nfnl_log_get_physindev(nflog_obj))
		pch += snprintf(pch, AVAIL, "physin=%u ",
						nfnl_log_get_indev(nflog_obj));
	if (nfnl_log_get_outdev(nflog_obj))
		pch += snprintf(pch, AVAIL, "out=%u ",
						nfnl_log_get_outdev(nflog_obj));
	if (nfnl_log_get_physoutdev(nflog_obj))
		pch += snprintf(pch, AVAIL, "physout=%u ",
						nfnl_log_get_physoutdev(nflog_obj));

	if (nfnl_log_test_hook(nflog_obj))
		pch += snprintf(pch, AVAIL, "hook=%u ",
						nfnl_log_get_hook(nflog_obj));

	family = nfnl_log_get_family(nflog_obj);
	pch += snprintf(pch, AVAIL, "family=%s ",
					nl_af2str(family, buf, sizeof(buf)));

	if (nfnl_log_test_hwproto(nflog_obj)) {
		uint16_t proto = nfnl_log_get_hwproto(nflog_obj);

		pch += snprintf(pch, AVAIL, "proto=%s ",
						nl_ether_proto2str(proto, buf, sizeof(buf)));
	}

	mac = (struct ether_addr *)nfnl_log_get_hwaddr(nflog_obj, &len);
	if (mac)
		pch += snprintf(pch, AVAIL, "mac=%s ", ether_ntoa(mac));

	if (nfnl_log_test_mark(nflog_obj))
		pch += snprintf(pch, AVAIL, "mark=%u ",	nfnl_log_get_mark(nflog_obj));

#if 0
	if (nfnl_log_test_logmark(nflog_obj))
		pch += snprintf(pch, AVAIL, "logmark=%u ",
						nfnl_log_get_logmark(nflog_obj));
#endif /* 0 */

	if (nfnl_log_get_payload(nflog_obj, &len))
		pch += snprintf(pch, AVAIL, "payloadlen=%d ", len);

	if ((nflog_prefix = nfnl_log_get_prefix(nflog_obj)) && *nflog_prefix)
		pch += snprintf(pch, AVAIL, "prefix='%s' ", nflog_prefix);

	*(end - 1) = '\0';

#undef AVAIL

	ulogd_log(ULOGD_INFO, "%s\n", line);
}

static void
nflog_handle_msg(struct nl_object *obj, void *arg)
{
	struct ulogd_pluginstance *upi = arg;
	struct nfnl_log *nflog_obj = (struct nfnl_log *)obj;
	struct ulogd_key *out = upi->output.keys;
	const struct timeval *tv;
	char *prefix;
	unsigned flags = 0;
	int len;

	pr_fn_debug("pi=%p\n", upi);

	key_set_u8(&out[K_OOB_HOOK], nfnl_log_get_hook(nflog_obj));

	key_set_ptr(&out[K_RAW_MAC], (void*)nfnl_log_get_hwaddr(nflog_obj, &len));
	key_set_u16(&out[K_RAW_MAC_LEN], len);

	key_set_ptr(&out[K_RAW_PKT], (void*)nfnl_log_get_payload(nflog_obj, &len));
	key_set_u32(&out[K_RAW_PKTLEN], len);

	key_set_u32(&out[K_RAW_PKTCNT], 1);

	if ((prefix = nfnl_log_get_prefix(nflog_obj)) != NULL && *prefix)
		key_set_str(&out[K_OOB_PREFIX], (void*)nfnl_log_get_prefix(nflog_obj));

	if ((tv = nfnl_log_get_timestamp(nflog_obj)) != NULL) {
		/* FIXME: convert endianness */
		key_set_u32(&out[K_OOB_TIME_SEC], tv->tv_sec);
		key_set_u32(&out[K_OOB_TIME_USEC], tv->tv_usec);
	}

	key_set_u32(&out[K_OOB_IFI_IN], nfnl_log_get_indev(nflog_obj));
	key_set_u32(&out[K_OOB_IFI_OUT], nfnl_log_get_outdev(nflog_obj));

	key_set_u32(&out[K_OOB_SEQ], nfnl_log_get_seq(nflog_obj));
	key_set_u32(&out[K_OOB_SEQ_GLOBAL], nfnl_log_get_seq_global(nflog_obj));

#if 0
	/* Astaro logmark */
	key_set_u32(&out[K_OOB_LOGMARK], nfnl_log_get_logmark(nflog_obj));
#endif /* 0 */

	ulogd_propagate_results(upi, &flags);
}

/*
 * Called from libnl for every valid netlink message.
 */
static int
nflog_parse_valid_msg(struct nl_msg *msg, void *arg)
{
	struct ulogd_pluginstance *upi = arg;

	pr_fn_debug("pi=%p msg=%p arg=%p\n", upi, msg, arg);

	if (nl_msg_parse(msg, nflog_handle_msg, upi) < 0)
		upi_log(upi, ULOGD_ERROR, "parse: %s\n", nl_geterror());

	return NL_OK;
}

/* callback called from ulogd core when fd is readable */
static int
nflog_ufd_cb(int fd, unsigned int what, void *arg)
{
	struct ulogd_pluginstance *upi = arg;
	struct nflog_priv *priv = upi_priv(upi);

	pr_fn_debug("fd=%d arg=%p\n", fd, arg);

	if (!(what & ULOGD_FD_READ))
		return 0;

	return nl_recvmsgs_default(priv->nfnlh);
}

static int
nflog_configure(struct ulogd_pluginstance *upi)
{
	struct nflog_priv *priv = upi_priv(upi);

	ulogd_init_fd(&priv->ufd, -1, ULOGD_FD_READ, nflog_ufd_cb, upi);

	return 0;
}

static int
nflog_start(struct ulogd_pluginstance *upi)
{
	struct nflog_priv *priv = upi_priv(upi);

	pr_fn_debug("pi=%p\n", upi);

	upi_log(upi, ULOGD_DEBUG, "opening nfnetlink socket\n");
	if ((priv->nfnlh = nl_handle_alloc()) == NULL) {
		upi_log(upi, ULOGD_ERROR, "open: %s\n", nl_geterror());
		return ULOGD_IRET_ERR;
	}

	nl_disable_sequence_check(priv->nfnlh);

	if (nl_socket_modify_cb(priv->nfnlh, NL_CB_VALID, NL_CB_CUSTOM,
							nflog_parse_valid_msg, upi) < 0) {
		upi_log(upi, ULOGD_ERROR, "callback: %s\n", nl_geterror());
		return ULOGD_IRET_ERR;
	}

	if (nfnl_connect(priv->nfnlh) < 0) {
		upi_log(upi, ULOGD_ERROR, "connect: %s\n", nl_geterror());
		return ULOGD_IRET_ERR;
	}

	if (nl_socket_set_nonblocking(priv->nfnlh) < 0) {
		upi_log(upi, ULOGD_ERROR, "%s\n", nl_geterror());
		return -1;
	}

	upi_log(upi, ULOGD_DEBUG, "binding to protocol family %d\n",
		  af_ce(upi->config_kset).u.value);
	if (nfnl_log_pf_unbind(priv->nfnlh, af_ce(upi->config_kset).u.value) < 0) {
		upi_log(upi, ULOGD_ERROR, "unbind: %s\n", nl_geterror());
		return ULOGD_IRET_ERR;
	}

	if (nfnl_log_pf_bind(priv->nfnlh, af_ce(upi->config_kset).u.value) < 0) {
		upi_log(upi, ULOGD_ERROR, "unable to bind to family %d\n",
				af_ce(upi->config_kset).u.value);
		return ULOGD_IRET_ERR;
	}

	upi_log(upi, ULOGD_DEBUG, "binding to log group %d\n",
			group_ce(upi->config_kset).u.value);
	if (nfnl_log_bind(priv->nfnlh, group_ce(upi->config_kset).u.value) < 0) {
		upi_log(upi, ULOGD_ERROR, "unable to bind to log group '%d'\n",
				group_ce(upi->config_kset).u.value);
		return ULOGD_IRET_ERR;
	}

	/* TODO use COPY_PACKET define */
	nfnl_log_set_mode(priv->nfnlh, 0, 2 /* COPY_PACKET */, 0xffff);

	/* TODO set flags */

	priv->ufd.fd = nl_socket_get_fd(priv->nfnlh);
	if (ulogd_register_fd(&priv->ufd) < 0)
		goto err_free;

	return 0;

err_free:
	/* free nl_handle */

	return ULOGD_IRET_ERR;
}

static int
nflog_stop(struct ulogd_pluginstance *upi)
{
	struct nflog_priv *priv = upi_priv(upi);

	pr_fn_debug("pi=%p\n", upi);

	ulogd_unregister_fd(&priv->ufd);

	nfnl_log_pf_unbind(priv->nfnlh, af_ce(upi->config_kset).u.value);
	nl_close(priv->nfnlh);

	return 0;
}

struct ulogd_plugin nflog_plugin = {
	.name = "NFLOG",
	.flags = ULOGD_PF_RECONF,
	.input = {
			.type = ULOGD_DTYPE_SOURCE,
		},
	.output = {
			.type = ULOGD_DTYPE_RAW,
			.keys = output_keys,
			.num_keys = ARRAY_SIZE(output_keys),
		},
	.priv_size 	= sizeof(struct nflog_priv),
	.configure = &nflog_configure,
	.start 		= &nflog_start,
	.stop 		= &nflog_stop,
	.config_kset = &nflog_kset,
	.rev		= ULOGD_PLUGIN_REVISION,
};

void __upi_ctor init(void);

void init(void)
{
	ulogd_register_plugin(&nflog_plugin);
}
