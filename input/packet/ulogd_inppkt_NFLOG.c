/*
 * ulogd_inppkt_NFLOG.c
 *
 * (C) 2004-2005 by Harald Welte <laforge@gnumonks.org>
 */
#include "config.h"
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/plugin.h>

#include <netinet/in.h>
#include <netlink/utils.h>
#include <netlink/msg.h>
#include <netlink/netfilter/nfnl.h>
#include <netlink/netfilter/log.h>

#ifndef NFLOG_GROUP_DEFAULT
#define NFLOG_GROUP_DEFAULT	0
#endif

/* Size of the socket recevive memory.  Should be at least the same size as the
 * 'nlbufsiz' parameter of nfnetlink_log.ko
 * If you have _big_ in-kernel queues, you may have to increase this number.  (
 * --qthreshold 100 * 1500 bytes/packet = 150kB  */
#define NFLOG_RMEM_DEFAULT 131071

/* Size of the receive buffer for the netlink socket.  Should be at least of
 * RMEM_DEFAULT size.  */
#define NFLOG_BUFSIZE_DEFAULT  150000

struct nflog_priv {
	struct nl_handle *nfnlh;
	struct ulogd_fd ufd;
};

/* configuration entries */
static const struct config_keyset nflog_kset = {
	.num_ces = 7,
	.ces = {
		{
			.key 	 = "bufsize",
			.type 	 = CONFIG_TYPE_INT,
			.u.value = NFLOG_BUFSIZE_DEFAULT,
		},
		{
			.key	 = "group",
			.type	 = CONFIG_TYPE_INT,
			.u.value = NFLOG_GROUP_DEFAULT,
		},
		{
			.key	 = "rmem",
			.type	 = CONFIG_TYPE_INT,
			.u.value = NFLOG_RMEM_DEFAULT,
		},
		{
			.key 	 = "addressfamily",
			.type	 = CONFIG_TYPE_INT,
			.u.value = AF_INET,
		},
		{
			.key	 = "unbind",
			.type	 = CONFIG_TYPE_INT,
			.u.value = 1,
		},
		{
			.key	 = "seq_local",
			.type	 = CONFIG_TYPE_INT,
			.u.value = 0,
		},
		{
			.key	 = "seq_global",
			.type	 = CONFIG_TYPE_INT,
			.u.value = 0,
		},
	}
};

#define bufsiz_ce(x)	(x->ces[0])
#define group_ce(x)	(x->ces[1])
#define rmem_ce(x)	(x->ces[2])
#define af_ce(x)	(x->ces[3])
#define unbind_ce(x)	(x->ces[4])
#define seq_ce(x)	(x->ces[4])
#define seq_global_ce(x)	(x->ces[5])


static struct ulogd_key output_keys[] = {
	{
		.type = ULOGD_RET_RAW, 
		.name = "raw.mac", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_sourceMacAddress,
		},
	},
	{
		.type = ULOGD_RET_RAW,
		.name = "raw.pkt",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_rawpacket,
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.name = "raw.pktlen",
		.ipfix = { 
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_rawpacket_length,
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.name = "raw.pktcount",
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_packetDeltaCount,
		},
	},
	{
		.type = ULOGD_RET_STRING,
		.name = "oob.prefix", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_prefix,  
		},
	},
	{ 	.type = ULOGD_RET_UINT32, 
		.name = "oob.time.sec", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF, 
			.field_id = IPFIX_flowStartSeconds, 
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.name = "oob.time.usec", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_flowStartMicroSeconds,
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.name = "oob.mark", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_mark,
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.name = "oob.ifindex_in", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_ingressInterface,
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.name = "oob.ifindex_out", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_egressInterface,
		},
	},
	{
		.type = ULOGD_RET_UINT8,
		.name = "oob.hook",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_hook,
		},
	},
	{ 
		.type = ULOGD_RET_UINT16,
		.name = "raw.mac_len", 
	},
	{
		.type = ULOGD_RET_UINT32,
		.name = "oob.seq.local",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_seq_local,
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.name = "oob.seq.global",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_seq_global,
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.name = "oob.logmark",
	},
};

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

static void
nflog_handle_msg(struct nl_object *obj, void *arg)
{
	struct ulogd_pluginstance *upi = arg;
	struct nfnl_log *nflog_obj = (struct nfnl_log *)obj;
	struct ulogd_key *out = upi->output.keys;
	const struct timeval *tv;
	int len;

	pr_fn_debug("pi=%p\n", upi);

	key_set_u8(&out[K_OOB_HOOK], nfnl_log_get_hook(nflog_obj));

	key_set_ptr(&out[K_RAW_MAC], (void*)nfnl_log_get_hwaddr(nflog_obj, &len));
	key_set_u16(&out[K_RAW_MAC_LEN], len);

	key_set_ptr(&out[K_RAW_PKT], (void*)nfnl_log_get_payload(nflog_obj, &len));
	key_set_u32(&out[K_RAW_PKTLEN], len);

	key_set_u32(&out[K_RAW_PKTCNT], 1);

	if (nfnl_log_get_prefix(nflog_obj) != NULL)
		key_set_ptr(&out[K_OOB_PREFIX], (void*)nfnl_log_get_prefix(nflog_obj));

	if ((tv = nfnl_log_get_timestamp(nflog_obj)) != NULL) {
		/* FIXME: convert endianness */
		key_set_u32(&out[K_OOB_TIME_SEC], tv->tv_sec);
		key_set_u32(&out[K_OOB_TIME_USEC], tv->tv_usec);
	}

	key_set_u32(&out[K_OOB_IFI_IN], nfnl_log_get_indev(nflog_obj));
	key_set_u32(&out[K_OOB_IFI_OUT], nfnl_log_get_outdev(nflog_obj));

	key_set_u32(&out[K_OOB_SEQ], nfnl_log_get_seq(nflog_obj));
	key_set_u32(&out[K_OOB_SEQ_GLOBAL], nfnl_log_get_seq_global(nflog_obj));

	key_set_u32(&out[K_OOB_LOGMARK], nfnl_log_get_mark(nflog_obj));

	ulogd_propagate_results(upi);
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
	priv->ufd.cb = &nflog_ufd_cb;
	priv->ufd.data = upi;
	priv->ufd.when = ULOGD_FD_READ;

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
