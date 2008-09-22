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
#include <libnetfilter_log/libnetfilter_log.h>

#ifndef NFLOG_GROUP_DEFAULT
#define NFLOG_GROUP_DEFAULT	0
#endif

/* Size of the socket recevive memory.  Should be at least the same size as the
 * 'nlbufsiz' parameter of nfnetlink_log.ko
 * If you have _big_ in-kernel queues, you may have to increase this number.  (
 * --qthreshold 100 * 1500 bytes/packet = 150kB  */
#define NFLOG_RMEM_DEFAULT	131071

/* Size of the receive buffer for the netlink socket.  Should be at least of
 * RMEM_DEFAULT size.  */
#define NFLOG_BUFSIZE_DEFAULT	150000

struct nflog_priv {
	struct nflog_handle *nful_h;
	struct nflog_g_handle *nful_gh;
	unsigned char *nfulog_buf;
	struct ulogd_fd nful_fd;
};

/* configuration entries */
static struct config_keyset libulog_kset = {
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


static int
nflog_interp(struct ulogd_pluginstance *upi, struct nflog_data *ldata)
{
	struct ulogd_key *out = upi->output.keys;
	struct nfulnl_msg_packet_hdr *ph;
	struct nfulnl_msg_packet_hw *hw;
	char *payload;
	int payload_len;
	char *prefix;
	struct timeval ts;
	u_int32_t dev, seq, mark;
	

	if ((ph = nflog_get_msg_packet_hdr(ldata)) != NULL)
		key_u8(&out[K_OOB_HOOK], ph->hook);

	if ((hw = nflog_get_packet_hw(ldata)) != NULL) {
		key_ptr(&out[K_RAW_MAC], &hw->hw_addr);
		key_u16(&out[K_RAW_MAC_LEN], ntohs(hw->hw_addrlen));
	}

	if ((payload_len = nflog_get_payload(ldata, &payload)) >= 0) {
		key_ptr(&out[K_RAW_PKT], payload);
		key_u32(&out[K_RAW_PKTLEN], payload_len);
	}

	key_u32(&out[K_RAW_PKTCNT], 1);

	if ((prefix = nflog_get_prefix(ldata)) != NULL)
		key_ptr(&out[K_OOB_PREFIX], prefix);

	/* god knows why timestamp_usec contains crap if timestamp_sec
	 * == 0 if (pkt->timestamp_sec || pkt->timestamp_usec) { */
	if (nflog_get_timestamp(ldata, &ts) == 0 && ts.tv_sec) {
		/* FIXME: convert endianness */
		key_u32(&out[K_OOB_TIME_SEC], ts.tv_sec & 0xffffffff);
		key_u32(&out[K_OOB_TIME_USEC], ts.tv_usec & 0xffffffff);
	}

	key_u32(&out[K_OOB_MARK], nflog_get_nfmark(ldata));

	if ((dev = nflog_get_indev(ldata)) > 0)
		key_u32(&out[K_OOB_IFI_IN], dev);
	if ((dev = nflog_get_outdev(ldata)) > 0)
		key_u32(&out[K_OOB_IFI_OUT], dev);

	if (nflog_get_seq(ldata, &seq) == 0)
		key_u32(&out[K_OOB_SEQ], seq);

	if (nflog_get_seq_global(ldata, &seq) == 0)
		key_u32(&out[K_OOB_SEQ_GLOBAL], seq);

	if (nflog_get_logmark(ldata, &mark) == 0)
		key_u32(&out[K_OOB_LOGMARK], mark);
	
	ulogd_propagate_results(upi);

	return 0;
}

/* callback called from ulogd core when fd is readable */
static int
nful_read_cb(int fd, unsigned int what, void *param)
{
	struct ulogd_pluginstance *upi = (struct ulogd_pluginstance *)param;
	struct nflog_priv *priv = upi_priv(upi);
	int len;

	if (!(what & ULOGD_FD_READ))
		return 0;

	/* we don't have a while loop here, since we don't want to
	 * grab all the processing time just for us.  there might be other
	 * sockets that have pending work */
	len = recv(fd, priv->nfulog_buf, bufsiz_ce(upi->config_kset).u.value, 0);
	if (len < 0)
		return len;

	nflog_handle_packet(priv->nful_h, (char *)priv->nfulog_buf, len);

	return 0;
}

/* callback called by libnfnetlink* for every nlmsg */
static int
msg_cb(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg,
	   struct nflog_data *nfa, void *data)
{
	struct ulogd_pluginstance *upi = data;

	return nflog_interp(upi, nfa);
}

static int
nflog_configure(struct ulogd_pluginstance *upi,
		  struct ulogd_pluginstance_stack *stack)
{
	if (config_parse_file(upi->id, upi->config_kset) < 0)
		return ULOGD_IRET_STOP;

	return 0;
}

static int
nflog_start(struct ulogd_pluginstance *upi)
{
	struct nflog_priv *priv = upi_priv(upi);
	unsigned int flags;

	priv->nfulog_buf = malloc(bufsiz_ce(upi->config_kset).u.value);
	if (!priv->nfulog_buf)
		goto out_buf;

	ulogd_log(ULOGD_DEBUG, "opening nfnetlink socket\n");
	priv->nful_h = nflog_open();
	if (!priv->nful_h)
		goto out_handle;

	if (unbind_ce(upi->config_kset).u.value > 0) {
		ulogd_log(ULOGD_NOTICE, "forcing unbind of existing log "
			  "handler for protocol %d\n", 
			  af_ce(upi->config_kset).u.value);
		if (nflog_unbind_pf(priv->nful_h,
				    af_ce(upi->config_kset).u.value) < 0) {
			ulogd_log(ULOGD_ERROR, "unable to force-unbind "
				  "existing log handler for protocol %d\n",
			  	  af_ce(upi->config_kset).u.value);
			goto out_handle;
		}
	}

	ulogd_log(ULOGD_DEBUG, "binding to protocol family %d\n",
		  af_ce(upi->config_kset).u.value);
	if (nflog_bind_pf(priv->nful_h, af_ce(upi->config_kset).u.value) < 0) {
		ulogd_log(ULOGD_ERROR, "unable to bind to protocol family %d\n",
			  af_ce(upi->config_kset).u.value);
		goto out_bind_pf;
	}

	ulogd_log(ULOGD_DEBUG, "binding to log group %d\n",
		  group_ce(upi->config_kset).u.value);
	priv->nful_gh = nflog_bind_group(priv->nful_h,
				       group_ce(upi->config_kset).u.value);
	if (!priv->nful_gh) {
		ulogd_log(ULOGD_ERROR, "unable to bind to log group %d\n",
			  group_ce(upi->config_kset).u.value);
		goto out_bind;
	}

	nflog_set_mode(priv->nful_gh, NFULNL_COPY_PACKET, 0xffff);

	//nflog_set_nlbufsiz(&priv->nful_gh, );
	//nfnl_set_rcvbuf();
	
	/* set log flags based on configuration */
	flags = 0;
	if (seq_ce(upi->config_kset).u.value != 0)
		flags = NFULNL_CFG_F_SEQ;
	if (seq_ce(upi->config_kset).u.value != 0)
		flags |= NFULNL_CFG_F_SEQ_GLOBAL;
	if (flags) {
		if (nflog_set_flags(priv->nful_gh, flags) < 0)
			ulogd_log(ULOGD_ERROR, "unable to set flags 0x%x\n",
				  flags);
	}
	
	nflog_callback_register(priv->nful_gh, &msg_cb, upi);

	priv->nful_fd.fd = nflog_fd(priv->nful_h);
	priv->nful_fd.cb = &nful_read_cb;
	priv->nful_fd.data = upi;
	priv->nful_fd.when = ULOGD_FD_READ;

	if (ulogd_register_fd(&priv->nful_fd) < 0)
		goto out_bind;

	return 0;

out_bind:
	nflog_close(priv->nful_h);
out_bind_pf:
	nflog_unbind_pf(priv->nful_h, af_ce(upi->config_kset).u.value);
out_handle:
	free(priv->nfulog_buf);
out_buf:
	return ULOGD_IRET_STOP;
}

static int
nflog_stop(struct ulogd_pluginstance *pi)
{
	struct nflog_priv *priv = upi_priv(pi);

	ulogd_unregister_fd(&priv->nful_fd);

	nflog_unbind_group(priv->nful_gh);
	nflog_close(priv->nful_h);

	return 0;
}

struct ulogd_plugin libulog_plugin = {
	.name = "NFLOG",
	.input = {
			.type = ULOGD_DTYPE_SOURCE,
		},
	.output = {
			.type = ULOGD_DTYPE_RAW,
			.keys = output_keys,
			.num_keys = ARRAY_SIZE(output_keys),
		},
	.priv_size 	= sizeof(struct nflog_priv),
	.configure 	= &nflog_configure,
	.start 		= &nflog_start,
	.stop 		= &nflog_stop,
	.config_kset = &libulog_kset,
	.rev		= ULOGD_PLUGIN_REVISION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&libulog_plugin);
}
