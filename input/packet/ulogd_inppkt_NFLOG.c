/* ulogd_inppkt_NFLOG.c - stackable input plugin for NFLOG packets -> ulogd2
 *
 * (C) 2004-2005 by Harald Welte <laforge@gnumonks.org>
 */

#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdbool.h>

#include <ulogd/ulogd.h>
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_log/libnetfilter_log.h>

#ifndef NFLOG_GROUP_DEFAULT
#define NFLOG_GROUP_DEFAULT	0
#endif

/* Size of the receive buffer for the netlink socket.  Should be at least of
 * RMEM_DEFAULT size.  */
#define NFLOG_BUFSIZE_DEFAULT	150000

struct nflog_input {
	struct nflog_handle *nful_h;
	struct nflog_g_handle *nful_gh;
	unsigned char *nfulog_buf;
	struct ulogd_fd nful_fd;
	int nlbufsiz;
	bool nful_overrun_warned;
};

/* configuration entries */

static struct config_keyset libulog_kset = {
	.num_ces = 11,
	.ces = {
		{
			.key 	 = "bufsize",
			.type 	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = NFLOG_BUFSIZE_DEFAULT,
		},
		{
			.key	 = "group",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = NFLOG_GROUP_DEFAULT,
		},
		{
			.key	 = "unbind",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 1,
		},
		{
			.key	 = "bind",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},

		{
			.key	 = "seq_local",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		{
			.key	 = "seq_global",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		{
			.key	 = "numeric_label",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		{
			.key     = "netlink_socket_buffer_size",
			.type    = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		{
			.key     = "netlink_socket_buffer_maxsize",
			.type    = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		{
			.key     = "netlink_qthreshold",
			.type    = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		{
			.key     = "netlink_qtimeout",
			.type    = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
	}
};

#define bufsiz_ce(x)	(x->ces[0])
#define group_ce(x)	(x->ces[1])
#define unbind_ce(x)	(x->ces[2])
#define bind_ce(x)	(x->ces[3])
#define seq_ce(x)	(x->ces[4])
#define seq_global_ce(x)	(x->ces[5])
#define label_ce(x)	(x->ces[6])
#define nlsockbufsize_ce(x) (x->ces[7])
#define nlsockbufmaxsize_ce(x) (x->ces[8])
#define nlthreshold_ce(x) (x->ces[9])
#define nltimeout_ce(x) (x->ces[10])

enum nflog_keys {
	NFLOG_KEY_RAW_MAC = 0,
	NFLOG_KEY_RAW_PCKT,
	NFLOG_KEY_RAW_PCKTLEN,
	NFLOG_KEY_RAW_PCKTCOUNT,
	NFLOG_KEY_OOB_PREFIX,
	NFLOG_KEY_OOB_TIME_SEC,
	NFLOG_KEY_OOB_TIME_USEC,
	NFLOG_KEY_OOB_MARK,
	NFLOG_KEY_OOB_IFINDEX_IN,
	NFLOG_KEY_OOB_IFINDEX_OUT,
	NFLOG_KEY_OOB_HOOK,
	NFLOG_KEY_RAW_MAC_LEN,
	NFLOG_KEY_OOB_SEQ_LOCAL,
	NFLOG_KEY_OOB_SEQ_GLOBAL,
	NFLOG_KEY_OOB_FAMILY,
	NFLOG_KEY_OOB_PROTOCOL,
	NFLOG_KEY_OOB_UID,
	NFLOG_KEY_OOB_GID,
	NFLOG_KEY_RAW_LABEL,
	NFLOG_KEY_RAW_TYPE,
	NFLOG_KEY_RAW_MAC_SADDR,
	NFLOG_KEY_RAW_MAC_ADDRLEN,
	NFLOG_KEY_RAW,
};

static struct ulogd_key output_keys[] = {
	[NFLOG_KEY_RAW_MAC] = {
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.mac",
	},
	[NFLOG_KEY_RAW_MAC_SADDR] = {
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.mac.saddr",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_sourceMacAddress,
		},
	},
	[NFLOG_KEY_RAW_PCKT] = {
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.pkt",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_rawpacket,
		},
	},
	[NFLOG_KEY_RAW_PCKTLEN] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.pktlen",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_rawpacket_length,
		},
	},
	[NFLOG_KEY_RAW_PCKTCOUNT] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.pktcount",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_packetDeltaCount,
		},
	},
	[NFLOG_KEY_OOB_PREFIX] = {
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.prefix",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_prefix,
		},
	},
	[NFLOG_KEY_OOB_TIME_SEC] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.time.sec",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_flowStartSeconds,
		},
	},
	[NFLOG_KEY_OOB_TIME_USEC] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.time.usec",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_flowStartMicroSeconds,
		},
	},
	[NFLOG_KEY_OOB_MARK] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.mark",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_mark,
		},
	},
	[NFLOG_KEY_OOB_IFINDEX_IN] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.ifindex_in",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_ingressInterface,
		},
	},
	[NFLOG_KEY_OOB_IFINDEX_OUT] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.ifindex_out",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_egressInterface,
		},
	},
	[NFLOG_KEY_OOB_HOOK] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.hook",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_hook,
		},
	},
	[NFLOG_KEY_RAW_MAC_LEN] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.mac_len",
	},
	[NFLOG_KEY_RAW_MAC_ADDRLEN] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.mac.addrlen",
	},

	[NFLOG_KEY_OOB_SEQ_LOCAL] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.seq.local",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_seq_local,
		},
	},
	[NFLOG_KEY_OOB_SEQ_GLOBAL] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.seq.global",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_seq_global,
		},
	},
	[NFLOG_KEY_OOB_FAMILY] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.family",
	},
	[NFLOG_KEY_OOB_PROTOCOL] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.protocol",
	},
	[NFLOG_KEY_OOB_UID] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.uid",
	},
	[NFLOG_KEY_OOB_GID] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.gid",
	},
	[NFLOG_KEY_RAW_LABEL] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.label",
	},
	[NFLOG_KEY_RAW_TYPE] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.type",
	},
	[NFLOG_KEY_RAW] = {
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_NONE,
		.name = "raw",
	},
};

static inline int
interp_packet(struct ulogd_pluginstance *upi, u_int8_t pf_family,
	      struct nflog_data *ldata)
{
	struct ulogd_key *ret = upi->output.keys;

	struct nfulnl_msg_packet_hdr *ph = nflog_get_msg_packet_hdr(ldata);
	struct nfulnl_msg_packet_hw *hw = nflog_get_packet_hw(ldata);
	char *payload;
	int payload_len = nflog_get_payload(ldata, &payload);
	char *prefix = nflog_get_prefix(ldata);
	struct timeval ts;
	u_int32_t mark = nflog_get_nfmark(ldata);
	u_int32_t indev = nflog_get_indev(ldata);
	u_int32_t outdev = nflog_get_outdev(ldata);
	u_int32_t seq;
	u_int32_t uid;
	u_int32_t gid;

	okey_set_u8(&ret[NFLOG_KEY_OOB_FAMILY], 
		    pf_family);
	okey_set_u8(&ret[NFLOG_KEY_RAW_LABEL],
		    label_ce(upi->config_kset).u.value);

	if (ph) {
		okey_set_u8(&ret[NFLOG_KEY_OOB_HOOK], ph->hook);
		okey_set_u16(&ret[NFLOG_KEY_OOB_PROTOCOL],
			     ntohs(ph->hw_protocol));
	}

	if (nflog_get_msg_packet_hwhdrlen(ldata)) {
		okey_set_ptr(&ret[NFLOG_KEY_RAW_MAC], 
			     nflog_get_msg_packet_hwhdr(ldata));
		okey_set_u16(&ret[NFLOG_KEY_RAW_MAC_LEN],
			     nflog_get_msg_packet_hwhdrlen(ldata));
		okey_set_u16(&ret[NFLOG_KEY_RAW_TYPE], nflog_get_hwtype(ldata));
	}

	if (hw) {
		okey_set_ptr(&ret[NFLOG_KEY_RAW_MAC_SADDR], hw->hw_addr);
		okey_set_u16(&ret[NFLOG_KEY_RAW_MAC_ADDRLEN], 
			     ntohs(hw->hw_addrlen));
	}

	if (payload_len >= 0) {
		/* include pointer to raw packet */
		okey_set_ptr(&ret[NFLOG_KEY_RAW_PCKT], payload);
		okey_set_u32(&ret[NFLOG_KEY_RAW_PCKTLEN], payload_len);
	}

	/* number of packets */
	okey_set_u32(&ret[NFLOG_KEY_RAW_PCKTCOUNT], 1);

	if (prefix)
		okey_set_ptr(&ret[NFLOG_KEY_OOB_PREFIX], prefix);

	/* god knows why timestamp_usec contains crap if timestamp_sec
	 * == 0 if (pkt->timestamp_sec || pkt->timestamp_usec) { */
	if (! (nflog_get_timestamp(ldata, &ts) == 0 && ts.tv_sec))
		gettimeofday(&ts, NULL);

	okey_set_u32(&ret[NFLOG_KEY_OOB_TIME_SEC], ts.tv_sec & 0xffffffff);
	okey_set_u32(&ret[NFLOG_KEY_OOB_TIME_USEC], ts.tv_usec & 0xffffffff);

	okey_set_u32(&ret[NFLOG_KEY_OOB_MARK], mark);

	if (indev > 0)
		okey_set_u32(&ret[NFLOG_KEY_OOB_IFINDEX_IN], indev);

	if (outdev > 0)
		okey_set_u32(&ret[NFLOG_KEY_OOB_IFINDEX_OUT], outdev);

	if (nflog_get_uid(ldata, &uid) == 0)
		okey_set_u32(&ret[NFLOG_KEY_OOB_UID], uid);
	if (nflog_get_gid(ldata, &gid) == 0)
		okey_set_u32(&ret[NFLOG_KEY_OOB_GID], gid);
	if (nflog_get_seq(ldata, &seq) == 0)
		okey_set_u32(&ret[NFLOG_KEY_OOB_SEQ_LOCAL], seq);
	if (nflog_get_seq_global(ldata, &seq) == 0)
		okey_set_u32(&ret[NFLOG_KEY_OOB_SEQ_GLOBAL], seq);

	okey_set_ptr(&ret[NFLOG_KEY_RAW], ldata);

	ulogd_propagate_results(upi);
	return 0;
}

static int setnlbufsiz(struct ulogd_pluginstance *upi, int size)
{
	struct nflog_input *ui = (struct nflog_input *)upi->private;

	if (size < nlsockbufmaxsize_ce(upi->config_kset).u.value) {
		ui->nlbufsiz = nfnl_rcvbufsiz(nflog_nfnlh(ui->nful_h), size);
		return 1;
	}

	ulogd_log(ULOGD_NOTICE, "Maximum buffer size (%d) in NFLOG has been "
				"reached. Please, consider rising "
				"`netlink_socket_buffer_size` and "
				"`netlink_socket_buffer_maxsize` "
				"clauses.\n", ui->nlbufsiz);
	return 0;
}

/* callback called from ulogd core when fd is readable */
static int nful_read_cb(int fd, unsigned int what, void *param)
{
	struct ulogd_pluginstance *upi = (struct ulogd_pluginstance *)param;
	struct nflog_input *ui = (struct nflog_input *)upi->private;
	int len;

	if (!(what & ULOGD_FD_READ))
		return 0;

	/* we don't have a while loop here, since we don't want to
	 * grab all the processing time just for us.  there might be other
	 * sockets that have pending work */
	len = recv(fd, ui->nfulog_buf, bufsiz_ce(upi->config_kset).u.value, 0);
	if (len < 0) {
		if (errno == ENOBUFS && !ui->nful_overrun_warned) {
			if (nlsockbufmaxsize_ce(upi->config_kset).u.value) {
				int s = ui->nlbufsiz * 2;
				if (setnlbufsiz(upi, s)) {
					ulogd_log(ULOGD_NOTICE,
						  "We are losing events, "
						  "increasing buffer size "
						  "to %d\n", ui->nlbufsiz);
				} else {
					/* we have reached the maximum buffer
					 * limit size, don't perform any
					 * further treatments on overruns. */
					ui->nful_overrun_warned = true;
				}
			} else {
				ulogd_log(ULOGD_NOTICE,
					  "We are losing events. Please, "
					  "consider using the clauses "
					  "`netlink_socket_buffer_size' and "
					  "`netlink_socket_buffer_maxsize'\n");
				/* display the previous log message once. */
				ui->nful_overrun_warned = true;
			}
		}
		return len;
	}

	nflog_handle_packet(ui->nful_h, (char *)ui->nfulog_buf, len);

	return 0;
}

/* callback called by libnfnetlink* for every nlmsg */
static int msg_cb(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg,
		  struct nflog_data *nfa, void *data)
{
	struct ulogd_pluginstance *upi = data;
	struct ulogd_pluginstance *npi = NULL;
	int ret = 0;

	/* since we support the re-use of one instance in several 
	 * different stacks, we duplicate the message to let them know */
	llist_for_each_entry(npi, &upi->plist, plist) {
		ret = interp_packet(npi, nfmsg->nfgen_family, nfa);
		if (ret != 0)
			return ret;
	}
	return interp_packet(upi, nfmsg->nfgen_family, nfa);
}

static int configure(struct ulogd_pluginstance *upi,
		     struct ulogd_pluginstance_stack *stack)
{
	ulogd_log(ULOGD_DEBUG, "parsing config file section `%s', "
		  "plugin `%s'\n", upi->id, upi->plugin->name);

	config_parse_file(upi->id, upi->config_kset);
	return 0;
}

static int become_system_logging(struct ulogd_pluginstance *upi, u_int8_t pf)
{
	struct nflog_input *ui = (struct nflog_input *) upi->private;

	if (unbind_ce(upi->config_kset).u.value > 0) {
		ulogd_log(ULOGD_NOTICE, "forcing unbind of existing log "
				"handler for protocol %d\n",
				pf);
		if (nflog_unbind_pf(ui->nful_h, pf) < 0) {
			ulogd_log(ULOGD_ERROR, "unable to force-unbind "
					"existing log handler for protocol %d\n",
					pf);
			return -1;
		}
	}

	ulogd_log(ULOGD_DEBUG, "binding to protocol family %d\n", pf);
	if (nflog_bind_pf(ui->nful_h, pf) < 0) {
		ulogd_log(ULOGD_ERROR, "unable to bind to"
				" protocol family %d\n", pf);
		return -1;
	}
	return 0;
}

static int start(struct ulogd_pluginstance *upi)
{
	struct nflog_input *ui = (struct nflog_input *) upi->private;
	unsigned int flags;

	ui->nfulog_buf = malloc(bufsiz_ce(upi->config_kset).u.value);
	if (!ui->nfulog_buf)
		goto out_buf;

	ulogd_log(ULOGD_DEBUG, "opening nfnetlink socket\n");
	ui->nful_h = nflog_open();
	if (!ui->nful_h)
		goto out_handle;

	/* This is the system logging (conntrack, ...) facility */
	if ((group_ce(upi->config_kset).u.value == 0) ||
			(bind_ce(upi->config_kset).u.value > 0)) {
		if (become_system_logging(upi, AF_INET) == -1)
			goto out_handle;
		if (become_system_logging(upi, AF_INET6) == -1)
			goto out_handle;
		if (become_system_logging(upi, AF_BRIDGE) == -1)
			goto out_handle;
	}

	ulogd_log(ULOGD_DEBUG, "binding to log group %d\n",
		  group_ce(upi->config_kset).u.value);
	ui->nful_gh = nflog_bind_group(ui->nful_h,
				       group_ce(upi->config_kset).u.value);
	if (!ui->nful_gh) {
		ulogd_log(ULOGD_ERROR, "unable to bind to log group %d\n",
			  group_ce(upi->config_kset).u.value);
		goto out_bind;
	}

	nflog_set_mode(ui->nful_gh, NFULNL_COPY_PACKET, 0xffff);

	if (nlsockbufsize_ce(upi->config_kset).u.value) {
		setnlbufsiz(upi, nlsockbufsize_ce(upi->config_kset).u.value);
		ulogd_log(ULOGD_NOTICE, "NFLOG netlink buffer size has been "
					"set to %d\n", ui->nlbufsiz);
	}

	if (nlthreshold_ce(upi->config_kset).u.value) {
		if (nflog_set_qthresh(ui->nful_gh,
				  nlthreshold_ce(upi->config_kset).u.value)
				>= 0)
			ulogd_log(ULOGD_NOTICE,
				  "NFLOG netlink queue threshold has "
					"been set to %d\n",
				  nlthreshold_ce(upi->config_kset).u.value);
		else
			ulogd_log(ULOGD_NOTICE,
				  "NFLOG netlink queue threshold can't "
				  "be set to %d\n",
				  nlthreshold_ce(upi->config_kset).u.value);
	}

	if (nltimeout_ce(upi->config_kset).u.value) {
		if (nflog_set_timeout(ui->nful_gh,
				      nltimeout_ce(upi->config_kset).u.value)
			>= 0)
			ulogd_log(ULOGD_NOTICE,
				  "NFLOG netlink queue timeout has "
					"been set to %d\n",
				  nltimeout_ce(upi->config_kset).u.value);
		else
			ulogd_log(ULOGD_NOTICE,
				  "NFLOG netlink queue timeout can't "
				  "be set to %d\n",
				  nltimeout_ce(upi->config_kset).u.value);
	}

	/* set log flags based on configuration */
	flags = 0;
	if (seq_ce(upi->config_kset).u.value != 0)
		flags = NFULNL_CFG_F_SEQ;
	if (seq_ce(upi->config_kset).u.value != 0)
		flags |= NFULNL_CFG_F_SEQ_GLOBAL;
	if (flags) {
		if (nflog_set_flags(ui->nful_gh, flags) < 0)
			ulogd_log(ULOGD_ERROR, "unable to set flags 0x%x\n",
				  flags);
	}

	nflog_callback_register(ui->nful_gh, &msg_cb, upi);

	ui->nful_fd.fd = nflog_fd(ui->nful_h);
	ui->nful_fd.cb = &nful_read_cb;
	ui->nful_fd.data = upi;
	ui->nful_fd.when = ULOGD_FD_READ;

	if (ulogd_register_fd(&ui->nful_fd) < 0)
		goto out_bind;

	ui->nful_overrun_warned = false;

	return 0;

out_bind:
	if (group_ce(upi->config_kset).u.value == 0) {
		nflog_unbind_pf(ui->nful_h, AF_INET);
		nflog_unbind_pf(ui->nful_h, AF_INET6);
		nflog_unbind_pf(ui->nful_h, AF_BRIDGE);
	}
	nflog_close(ui->nful_h);
out_handle:
	free(ui->nfulog_buf);
out_buf:
	return -1;
}

static int stop(struct ulogd_pluginstance *pi)
{
	struct nflog_input *ui = (struct nflog_input *)pi->private;

	ulogd_unregister_fd(&ui->nful_fd);
	nflog_unbind_group(ui->nful_gh);
	nflog_close(ui->nful_h);

	free(ui->nfulog_buf);

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
	.priv_size 	= sizeof(struct nflog_input),
	.configure 	= &configure,
	.start 		= &start,
	.stop 		= &stop,
	.config_kset 	= &libulog_kset,
	.version	= VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&libulog_plugin);
}
