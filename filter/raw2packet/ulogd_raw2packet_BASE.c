/*
 * ulogd_raw2packet_BASE.c
 *
 * ulogd interpreter plugin for 
 *
 * 	o IP header
 * 	o TCP header
 * 	o UDP header
 * 	o ICMP header
 * 	o AH/ESP header
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
 *
 * Put a step further by H. Eitzenberger <holger@eitzenberger.org>,
 * Astaro AG 2008.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include "config.h"
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/plugin.h>
#include <ulogd/ipfix_protocol.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>


enum OutKeys {
	O_IpSAddr = 0,
	O_IpDAddr,
	O_IpProto,
	O_IpTos,
	O_IpTtl,
	O_IpTotLen,
	O_IpIhl,
	O_IpCsum,
	O_IpId,
	O_IpFragOff,
	O_TcpSPort,
	O_TcpDPort,
	O_TcpSeq,
	O_TcpAckSeq,
	O_TcpOff,
	O_TcpReserved,
	O_TcpWin,
	O_TcpUrg,
	O_TcpUrgp,
	O_TcpAck,
	O_TcpPsh,
	O_TcpRst,
	O_TcpSyn,
	O_TcpFin,
	O_TcpRes1,
	O_TcpRes2,
	O_TcpCsum,
	O_UdpSPort,
	O_UdpDPort,
	O_UdpLen,
	O_UdpCsum,
	O_IcmpType,
	O_IcmpCode,
	O_IcmpEchoId,
	O_IcmpEchoSeq,
	O_IcmpGw,
	O_IcmpFragMtu,
	O_IcmpCsum,
	O_AhEspSpi,
};

/***********************************************************************
 * 			IP HEADER
 ***********************************************************************/
static struct ulogd_key out_keys[] = {
	[O_IpSAddr] = {
		.type = ULOGD_RET_IPADDR,
		.name = "ip.saddr", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_sourceIPv4Address,
		},
	},
	[O_IpDAddr] = {
		.type = ULOGD_RET_IPADDR,
		.name = "ip.daddr", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_destinationIPv4Address,
		},
	},
	[O_IpProto] = {
		.type = ULOGD_RET_UINT8,
		.name = "ip.protocol", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_protocolIdentifier,
		},
	},
	[O_IpTos] = {
		.type = ULOGD_RET_UINT8,
		.name = "ip.tos", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_classOfServiceIPv4,
		},
	},
	[O_IpTtl] = {
		.type = ULOGD_RET_UINT8,
		.name = "ip.ttl", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_ipTimeToLive,
		},
	},
	[O_IpTotLen] {
		.type = ULOGD_RET_UINT16,
		.name = "ip.totlen", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_totalLengthIPv4,
		},
	},
	[O_IpIhl] = {
		.type = ULOGD_RET_UINT8,
		.name = "ip.ihl", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_internetHeaderLengthIPv4,
		},
	},
	[O_IpCsum] = {
		.type = ULOGD_RET_UINT16,
		.name = "ip.csum", 
	},
	[O_IpId] = {
		.type = ULOGD_RET_UINT16,
		.name = "ip.id", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_identificationIPv4,
		},
	},
	[O_IpFragOff] = {
		.type = ULOGD_RET_UINT16,
		.name = "ip.fragoff", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_fragmentOffsetIPv4,
		},
	},

	/* 10 */
	[O_TcpSPort] = {
		.type = ULOGD_RET_UINT16,
		.name = "tcp.sport", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpSourcePort,
		},
	},
	[O_TcpDPort] = {
		.type = ULOGD_RET_UINT16,
		.name = "tcp.dport", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpDestinationPort,
		},
	},
	[O_TcpSeq] = {
		.type = ULOGD_RET_UINT32,
		.name = "tcp.seq", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpSequenceNumber,
		},
	},
	[O_TcpAckSeq] = {
		.type = ULOGD_RET_UINT32,
		.name = "tcp.ackseq", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpAcknowledgementNumber,
		},
	},
	[O_TcpOff] = {
		.type = ULOGD_RET_UINT8,
		.name = "tcp.offset",
	},
	[O_TcpReserved] = {
		.type = ULOGD_RET_UINT8,
		.name = "tcp.reserved",
	}, 
	[O_TcpWin] = {
		.type = ULOGD_RET_UINT16,
		.name = "tcp.window",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpWindowSize,
		},
	},
	[O_TcpUrg] = {
		.type = ULOGD_RET_BOOL, 
		.name = "tcp.urg", 
	},
	[O_TcpUrgp] = {
		.type = ULOGD_RET_UINT16, 
		.name = "tcp.urgp",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpUrgentPointer,
		},
	},
	[O_TcpAck] = {
		.type = ULOGD_RET_BOOL, 
		.name = "tcp.ack", 
	},
	[O_TcpPsh] = {
		.type = ULOGD_RET_BOOL,
		.name = "tcp.psh",
	},
	[O_TcpRst] = {
		.type = ULOGD_RET_BOOL,
		.name = "tcp.rst",
	},
	[O_TcpSyn] = {
		.type = ULOGD_RET_BOOL,
		.name = "tcp.syn",
	},
	[O_TcpFin] = {
		.type = ULOGD_RET_BOOL,
		.name = "tcp.fin",
	},
	[O_TcpRes1] = {
		.type = ULOGD_RET_BOOL,
		.name = "tcp.res1",
	},
	[O_TcpRes2] = {
		.type = ULOGD_RET_BOOL,
		.name = "tcp.res2",
	},
	[O_TcpCsum] = {
		.type = ULOGD_RET_UINT16,
		.name = "tcp.csum",
	},

	/* 27 */
	[O_UdpSPort] = {
		.type = ULOGD_RET_UINT16,
		.name = "udp.sport", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF, 
			.field_id = IPFIX_udpSourcePort,
		},
	},
	[O_UdpDPort] = {
		.type = ULOGD_RET_UINT16,
		.name = "udp.dport", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_udpDestinationPort,
		},
	},
	[O_UdpLen] = {
		.type = ULOGD_RET_UINT16,
		.name = "udp.len", 
	},
	[O_UdpCsum] = {
		.type = ULOGD_RET_UINT16,
		.name = "udp.csum",
	},

	/* 31 */
	[O_IcmpType] = {
		.type = ULOGD_RET_UINT8,
		.name = "icmp.type", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_icmpTypeIPv4,
		},
	},
	[O_IcmpCode] {
		.type = ULOGD_RET_UINT8,
		.name = "icmp.code", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_icmpCodeIPv4,
		},
	},
	[O_IcmpEchoId] = {
		.type = ULOGD_RET_UINT16,
		.name = "icmp.echoid", 
	},
	[O_IcmpEchoSeq] = {
		.type = ULOGD_RET_UINT16,
		.name = "icmp.echoseq",
	},
	[O_IcmpGw] = {
		.type = ULOGD_RET_IPADDR,
		.name = "icmp.gateway", 
	},
	[O_IcmpFragMtu] = {
		.type = ULOGD_RET_UINT16,
		.name = "icmp.fragmtu", 
	},
	[O_IcmpCsum] = {
		.type = ULOGD_RET_UINT16,
		.name = "icmp.csum",
	},
	[O_AhEspSpi] = {
		.type = ULOGD_RET_UINT32,
		.name = "ahesp.spi",
	},
};

static void *
ipv4_data(const struct iphdr *iph)
{
	return (void *)((uint8_t *)iph + iph->ihl * 4);
}

/***********************************************************************
 * 			TCP HEADER
 ***********************************************************************/

static int
_interp_tcp(const struct ulogd_pluginstance *pi, const struct iphdr *iph)
{
	struct ulogd_key *ret = pi->output.keys;
	const struct tcphdr *tcph = ipv4_data(iph);

	assert(iph->protocol == IPPROTO_TCP);

	key_u16(&ret[O_TcpSPort], ntohs(tcph->source));
	key_u16(&ret[O_TcpDPort], ntohs(tcph->dest));
	key_u32(&ret[O_TcpSeq], ntohl(tcph->seq));
	key_u32(&ret[O_TcpAckSeq], ntohl(tcph->ack_seq));
	key_u8(&ret[O_TcpOff], ntohs(tcph->doff));
	key_u8(&ret[O_TcpReserved], ntohs(tcph->res1));
	key_u16(&ret[O_TcpWin],ntohs(tcph->window));

	key_bool(&ret[O_TcpUrg], tcph->urg);
	if (tcph->urg)
		key_u16(&ret[O_TcpUrgp], ntohs(tcph->urg_ptr));
	key_bool(&ret[O_TcpAck], tcph->ack);
	key_bool(&ret[O_TcpPsh],  tcph->psh);
	key_bool(&ret[O_TcpRst], tcph->rst);
	key_bool(&ret[O_TcpSyn], tcph->syn);
	key_bool(&ret[O_TcpFin], tcph->fin);
	key_bool(&ret[O_TcpRes1], tcph->res1);
	key_bool(&ret[O_TcpRes2], tcph->res2);
	key_bool(&ret[O_TcpCsum], ntohs(tcph->check));
	
	return 0;
}

/***********************************************************************
 * 			UDP HEADER
 ***********************************************************************/

static int
_interp_udp(const struct ulogd_pluginstance *pi, const struct iphdr *iph)
{
	struct ulogd_key *ret = pi->output.keys;
	const struct udphdr *udph = ipv4_data(iph);

	assert(iph->protocol == IPPROTO_UDP);

	key_u16(&ret[O_UdpSPort], ntohs(udph->source));
	key_u16(&ret[O_UdpDPort], ntohs(udph->dest));
	key_u16(&ret[O_UdpLen], ntohs(udph->len));
	key_u16(&ret[O_UdpCsum], ntohs(udph->check));
	
	return 0;
}

/***********************************************************************
 * 			ICMP HEADER
 ***********************************************************************/

static int
_interp_icmp(const struct ulogd_pluginstance *pi, const struct iphdr *iph)
{
	struct ulogd_key *ret = pi->output.keys;
	struct icmphdr *icmph = ipv4_data(iph);

	assert(iph->protocol == IPPROTO_ICMP);
	
	key_u8(&ret[O_IcmpType], icmph->type);
	key_u8(&ret[O_IcmpCode], icmph->code);

	switch (icmph->type) {
	case ICMP_ECHO:
	case ICMP_ECHOREPLY:
		key_u16(&ret[O_IcmpEchoId], ntohs(icmph->un.echo.id));
		key_u16(&ret[O_IcmpEchoSeq], ntohs(icmph->un.echo.sequence));
		break;

	case ICMP_REDIRECT:
	case ICMP_PARAMETERPROB:
		key_u32(&ret[O_IcmpGw], ntohl(icmph->un.gateway));
		break;

	case ICMP_DEST_UNREACH:
		if (icmph->code == ICMP_FRAG_NEEDED)
			key_u16(&ret[O_IcmpFragMtu], ntohs(icmph->un.frag.mtu));
		break;
	}

	key_u16(&ret[O_IcmpCsum], icmph->checksum);

	return 0;
}

/***********************************************************************
 * 			IPSEC HEADER 
 ***********************************************************************/

static int
_interp_ahesp(const struct ulogd_pluginstance *pi, const struct iphdr *iph)
{
#if 0
	struct ulogd_key *ret = &pi->output.keys[38];

	struct esphdr *esph = protoh;

	if (iph->protocol != IPPROTO_ESP)
		return NULL;

	ret[0].u.value.ui32 = ntohl(esph->spi);
	ret[0].flags |= ULOGD_RETF_VALID;
#endif

	return 0;
}

static int
_interp_iphdr(struct ulogd_pluginstance *pi)
{
	struct ulogd_key *ret = pi->output.keys;
	const struct iphdr *iph = key_get_ptr(&pi->input.keys[0]);

	key_u32(&ret[0], ntohl(iph->saddr));
	key_u32(&ret[1], ntohl(iph->daddr));
	key_u8(&ret[2], iph->protocol);
	key_u8(&ret[3], iph->tos);
	key_u8(&ret[4], iph->ttl);
	key_u16(&ret[5], ntohs(iph->tot_len));
	key_u8(&ret[6], iph->ihl);
	key_u16(&ret[7], ntohs(iph->check));
	key_u16(&ret[8], ntohs(iph->id));
	key_u16(&ret[9], ntohs(iph->frag_off));

	switch (iph->protocol) {
	case IPPROTO_TCP:
		_interp_tcp(pi, iph);
		break;

	case IPPROTO_UDP:
		_interp_udp(pi, iph);
		break;

	case IPPROTO_ICMP:
		_interp_icmp(pi, iph);
		break;

	case IPPROTO_AH:
	case IPPROTO_ESP:
		_interp_ahesp(pi, iph);
		break;
	}

	return 0;
}

static struct ulogd_key in_keys[] = {
	{ 
		.type = ULOGD_RET_RAW,
		.name = "raw.pkt", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_NETFILTER, 
			.field_id = 1 
		},
	},
};

static struct ulogd_plugin base_plugin = {
	.name = "BASE",
	.input = {
		.keys = in_keys,
		.num_keys = ARRAY_SIZE(in_keys),
		.type = ULOGD_DTYPE_RAW,
		},
	.output = {
		.keys = out_keys,
		.num_keys = ARRAY_SIZE(out_keys),
		.type = ULOGD_DTYPE_PACKET,
		},
	.interp = &_interp_iphdr,
	.rev = ULOGD_PLUGIN_REVISION,
};

void __attribute__ ((constructor)) init(void);

void
init(void)
{
	ulogd_register_plugin(&base_plugin);
}
