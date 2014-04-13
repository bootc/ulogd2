/* ulogd_MAC.c
 *
 * ulogd interpreter plugin for 
 * 	o MAC addresses
 * 	o NFMARK field
 * 	o TIME
 * 	o Interface names
 * 	o IP header
 * 	o TCP header
 * 	o UDP header
 * 	o ICMP header
 * 	o AH/ESP header
 *      o ARP header
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
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
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <ulogd/ulogd.h>
#include <ulogd/ipfix_protocol.h>
#include <netinet/if_ether.h>
#include <string.h>

enum input_keys {
	INKEY_RAW_PCKT,
	INKEY_RAW_PCKTLEN,
	INKEY_OOB_FAMILY,
	INKEY_OOB_PROTOCOL,
};

enum output_keys {
	KEY_IP_SADDR,
	KEY_IP_DADDR,
	KEY_IP_PROTOCOL,
	KEY_IP_TOS,
	KEY_IP_TTL,
	KEY_IP_TOTLEN,
	KEY_IP_IHL,
	KEY_IP_CSUM,
	KEY_IP_ID,
	KEY_IP_FRAGOFF,
	KEY_IP6_PAYLOAD_LEN,
	KEY_IP6_PRIORITY,
	KEY_IP6_FLOWLABEL,
	KEY_IP6_HOPLIMIT,
	KEY_IP6_NEXTHDR,
	KEY_IP6_FRAG_OFF,
	KEY_IP6_FRAG_ID,
	KEY_TCP_SPORT,
	KEY_TCP_DPORT,
	KEY_TCP_SEQ,
	KEY_TCP_ACKSEQ,
	KEY_TCP_WINDOW,
	KEY_TCP_OFFSET,
	KEY_TCP_RESERVED,
	KEY_TCP_URG,
	KEY_TCP_URGP,
	KEY_TCP_ACK,
	KEY_TCP_PSH,
	KEY_TCP_RST,
	KEY_TCP_SYN,
	KEY_TCP_FIN,
	KEY_TCP_RES1,
	KEY_TCP_RES2,
	KEY_TCP_CSUM,
	KEY_UDP_SPORT,
	KEY_UDP_DPORT,
	KEY_UDP_LEN,
	KEY_UDP_CSUM,
	KEY_ICMP_TYPE,
	KEY_ICMP_CODE,
	KEY_ICMP_ECHOID,
	KEY_ICMP_ECHOSEQ,
	KEY_ICMP_GATEWAY,
	KEY_ICMP_FRAGMTU,
	KEY_ICMP_CSUM,
	KEY_ICMPV6_TYPE,
	KEY_ICMPV6_CODE,
	KEY_ICMPV6_ECHOID,
	KEY_ICMPV6_ECHOSEQ,
	KEY_ICMPV6_CSUM,
	KEY_AHESP_SPI,
	KEY_OOB_PROTOCOL,
	KEY_ARP_HTYPE,
	KEY_ARP_PTYPE,
	KEY_ARP_OPCODE,
	KEY_ARP_SHA,
	KEY_ARP_SPA,
	KEY_ARP_THA,
	KEY_ARP_TPA,
	KEY_SCTP_SPORT,
	KEY_SCTP_DPORT,
	KEY_SCTP_CSUM,

};

static struct ulogd_key iphdr_rets[] = {
	[KEY_IP_SADDR] = { 
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE, 
		.name = "ip.saddr", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_sourceIPv4Address,
		},
	},
	[KEY_IP_DADDR] = {
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.daddr", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_destinationIPv4Address,
		},
	},
	[KEY_IP_PROTOCOL] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.protocol", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_protocolIdentifier,
		},
	},
	[KEY_IP_TOS] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.tos", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_classOfServiceIPv4,
		},
	},
	[KEY_IP_TTL] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.ttl", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_ipTimeToLive,
		},
	},
	[KEY_IP_TOTLEN] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.totlen", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_totalLengthIPv4,
		},
	},
	[KEY_IP_IHL] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.ihl", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_internetHeaderLengthIPv4,
		},
	},
	[KEY_IP_CSUM] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.csum", 
	},
	[KEY_IP_ID] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.id", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_identificationIPv4,
		},
	},
	[KEY_IP_FRAGOFF] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.fragoff", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_fragmentOffsetIPv4,
		},
	},
	[KEY_IP6_PAYLOAD_LEN] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "ip6.payloadlen",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_payloadLengthIPv6,
		},
	},
	[KEY_IP6_PRIORITY] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip6.priority",
	},
	[KEY_IP6_FLOWLABEL] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "ip6.flowlabel",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_flowLabelIPv6,
		},
	},
	[KEY_IP6_HOPLIMIT] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip6.hoplimit",
	},
	[KEY_IP6_NEXTHDR] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip6.nexthdr",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_nextHeaderIPv6,
		},
	},
	[KEY_IP6_FRAG_OFF] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "ip6.fragoff",
	},
	[KEY_IP6_FRAG_ID] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "ip6.fragid",
	},
	[KEY_TCP_SPORT] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.sport", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpSourcePort,
		},
		.cim_name = "src_port",
	},
	[KEY_TCP_DPORT] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.dport", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpDestinationPort,
		},
		.cim_name = "dest_port",
	},
	[KEY_TCP_SEQ] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.seq", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpSequenceNumber,
		},
	},
	[KEY_TCP_ACKSEQ] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.ackseq", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpAcknowledgementNumber,
		},
	},
	[KEY_TCP_OFFSET] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE, 
		.name = "tcp.offset",
	},
	[KEY_TCP_RESERVED] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.reserved",
	}, 
	[KEY_TCP_WINDOW] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.window",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpWindowSize,
		},
	},
	[KEY_TCP_URG] = {
		.type = ULOGD_RET_BOOL, 
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.urg", 
	},
	[KEY_TCP_URGP] = {
		.type = ULOGD_RET_UINT16, 
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.urgp",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpUrgentPointer,
		},
	},
	[KEY_TCP_ACK] = {
		.type = ULOGD_RET_BOOL, 
		.flags = ULOGD_RETF_NONE, 
		.name = "tcp.ack", 
	},
	[KEY_TCP_PSH] = {
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.psh",
	},
	[KEY_TCP_RST] = {
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.rst",
	},
	[KEY_TCP_SYN] = {
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.syn",
	},
	[KEY_TCP_FIN] = {
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.fin",
	},
	[KEY_TCP_RES1] = {
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.res1",
	},
	[KEY_TCP_RES2] = {
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.res2",
	},
	[KEY_TCP_CSUM] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.csum",
	},
	[KEY_UDP_SPORT] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "udp.sport", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF, 
			.field_id = IPFIX_udpSourcePort,
		},
		.cim_name = "src_port",
	},
	[KEY_UDP_DPORT] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "udp.dport", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_udpDestinationPort,
		},
		.cim_name = "dest_port",
	},
	[KEY_UDP_LEN] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "udp.len", 
	},
	[KEY_UDP_CSUM] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "udp.csum",
	},
	[KEY_ICMP_TYPE] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.type", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_icmpTypeIPv4,
		},
	},
	[KEY_ICMP_CODE] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.code", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_icmpCodeIPv4,
		},
	},
	[KEY_ICMP_ECHOID] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.echoid", 
	},
	[KEY_ICMP_ECHOSEQ] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.echoseq",
	},
	[KEY_ICMP_GATEWAY] = {
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.gateway", 
	},
	[KEY_ICMP_FRAGMTU] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.fragmtu", 
	},
	[KEY_ICMP_CSUM] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.csum",
	},
	[KEY_ICMPV6_TYPE] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "icmpv6.type", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_icmpTypeIPv6,
		},
	},
	[KEY_ICMPV6_CODE] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "icmpv6.code", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_icmpCodeIPv6,
		},
	},
	[KEY_ICMPV6_ECHOID] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "icmpv6.echoid", 
	},
	[KEY_ICMPV6_ECHOSEQ] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "icmpv6.echoseq",
	},
	[KEY_ICMPV6_CSUM] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "icmpv6.csum",
	},
	[KEY_AHESP_SPI] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "ahesp.spi",
	},
	[KEY_OOB_PROTOCOL] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.protocol",
	},
	[KEY_ARP_HTYPE] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "arp.hwtype",
	},
	[KEY_ARP_PTYPE] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "arp.protocoltype",
	},
	[KEY_ARP_OPCODE] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "arp.operation",
	},
	[KEY_ARP_SHA] = {
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_NONE,
		.name = "arp.shwaddr",
	},
	[KEY_ARP_SPA] = {
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE,
		.name = "arp.saddr",
	},
	[KEY_ARP_THA] = {
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_NONE,
		.name = "arp.dhwaddr",
	},
	[KEY_ARP_TPA] = {
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE,
		.name = "arp.daddr",
	},
	[KEY_SCTP_SPORT] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "sctp.sport",
		.cim_name = "src_port",
	},
	[KEY_SCTP_DPORT] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "sctp.dport",
		.cim_name = "dest_port",
	},
	[KEY_SCTP_CSUM] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "sctp.csum",
	},
};

/***********************************************************************
 * 			TCP HEADER
 ***********************************************************************/

static int _interp_tcp(struct ulogd_pluginstance *pi, struct tcphdr *tcph,
		       u_int32_t len)
{
	struct ulogd_key *ret = pi->output.keys;

	if (len < sizeof(struct tcphdr))
		return ULOGD_IRET_OK;
	
	okey_set_u16(&ret[KEY_TCP_SPORT], ntohs(tcph->source));
	okey_set_u16(&ret[KEY_TCP_DPORT], ntohs(tcph->dest));
	okey_set_u32(&ret[KEY_TCP_SEQ], ntohl(tcph->seq));
	okey_set_u32(&ret[KEY_TCP_ACKSEQ], ntohl(tcph->ack_seq));
	okey_set_u8(&ret[KEY_TCP_OFFSET], ntohs(tcph->doff));
	okey_set_u8(&ret[KEY_TCP_RESERVED], ntohs(tcph->res1));
	okey_set_u16(&ret[KEY_TCP_WINDOW], ntohs(tcph->window));

	okey_set_b(&ret[KEY_TCP_URG], tcph->urg);
	if (tcph->urg)
		okey_set_u16(&ret[KEY_TCP_URGP], ntohs(tcph->urg_ptr));
	okey_set_b(&ret[KEY_TCP_ACK], tcph->ack);
	okey_set_b(&ret[KEY_TCP_PSH], tcph->psh);
	okey_set_b(&ret[KEY_TCP_RST], tcph->rst);
	okey_set_b(&ret[KEY_TCP_SYN], tcph->syn);
	okey_set_b(&ret[KEY_TCP_FIN], tcph->fin);
	okey_set_b(&ret[KEY_TCP_RES1], tcph->res1);
	okey_set_b(&ret[KEY_TCP_RES2], tcph->res2);
	okey_set_u16(&ret[KEY_TCP_CSUM], ntohs(tcph->check));
	
	return ULOGD_IRET_OK;
}

/***********************************************************************
 * 			UDP HEADER
 ***********************************************************************/

static int _interp_udp(struct ulogd_pluginstance *pi, struct udphdr *udph,
		       u_int32_t len)
		
{
	struct ulogd_key *ret = pi->output.keys;

	if (len < sizeof(struct udphdr))
		return ULOGD_IRET_OK;

	okey_set_u16(&ret[KEY_UDP_SPORT], ntohs(udph->source));
	okey_set_u16(&ret[KEY_UDP_DPORT], ntohs(udph->dest));
	okey_set_u16(&ret[KEY_UDP_LEN], ntohs(udph->len));
	okey_set_u16(&ret[KEY_UDP_CSUM], ntohs(udph->check));
	
	return ULOGD_IRET_OK;
}

/***********************************************************************
 * 			SCTP HEADER
 ***********************************************************************/

/* Section 3.1.  SCTP Common Header Format */
typedef struct sctphdr {
	__be16 source;
	__be16 dest;
	__be32 vtag;
	__be32 checksum;
} __attribute__((packed)) sctp_sctphdr_t;

static int _interp_sctp(struct ulogd_pluginstance *pi, struct sctphdr *sctph,
		       u_int32_t len)
		
{
	struct ulogd_key *ret = pi->output.keys;

	if (len < sizeof(struct sctphdr))
		return ULOGD_IRET_OK;

	ret[KEY_SCTP_SPORT].u.value.ui16 = ntohs(sctph->source);
	ret[KEY_SCTP_SPORT].flags |= ULOGD_RETF_VALID;
	ret[KEY_SCTP_DPORT].u.value.ui16 = ntohs(sctph->dest);
	ret[KEY_SCTP_DPORT].flags |= ULOGD_RETF_VALID;
	ret[KEY_SCTP_CSUM].u.value.ui32 = ntohl(sctph->checksum);
	ret[KEY_SCTP_CSUM].flags |= ULOGD_RETF_VALID;
	
	return ULOGD_IRET_OK;
}

/***********************************************************************
 * 			ICMP HEADER
 ***********************************************************************/

static int _interp_icmp(struct ulogd_pluginstance *pi, struct icmphdr *icmph,
			u_int32_t len)
{
	struct ulogd_key *ret = pi->output.keys;

	if (len < sizeof(struct icmphdr))
		return ULOGD_IRET_OK;

	okey_set_u8(&ret[KEY_ICMP_TYPE], icmph->type);
	okey_set_u8(&ret[KEY_ICMP_CODE], icmph->code);

	switch (icmph->type) {
	case ICMP_ECHO:
	case ICMP_ECHOREPLY:
		okey_set_u16(&ret[KEY_ICMP_ECHOID], ntohs(icmph->un.echo.id));
		okey_set_u16(&ret[KEY_ICMP_ECHOSEQ],
			     ntohs(icmph->un.echo.sequence));
		break;
	case ICMP_REDIRECT:
	case ICMP_PARAMETERPROB:
		okey_set_u32(&ret[KEY_ICMP_GATEWAY], ntohl(icmph->un.gateway));
		break;
	case ICMP_DEST_UNREACH:
		if (icmph->code == ICMP_FRAG_NEEDED) {
			okey_set_u16(&ret[KEY_ICMP_FRAGMTU],
				     ntohs(icmph->un.frag.mtu));
		}
		break;
	}
	okey_set_u16(&ret[KEY_ICMP_CSUM], icmph->checksum);

	return ULOGD_IRET_OK;
}

/***********************************************************************
 * 			ICMPv6 HEADER
 ***********************************************************************/

static int _interp_icmpv6(struct ulogd_pluginstance *pi, struct icmp6_hdr *icmph,
			  u_int32_t len)
{
	struct ulogd_key *ret = pi->output.keys;

	if (len < sizeof(struct icmp6_hdr))
		return ULOGD_IRET_OK;

	okey_set_u8(&ret[KEY_ICMPV6_TYPE], icmph->icmp6_type);
	okey_set_u8(&ret[KEY_ICMPV6_CODE], icmph->icmp6_code);

	switch (icmph->icmp6_type) {
	case ICMP6_ECHO_REQUEST:
	case ICMP6_ECHO_REPLY:
		okey_set_u16(&ret[KEY_ICMPV6_ECHOID], ntohs(icmph->icmp6_id));
		okey_set_u16(&ret[KEY_ICMPV6_ECHOSEQ],
			      ntohs(icmph->icmp6_seq));
		break;
	}
	okey_set_u16(&ret[KEY_ICMPV6_CSUM], icmph->icmp6_cksum);

	return ULOGD_IRET_OK;
}


/***********************************************************************
 * 			IPSEC HEADER 
 ***********************************************************************/
static int _interp_ahesp(struct ulogd_pluginstance *pi, void *protoh,
			 u_int32_t len)
{
#if 0
	struct ulogd_key *ret = pi->output.keys;
	struct esphdr *esph = protoh;

	if (len < sizeof(struct esphdr))
		return 0;

	ret[KEY_AHESP_SPI].u.value.ui32 = ntohl(esph->spi);
	ret[KEY_AHESP_SPI].flags |= ULOGD_RETF_VALID;
#endif

	return ULOGD_IRET_OK;
}

/***********************************************************************
 * 			IP HEADER
 ***********************************************************************/

static int _interp_iphdr(struct ulogd_pluginstance *pi, u_int32_t len)
{
	struct ulogd_key *ret = pi->output.keys;
	struct iphdr *iph =
		ikey_get_ptr(&pi->input.keys[INKEY_RAW_PCKT]);
	void *nexthdr = (u_int32_t *)iph + iph->ihl;

	if (len < sizeof(struct iphdr) || len <= (u_int32_t)(iph->ihl * 4))
		return ULOGD_IRET_OK;
	len -= iph->ihl * 4;

	okey_set_u32(&ret[KEY_IP_SADDR], iph->saddr);
	okey_set_u32(&ret[KEY_IP_DADDR], iph->daddr);
	okey_set_u8(&ret[KEY_IP_PROTOCOL], iph->protocol);
	okey_set_u8(&ret[KEY_IP_TOS], iph->tos);
	okey_set_u8(&ret[KEY_IP_TTL], iph->ttl);
	okey_set_u16(&ret[KEY_IP_TOTLEN], ntohs(iph->tot_len));
	okey_set_u8(&ret[KEY_IP_IHL], iph->ihl);
	okey_set_u16(&ret[KEY_IP_CSUM], ntohs(iph->check));
	okey_set_u16(&ret[KEY_IP_ID], ntohs(iph->id));
	okey_set_u16(&ret[KEY_IP_FRAGOFF], ntohs(iph->frag_off));

	switch (iph->protocol) {
	case IPPROTO_TCP:
		_interp_tcp(pi, nexthdr, len);
		break;
	case IPPROTO_UDP:
		_interp_udp(pi, nexthdr, len);
		break;
	case IPPROTO_ICMP:
		_interp_icmp(pi, nexthdr, len);
		break;
	case IPPROTO_SCTP:
		_interp_sctp(pi, nexthdr, len);
		break;
	case IPPROTO_AH:
	case IPPROTO_ESP:
		_interp_ahesp(pi, nexthdr, len);
		break;
	}

	return ULOGD_IRET_OK;
}

/***********************************************************************
 * 			IPv6 HEADER
 ***********************************************************************/

static int ip6_ext_hdr(u_int8_t nexthdr)
{
	switch (nexthdr) {
	case IPPROTO_HOPOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_FRAGMENT:
	case IPPROTO_ESP:
	case IPPROTO_AH:
	case IPPROTO_DSTOPTS:
		return 1;
	default:
		return 0;
	}
}

static int _interp_ipv6hdr(struct ulogd_pluginstance *pi, u_int32_t len)
{
	struct ulogd_key *ret = pi->output.keys;
	struct ip6_hdr *ipv6h = ikey_get_ptr(&pi->input.keys[INKEY_RAW_PCKT]);
	unsigned int ptr, hdrlen = 0;
	u_int8_t curhdr;
	int fragment = 0;

	if (len < sizeof(struct ip6_hdr))
		return ULOGD_IRET_OK;

	okey_set_u128(&ret[KEY_IP_SADDR], &ipv6h->ip6_src);
	okey_set_u128(&ret[KEY_IP_DADDR], &ipv6h->ip6_dst);
	okey_set_u16(&ret[KEY_IP6_PAYLOAD_LEN], ntohs(ipv6h->ip6_plen));
	okey_set_u8(&ret[KEY_IP6_PRIORITY],
		    (ntohl(ipv6h->ip6_flow) & 0x0ff00000) >> 20);
	okey_set_u32(&ret[KEY_IP6_FLOWLABEL],
		     ntohl(ipv6h->ip6_flow) & 0x000fffff);
	okey_set_u8(&ret[KEY_IP6_HOPLIMIT], ipv6h->ip6_hlim);

	curhdr = ipv6h->ip6_nxt;
	ptr = sizeof(struct ip6_hdr);
	len -= sizeof(struct ip6_hdr);

	while (curhdr != IPPROTO_NONE && ip6_ext_hdr(curhdr)) {
		struct ip6_ext *ext = (void *)ipv6h + ptr;

		if (len < sizeof(struct ip6_ext))
			return ULOGD_IRET_OK;

		switch (curhdr) {
		case IPPROTO_FRAGMENT: {
			struct ip6_frag *fh = (struct ip6_frag *)ext;

			hdrlen = sizeof(struct ip6_frag);
			if (len < hdrlen)
				return ULOGD_IRET_OK;
			len -= hdrlen;

			okey_set_u16(&ret[KEY_IP6_FRAG_OFF],
				     ntohs(fh->ip6f_offlg & IP6F_OFF_MASK));
			okey_set_u32(&ret[KEY_IP6_FRAG_ID],
				     ntohl(fh->ip6f_ident));

			if (ntohs(fh->ip6f_offlg & IP6F_OFF_MASK))
				fragment = 1;
			break;
		}
		case IPPROTO_DSTOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_HOPOPTS:
			if (fragment)
				goto out;

			hdrlen = (ext->ip6e_len + 1) << 3;
			if (len < hdrlen)
				return ULOGD_IRET_OK;
			len -= hdrlen;
			break;
		case IPPROTO_AH:
			if (fragment)
				goto out;

			hdrlen = (ext->ip6e_len + 2) << 2;
			if (len < hdrlen)
				return ULOGD_IRET_OK;
			len -= hdrlen;

			_interp_ahesp(pi, (void *)ext, len);
			break;
		case IPPROTO_ESP:
			if (fragment)
				goto out;

			hdrlen = (ext->ip6e_len + 2) << 2;
			if (len < hdrlen)
				return ULOGD_IRET_OK;
			len -= hdrlen;

			_interp_ahesp(pi, (void *)ext, len);
			goto out;
		default:
			return ULOGD_IRET_OK;
		}

		curhdr = ext->ip6e_nxt;
		ptr += hdrlen;
	}

	if (fragment)
		goto out;


	okey_set_u8(&ret[KEY_IP_PROTOCOL], curhdr);

	switch (curhdr) {
	case IPPROTO_TCP:
		_interp_tcp(pi, (void *)ipv6h + ptr, len);
		break;
	case IPPROTO_UDP:
		_interp_udp(pi, (void *)ipv6h + ptr, len);
		break;
	case IPPROTO_ICMPV6:
		_interp_icmpv6(pi, (void *)ipv6h + ptr, len);
		break;
	}

out:
	okey_set_u8(&ret[KEY_IP6_NEXTHDR], curhdr);
	return ULOGD_IRET_OK;
}

/***********************************************************************
 * 			ARP HEADER
 ***********************************************************************/
static int _interp_arp(struct ulogd_pluginstance *pi, u_int32_t len)
{
	struct ulogd_key *ret = pi->output.keys;
	const struct ether_arp *arph =
		ikey_get_ptr(&pi->input.keys[INKEY_RAW_PCKT]);

	if (len < sizeof(struct ether_arp))
		return ULOGD_IRET_OK;

	okey_set_u16(&ret[KEY_ARP_HTYPE], ntohs(arph->arp_hrd));
	okey_set_u16(&ret[KEY_ARP_PTYPE], ntohs(arph->arp_pro));
	okey_set_u16(&ret[KEY_ARP_OPCODE], ntohs(arph->arp_op));

	okey_set_ptr(&ret[KEY_ARP_SHA], (void *)&arph->arp_sha);
	okey_set_ptr(&ret[KEY_ARP_SPA], (void *)&arph->arp_spa),
	okey_set_ptr(&ret[KEY_ARP_THA], (void *)&arph->arp_tha);
	okey_set_ptr(&ret[KEY_ARP_TPA], (void *)&arph->arp_tpa);

	return ULOGD_IRET_OK;
}

/***********************************************************************
 * 			ETHER HEADER
 ***********************************************************************/

static int _interp_bridge(struct ulogd_pluginstance *pi, u_int32_t len)
{
	const u_int16_t proto =
		ikey_get_u16(&pi->input.keys[INKEY_OOB_PROTOCOL]);

	switch (proto) {
	case ETH_P_IP:
		_interp_iphdr(pi, len);
		break;
	case ETH_P_IPV6:
		_interp_ipv6hdr(pi, len);
		break;
	case ETH_P_ARP:
		_interp_arp(pi, len);
		break;
	/* ETH_P_8021Q ?? others? */
	};

	return ULOGD_IRET_OK;
}


static int _interp_pkt(struct ulogd_pluginstance *pi)
{
	u_int32_t len = ikey_get_u32(&pi->input.keys[INKEY_RAW_PCKTLEN]);
	u_int8_t family = ikey_get_u8(&pi->input.keys[INKEY_OOB_FAMILY]);
	struct ulogd_key *ret = pi->output.keys;

	okey_set_u16(&ret[KEY_OOB_PROTOCOL],
		     ikey_get_u16(&pi->input.keys[INKEY_OOB_PROTOCOL]));

	switch (family) {
	case AF_INET:
		return _interp_iphdr(pi, len);
	case AF_INET6:
		return _interp_ipv6hdr(pi, len);
	case AF_BRIDGE:
		return _interp_bridge(pi, len);
	}
	return ULOGD_IRET_OK;
}

static struct ulogd_key base_inp[] = {
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
		.type = ULOGD_RET_UINT8,
		.name = "oob.family",
	},
	{
		.type = ULOGD_RET_UINT16,
		.name = "oob.protocol",
	},

};

static struct ulogd_plugin base_plugin = {
	.name = "BASE",
	.input = {
		.keys = base_inp,
		.num_keys = ARRAY_SIZE(base_inp),
		.type = ULOGD_DTYPE_RAW,
		},
	.output = {
		.keys = iphdr_rets,
		.num_keys = ARRAY_SIZE(iphdr_rets),
		.type = ULOGD_DTYPE_PACKET,
		},
	.interp = &_interp_pkt,
	.version = VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&base_plugin);
}
