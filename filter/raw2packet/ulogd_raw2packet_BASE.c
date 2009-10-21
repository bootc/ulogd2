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
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

#define NEXTHDR_TCP		IPPROTO_TCP
#define NEXTHDR_UDP		IPPROTO_UDP
#define NEXTHDR_ICMP	IPPROTO_ICMP
#define NEXTHDR_ICMP6	IPPROTO_ICMPV6
#define NEXTHDR_NONE	59

enum {
	I_RawPkt = 0,
	I_OobFamily,
};

static struct ulogd_key in_keys[] = {
	[I_RawPkt] = KEY(RAW, "raw.pkt"),
	[I_OobFamily] = KEY(UINT8, "oob.family"),
};

enum {
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
	O_Ip6SAddr,
	O_Ip6DAddr,
	O_Ip6Len,					/* payload len */
	O_Ip6Hlim,
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
	O_Icmp6Type,
	O_Icmp6Code,
};

static struct ulogd_key out_keys[] = {
	[O_IpSAddr] = KEY_IPFIX(IPADDR, "ip.saddr", IETF, sourceIPv4Address),
	[O_IpDAddr] = KEY_IPFIX(IPADDR, "ip.daddr", IETF, destinationIPv4Address),
	[O_IpProto] = KEY_IPFIX(UINT8, "ip.protocol", IETF, protocolIdentifier),
	[O_IpTos] = KEY_IPFIX(UINT8, "ip.tos", IETF, classOfServiceIPv4),
	[O_IpTtl] = KEY_IPFIX(UINT8, "ip.ttl", IETF, ipTimeToLive),
	[O_IpTotLen] = KEY_IPFIX(UINT16, "ip.totlen", IETF, totalLengthIPv4),
	[O_IpIhl] = KEY_IPFIX(UINT8, "ip.ihl", IETF, internetHeaderLengthIPv4),
	[O_IpCsum] = KEY(UINT16, "ip.csum"),
	[O_IpId] = KEY_IPFIX(UINT16, "ip.id", IETF, identificationIPv4),
	[O_IpFragOff] = KEY_IPFIX(UINT16, "ip.fragoff", IETF, fragmentOffsetIPv4),
	[O_Ip6SAddr] = KEY(IP6ADDR, "ip6.saddr"),
	[O_Ip6DAddr] = KEY(IP6ADDR, "ip6.daddr"),
	[O_Ip6Len] = KEY(UINT16, "ip6.len"),
	[O_Ip6Hlim] = KEY(UINT8, "ip6.hlim"),
	[O_TcpSPort] = KEY_IPFIX(UINT16, "tcp.sport", IETF, tcpSourcePort),
	[O_TcpDPort] = KEY_IPFIX(UINT16, "tcp.dport", IETF, tcpDestinationPort),
	[O_TcpSeq] = KEY_IPFIX(UINT32, "tcp.seq", IETF, tcpSequenceNumber),
	[O_TcpAckSeq] = KEY_IPFIX(UINT32, "tcp.ackseq", IETF,
							  tcpAcknowledgementNumber),
	[O_TcpOff] = KEY(UINT8, "tcp.offset"),
	[O_TcpReserved] = KEY(UINT8, "tcp.reserved"),
	[O_TcpWin] = KEY_IPFIX(UINT16, "tcp.window", IETF, tcpWindowSize),
	[O_TcpUrg] = KEY(BOOL, "tcp.urg"),
	[O_TcpUrgp] = KEY_IPFIX(UINT16, "tcp.urgp", IETF, tcpUrgentPointer),
	[O_TcpAck] = KEY(BOOL, "tcp.ack"),
	[O_TcpPsh] = KEY(BOOL, "tcp.psh"),
	[O_TcpRst] = KEY(BOOL, "tcp.rst"),
	[O_TcpSyn] = KEY(BOOL, "tcp.syn"),
	[O_TcpFin] = KEY(BOOL, "tcp.fin"),
	[O_TcpRes1] = KEY(BOOL, "tcp.res1"),
	[O_TcpRes2] = KEY(BOOL,  "tcp.res2"),
	[O_TcpCsum] = KEY(UINT16, "tcp.csum"),
	[O_UdpSPort] = KEY_IPFIX(UINT16, "udp.sport", IETF, udpSourcePort),
	[O_UdpDPort] = KEY_IPFIX(UINT16, "udp.dport", IETF, udpDestinationPort),
	[O_UdpLen] = KEY(UINT16, "udp.len"),
	[O_UdpCsum] = KEY(UINT16, "udp.csum"),
	[O_IcmpType] = KEY_IPFIX(UINT8, "icmp.type", IETF, icmpTypeIPv4),
	[O_IcmpCode] = KEY_IPFIX(UINT8, "icmp.code", IETF, icmpCodeIPv4),
	[O_IcmpEchoId] = KEY(UINT16, "icmp.echoid"),
	[O_IcmpEchoSeq] = KEY(UINT16, "icmp.echoseq"),
	[O_IcmpGw] = KEY(IPADDR, "icmp.gateway"),
	[O_IcmpFragMtu] = KEY(UINT16, "icmp.fragmtu"),
	[O_IcmpCsum] = KEY(UINT16, "icmp.csum"),
	[O_AhEspSpi] = KEY(UINT32, "ahesp.spi"),
	[O_Icmp6Type] = KEY(UINT8, "icmp6.type"),
	[O_Icmp6Code] = KEY(UINT8, "icmp6.code"),
};


static int
tcp_interp(const struct ulogd_pluginstance *pi, const void *data)
{
	struct ulogd_key *ret = pi->output.keys;
	const struct tcphdr *tcph = data;

	key_set_u16(&ret[O_TcpSPort], ntohs(tcph->source));
	key_set_u16(&ret[O_TcpDPort], ntohs(tcph->dest));
	key_set_u32(&ret[O_TcpSeq], ntohl(tcph->seq));
	key_set_u32(&ret[O_TcpAckSeq], ntohl(tcph->ack_seq));
	key_set_u8(&ret[O_TcpOff], ntohs(tcph->doff));
	key_set_u8(&ret[O_TcpReserved], ntohs(tcph->res1));
	key_set_u16(&ret[O_TcpWin], ntohs(tcph->window));

	key_set_bool(&ret[O_TcpUrg], tcph->urg);
	if (tcph->urg)
		key_set_u16(&ret[O_TcpUrgp], ntohs(tcph->urg_ptr));
	key_set_bool(&ret[O_TcpAck], tcph->ack);
	key_set_bool(&ret[O_TcpPsh], tcph->psh);
	key_set_bool(&ret[O_TcpRst], tcph->rst);
	key_set_bool(&ret[O_TcpSyn], tcph->syn);
	key_set_bool(&ret[O_TcpFin], tcph->fin);
	key_set_bool(&ret[O_TcpRes1], tcph->res1);
	key_set_bool(&ret[O_TcpRes2], tcph->res2);
	key_set_u16(&ret[O_TcpCsum], ntohs(tcph->check));
	
	return 0;
}

/***********************************************************************
 * 			UDP HEADER
 ***********************************************************************/
static int
udp_interp(const struct ulogd_pluginstance *pi, const void *data)
{
	struct ulogd_key *ret = pi->output.keys;
	const struct udphdr *udph = data;

	key_set_u16(&ret[O_UdpSPort], ntohs(udph->source));
	key_set_u16(&ret[O_UdpDPort], ntohs(udph->dest));
	key_set_u16(&ret[O_UdpLen], ntohs(udph->len));
	key_set_u16(&ret[O_UdpCsum], ntohs(udph->check));
	
	return 0;
}

static int
icmp_interp(const struct ulogd_pluginstance *pi, const void *data)
{
	struct ulogd_key *ret = pi->output.keys;
	const struct icmphdr *icmph = data;

	key_set_u8(&ret[O_IcmpType], icmph->type);
	key_set_u8(&ret[O_IcmpCode], icmph->code);

	switch (icmph->type) {
	case ICMP_ECHO:
	case ICMP_ECHOREPLY:
		key_set_u16(&ret[O_IcmpEchoId], ntohs(icmph->un.echo.id));
		key_set_u16(&ret[O_IcmpEchoSeq], ntohs(icmph->un.echo.sequence));
		break;

	case ICMP_REDIRECT:
	case ICMP_PARAMETERPROB:
		key_set_u32(&ret[O_IcmpGw], ntohl(icmph->un.gateway));
		break;

	case ICMP_DEST_UNREACH:
		if (icmph->code == ICMP_FRAG_NEEDED)
			key_set_u16(&ret[O_IcmpFragMtu], ntohs(icmph->un.frag.mtu));
		break;
	}

	key_set_u16(&ret[O_IcmpCsum], icmph->checksum);

	return 0;
}

static int
icmp6_interp(const struct ulogd_pluginstance *pi, const void *data)
{
	struct ulogd_key *out = pi->output.keys;
	const struct icmp6_hdr *icmp6h = data;

	key_set_u8(&out[O_Icmp6Type], icmp6h->icmp6_type);
	key_set_u8(&out[O_Icmp6Code], icmp6h->icmp6_code);

	return 0;
}

static int
ahesp_interp(const struct ulogd_pluginstance *pi, const void *data)
{
#if 0
	struct ulogd_key *out = &pi->output.keys;
	struct esphdr *esph = data;

	key_set_u32(keys[O_AhEspSpi], ntohl(esph->spi));
#endif

	return 0;
}

static int
l4_interp(struct ulogd_pluginstance *pi, int proto, const void *data)
{
	int ret;

	if (!data)
		return -1;

	switch (proto) {
	case IPPROTO_TCP:
		ret = tcp_interp(pi, data);
		break;

	case IPPROTO_UDP:
		ret = udp_interp(pi, data);
			return -1;
		break;

	case IPPROTO_ICMP:
		ret = icmp_interp(pi, data);
		break;

	case IPPROTO_ICMPV6:
		ret = icmp6_interp(pi, data);
		break;

	case IPPROTO_AH:
	case IPPROTO_ESP:
		ret = ahesp_interp(pi, data);
		break;

	default:
		break;
	}

	return ret;
}

static int
ip_interp(struct ulogd_pluginstance *pi)
{
	const struct ulogd_key *in = pi->input.keys;
	struct ulogd_key *out = pi->output.keys;
	const struct iphdr *iph = key_src_ptr(&in[I_RawPkt]);

	key_set_in(&out[O_IpSAddr], (const struct in_addr *)&iph->saddr);
	key_set_in(&out[O_IpDAddr], (const struct in_addr *)&iph->daddr);
	key_set_u8(&out[O_IpProto], iph->protocol);
	key_set_u8(&out[O_IpTos], iph->tos);
	key_set_u8(&out[O_IpTtl], iph->ttl);
	key_set_u16(&out[O_IpTotLen], ntohs(iph->tot_len));
	key_set_u8(&out[O_IpIhl], iph->ihl);
	key_set_u16(&out[O_IpCsum], ntohs(iph->check));
	key_set_u16(&out[O_IpId], ntohs(iph->id));
	key_set_u16(&out[O_IpFragOff], ntohs(iph->frag_off));

	return l4_interp(pi, iph->protocol, (void *)iph + iph->ihl * 4);
}

static int
ip6_interp(struct ulogd_pluginstance *pi)
{
	const struct ulogd_key *in = pi->input.keys;
	struct ulogd_key *out = pi->output.keys;
	const struct ip6_hdr *ip6h = key_src_ptr(&in[I_RawPkt]);
	const uint8_t *data = (uint8_t *)ip6h + sizeof(*ip6h);
	uint8_t nexthdr;

	key_set_in6(&out[O_Ip6SAddr], &ip6h->ip6_src);
	key_set_in6(&out[O_Ip6DAddr], &ip6h->ip6_dst);
	key_set_u16(&out[O_Ip6Len], ntohs(ip6h->ip6_plen));
	key_set_u8(&out[O_Ip6Hlim], ip6h->ip6_hlim);

	/* skip extension headers */
	nexthdr = ip6h->ip6_nxt;
	do {
		if (nexthdr == NEXTHDR_NONE)
			break;
		if (nexthdr == NEXTHDR_TCP || nexthdr == NEXTHDR_UDP
			|| nexthdr == NEXTHDR_ICMP6) {
			key_set_u8(&out[O_IpProto], nexthdr);
			return l4_interp(pi, nexthdr, data);
		}

		nexthdr = data[0];
		data += (data[1] + 1) << 3;
	} while (1);

	return 0;
}

static int
base_interp(struct ulogd_pluginstance *pi, unsigned *flags)
{
	const struct ulogd_key *in = pi->input.keys;

	if (key_src_u8(&in[I_OobFamily]) == AF_INET) {
		if (ip_interp(pi) < 0)
			return ULOGD_IRET_ERR;
	} else if (key_src_u8(&in[I_OobFamily]) == AF_INET6) {
		if (ip6_interp(pi) < 0)
			return ULOGD_IRET_ERR;
	}

	return 0;
}

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
	.interp = base_interp,
	.rev = ULOGD_PLUGIN_REVISION,
};

void __upi_ctor init(void);

void
init(void)
{
	ulogd_register_plugin(&base_plugin);
}
