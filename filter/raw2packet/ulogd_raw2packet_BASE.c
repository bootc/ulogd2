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


/***********************************************************************
 * 			IP HEADER
 ***********************************************************************/

static struct ulogd_key iphdr_rets[] = {
	{ 
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE, 
		.name = "ip.saddr", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_sourceIPv4Address,
		},
	},
	{
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.daddr", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_destinationIPv4Address,
		},
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.protocol", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_protocolIdentifier,
		},
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.tos", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_classOfServiceIPv4,
		},
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.ttl", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_ipTimeToLive,
		},
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.totlen", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_totalLengthIPv4,
		},
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.ihl", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_internetHeaderLengthIPv4,
		},
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.csum", 
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.id", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_identificationIPv4,
		},
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.fragoff", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_fragmentOffsetIPv4,
		},
	},

	/* 10 */

	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.sport", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpSourcePort,
		},
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.dport", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpDestinationPort,
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.seq", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpSequenceNumber,
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.ackseq", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpAcknowledgementNumber,
		},
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE, 
		.name = "tcp.offset",
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.reserved",
	}, 
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.window",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpWindowSize,
		},
	},
	{
		.type = ULOGD_RET_BOOL, 
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.urg", 
	},
	{
		.type = ULOGD_RET_UINT16, 
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.urgp",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpUrgentPointer,
		},
	},
	{
		.type = ULOGD_RET_BOOL, 
		.flags = ULOGD_RETF_NONE, 
		.name = "tcp.ack", 
	},
	{
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.psh",
	},
	{
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.rst",
	},
	{
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.syn",
	},
	{
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.fin",
	},
	{
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.res1",
	},
	{
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.res2",
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.csum",
	},

	/* 27 */

	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "udp.sport", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF, 
			.field_id = IPFIX_udpSourcePort,
		},
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "udp.dport", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_udpDestinationPort,
		},
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "udp.len", 
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "udp.csum",
	},

	/* 31 */


	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.type", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_icmpTypeIPv4,
		},
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.code", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_icmpCodeIPv4,
		},
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.echoid", 
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.echoseq",
	},
	{
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.gateway", 
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.fragmtu", 
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.csum",
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "ahesp.spi",
	},

	/* 39 */

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
	struct ulogd_key *ret = &pi->output.keys[10];
	const struct tcphdr *tcph = ipv4_data(iph);

	assert(iph->protocol == IPPROTO_TCP);

	key_u16(&ret[0], ntohs(tcph->source));
	key_u16(&ret[1], ntohs(tcph->dest));
	key_u32(&ret[2], ntohl(tcph->seq));
	key_u32(&ret[3], ntohl(tcph->ack_seq));
	key_u8(&ret[4], ntohs(tcph->doff));
	key_u8(&ret[5], ntohs(tcph->res1));
	key_u16(&ret[6],ntohs(tcph->window));

	key_bool(&ret[7], tcph->urg);
	if (tcph->urg)
		key_u16(&ret[8], ntohs(tcph->urg_ptr));
	key_bool(&ret[9], tcph->ack);
	key_bool(&ret[10],  tcph->psh);
	key_bool(&ret[11], tcph->rst);
	key_bool(&ret[12], tcph->syn);
	key_bool(&ret[13], tcph->fin);
	key_bool(&ret[14], tcph->res1);
	key_bool(&ret[15], tcph->res2);
	key_bool(&ret[16], ntohs(tcph->check));
	
	return 0;
}

/***********************************************************************
 * 			UDP HEADER
 ***********************************************************************/

static int
_interp_udp(const struct ulogd_pluginstance *pi, const struct iphdr *iph)
{
	struct ulogd_key *ret = &pi->output.keys[27];
	const struct udphdr *udph = ipv4_data(iph);

	assert(iph->protocol == IPPROTO_UDP);

	key_u16(&ret[0], ntohs(udph->source));
	key_u16(&ret[1], ntohs(udph->dest));
	key_u16(&ret[2], ntohs(udph->len));
	key_u16(&ret[3], ntohs(udph->check));
	
	return 0;
}

/***********************************************************************
 * 			ICMP HEADER
 ***********************************************************************/

static int
_interp_icmp(const struct ulogd_pluginstance *pi, const struct iphdr *iph)
{
	struct ulogd_key *ret = &pi->output.keys[31];
	struct icmphdr *icmph = ipv4_data(iph);

	assert(iph->protocol == IPPROTO_ICMP);
	
	key_u8(&ret[0], icmph->type);
	key_u8(&ret[1], icmph->code);

	switch (icmph->type) {
	case ICMP_ECHO:
	case ICMP_ECHOREPLY:
		key_u16(&ret[2], ntohs(icmph->un.echo.id));
		key_u16(&ret[3], ntohs(icmph->un.echo.sequence));
		break;

	case ICMP_REDIRECT:
	case ICMP_PARAMETERPROB:
		key_u32(&ret[4], ntohl(icmph->un.gateway));
		break;

	case ICMP_DEST_UNREACH:
		if (icmph->code == ICMP_FRAG_NEEDED)
			key_u16(&ret[5], ntohs(icmph->un.frag.mtu));
		break;
	}

	key_u16(&ret[6], icmph->checksum);

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

static struct ulogd_key base_inp[] = {
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
		.keys = base_inp,
		.num_keys = ARRAY_SIZE(base_inp),
		.type = ULOGD_DTYPE_RAW,
		},
	.output = {
		.keys = iphdr_rets,
		.num_keys = ARRAY_SIZE(iphdr_rets),
		.type = ULOGD_DTYPE_PACKET,
		},
	.interp = &_interp_iphdr,
	.version = ULOGD_VERSION,
};

void __attribute__ ((constructor)) init(void);

void
init(void)
{
	ulogd_register_plugin(&base_plugin);
}
