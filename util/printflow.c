/* printflow.c
 *
 * build something looking like an iptables LOG message, but for flows
 *
 * (C) 2006 by Philip Craig <philipc@snapgear.com>
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

#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <ulogd/ulogd.h>
#include <ulogd/printflow.h>

enum printflow_fields {
	PRINTFLOW_ORIG_IP_SADDR = 0,
	PRINTFLOW_ORIG_IP_DADDR,
	PRINTFLOW_ORIG_IP_PROTOCOL,
	PRINTFLOW_ORIG_L4_SPORT,
	PRINTFLOW_ORIG_L4_DPORT,
	PRINTFLOW_ORIG_RAW_PKTLEN,
	PRINTFLOW_ORIG_RAW_PKTCOUNT,
	PRINTFLOW_REPLY_IP_SADDR,
	PRINTFLOW_REPLY_IP_DADDR,
	PRINTFLOW_REPLY_IP_PROTOCOL,
	PRINTFLOW_REPLY_L4_SPORT,
	PRINTFLOW_REPLY_L4_DPORT,
	PRINTFLOW_REPLY_RAW_PKTLEN,
	PRINTFLOW_REPLY_RAW_PKTCOUNT,
	PRINTFLOW_ICMP_CODE,
	PRINTFLOW_ICMP_TYPE,
	PRINTFLOW_EVENT_TYPE,
};

struct ulogd_key printflow_keys[FLOW_IDS] = {
	{
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE,
		.name = "orig.ip.saddr.str",
	},
	{
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE,
		.name = "orig.ip.daddr.str",
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "orig.ip.protocol",
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "orig.l4.sport",
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "orig.l4.dport",
	},
	{
		.type = ULOGD_RET_UINT64,
		.flags = ULOGD_RETF_NONE,
		.name = "orig.raw.pktlen",
	},
	{
		.type = ULOGD_RET_UINT64,
		.flags = ULOGD_RETF_NONE,
		.name = "orig.raw.pktcount",
	},
	{
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE,
		.name = "reply.ip.saddr.str",
	},
	{
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE,
		.name = "reply.ip.daddr.str",
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "reply.ip.protocol",
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "reply.l4.sport",
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "reply.l4.dport",
	},
	{
		.type = ULOGD_RET_UINT64,
		.flags = ULOGD_RETF_NONE,
		.name = "reply.raw.pktlen",
	},
	{
		.type = ULOGD_RET_UINT64,
		.flags = ULOGD_RETF_NONE,
		.name = "reply.raw.pktcount",
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.code",
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.type",
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "ct.event",
	},
};
int printflow_keys_num = sizeof(printflow_keys)/sizeof(*printflow_keys);

#define pp_pri(type) PRI##type
#define pp_print_u(buf_cur, label, res, x, type) \
	if (pp_is_valid(res, x)) \
		buf_cur += sprintf(buf_cur, label"=%" pp_pri(type) " ", ikey_get_##type(&res[x]));

int printflow_print(struct ulogd_key *res, char *buf)
{
	char *buf_cur = buf;

	if (pp_is_valid(res, PRINTFLOW_EVENT_TYPE)) {
		switch (ikey_get_u32(&res[PRINTFLOW_EVENT_TYPE])) {
			case 1:
				buf_cur += sprintf(buf_cur, "[NEW] ");
				break;
			case 2:
				buf_cur += sprintf(buf_cur, "[UPDATE] ");
				break;
			case 4:
				buf_cur += sprintf(buf_cur, "[DESTROY] ");
				break;
		}
	}

	buf_cur += sprintf(buf_cur, "ORIG: ");

	if (pp_is_valid(res, PRINTFLOW_ORIG_IP_SADDR))
		buf_cur += sprintf(buf_cur,
				   "SRC=%s ", 
				   (char *) ikey_get_ptr(&res[PRINTFLOW_ORIG_IP_SADDR]));

	if (pp_is_valid(res, PRINTFLOW_ORIG_IP_DADDR))
		buf_cur += sprintf(buf_cur,
				   "DST=%s ",
				   (char *) ikey_get_ptr(&res[PRINTFLOW_ORIG_IP_DADDR]));

	if (!pp_is_valid(res, PRINTFLOW_ORIG_IP_PROTOCOL))
		goto orig_out;

	switch (ikey_get_u8(&res[PRINTFLOW_ORIG_IP_PROTOCOL])) {
	case IPPROTO_TCP:
		buf_cur += sprintf(buf_cur, "PROTO=TCP ");
		pp_print_u(buf_cur, "SPT", res, PRINTFLOW_ORIG_L4_SPORT, u16);
		pp_print_u(buf_cur, "DPT", res, PRINTFLOW_ORIG_L4_DPORT, u16);
		break;

	case IPPROTO_UDP:
		buf_cur += sprintf(buf_cur, "PROTO=UDP ");
		pp_print_u(buf_cur, "SPT", res, PRINTFLOW_ORIG_L4_SPORT, u16);
		pp_print_u(buf_cur, "DPT", res, PRINTFLOW_ORIG_L4_DPORT, u16);
		break;

	case IPPROTO_ICMP:
		buf_cur += sprintf(buf_cur, "PROTO=ICMP ");
		pp_print_u(buf_cur, "TYPE", res, PRINTFLOW_ICMP_CODE, u8);
		pp_print_u(buf_cur, "CODE", res, PRINTFLOW_ICMP_TYPE, u8);
		break;

	case IPPROTO_ESP:
		buf_cur += sprintf(buf_cur, "PROTO=ESP ");
		break;

	case IPPROTO_AH:
		buf_cur += sprintf(buf_cur, "PROTO=AH ");
		break;

	default:
		pp_print_u(buf_cur, "PROTO", res, PRINTFLOW_ORIG_IP_PROTOCOL, u8);
		break;
	}

orig_out:
	pp_print_u(buf_cur, "PKTS", res, PRINTFLOW_ORIG_RAW_PKTCOUNT, u64);
	pp_print_u(buf_cur, "BYTES", res, PRINTFLOW_ORIG_RAW_PKTLEN, u64);

	buf_cur += sprintf(buf_cur, ", REPLY: ");

	if (pp_is_valid(res, PRINTFLOW_REPLY_IP_SADDR))
		buf_cur += sprintf(buf_cur,
				   "SRC=%s ",
				   (char *) ikey_get_ptr(&res[PRINTFLOW_REPLY_IP_SADDR]));

	if (pp_is_valid(res, PRINTFLOW_REPLY_IP_DADDR))
		buf_cur += sprintf(buf_cur,
				   "DST=%s ",
				   (char *) ikey_get_ptr(&res[PRINTFLOW_REPLY_IP_DADDR]));

	if (!pp_is_valid(res, PRINTFLOW_REPLY_IP_PROTOCOL))
		goto reply_out;

	switch (ikey_get_u8(&res[PRINTFLOW_REPLY_IP_PROTOCOL])) {
	case IPPROTO_TCP:
		buf_cur += sprintf(buf_cur, "PROTO=TCP ");
		pp_print_u(buf_cur, "SPT", res, PRINTFLOW_REPLY_L4_SPORT, u16);
		pp_print_u(buf_cur, "DPT", res, PRINTFLOW_REPLY_L4_DPORT, u16);
		break;

	case IPPROTO_UDP:
		buf_cur += sprintf(buf_cur, "PROTO=UDP ");
		pp_print_u(buf_cur, "SPT", res, PRINTFLOW_REPLY_L4_SPORT, u16);
		pp_print_u(buf_cur, "DPT", res, PRINTFLOW_REPLY_L4_DPORT, u16);
		break;

	case IPPROTO_ICMP:
		buf_cur += sprintf(buf_cur, "PROTO=ICMP ");
		pp_print_u(buf_cur, "TYPE", res, PRINTFLOW_ICMP_CODE, u8);
		pp_print_u(buf_cur, "CODE", res, PRINTFLOW_ICMP_TYPE, u8);
		break;

	case IPPROTO_ESP:
		buf_cur += sprintf(buf_cur, "PROTO=ESP ");
		break;

	case IPPROTO_AH:
		buf_cur += sprintf(buf_cur, "PROTO=AH ");
		break;

	default:
		pp_print_u(buf_cur, "PROTO", res, PRINTFLOW_REPLY_IP_PROTOCOL, u8);
		break;
	}

reply_out:
	pp_print_u(buf_cur, "PKTS", res, PRINTFLOW_REPLY_RAW_PKTCOUNT, u64);
	pp_print_u(buf_cur, "BYTES", res, PRINTFLOW_REPLY_RAW_PKTLEN, u64);

	strcat(buf_cur, "\n");
	return 0;
}
