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
 * $Id: printflow.c,v 1.1 2006/05/16 01:57:31 philipc Exp $
 *
 */
#include "config.h"
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/plugin.h>
#include <ulogd/printflow.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

struct ulogd_key printflow_keys[] = {
	KEY(IPADDR, "ip.saddr"),
	KEY(IPADDR, "ip.daddr"),
	KEY(UINT8, "ip.protocol"),
	KEY(UINT16, "l4.sport"),
	KEY(UINT16, "l4.dport"),
	KEY(UINT32, "raw.pktlen"),
	KEY(UINT32, "raw.pktcount"),
	KEY(UINT8, "icmp.code"),
	KEY(UINT8,  "icmp.type"),
	KEY(BOOL, "dir"),
};
int printflow_keys_num = sizeof(printflow_keys)/sizeof(*printflow_keys);

#define GET_VALUE(res, x)	(res[x].source->val)
#define GET_FLAGS(res, x)	(res[x].source->flags)
#define pp_is_valid(res, x)	(GET_FLAGS(res, x) & ULOGD_RETF_VALID)

#define pp_print(buf_cur, label, res, x, type) \
	if (pp_is_valid(res, x)) \
		buf_cur += sprintf(buf_cur, label"=%u ", GET_VALUE(res, x).type);

int printflow_print(struct ulogd_key *res, char *buf)
{
	char *buf_cur = buf;

	if (pp_is_valid(res, 9))
		buf_cur += sprintf(buf_cur, "DIR=%s ",
				GET_VALUE(res, 9).b ? "REPLY" : "ORIG ");

	if (pp_is_valid(res, 0))
		buf_cur += sprintf(buf_cur, "SRC=%s ", inet_ntoa(
				(struct in_addr) {htonl(GET_VALUE(res, 0).ui32)}));

	if (pp_is_valid(res, 1))
		buf_cur += sprintf(buf_cur, "DST=%s ", inet_ntoa(
				(struct in_addr) {htonl(GET_VALUE(res, 1).ui32)}));

	if (!pp_is_valid(res, 2))
		goto out;

	switch (GET_VALUE(res, 2).ui8) {
	case IPPROTO_TCP:
		buf_cur += sprintf(buf_cur, "PROTO=TCP ");
		pp_print(buf_cur, "SPT", res, 3, ui16);
		pp_print(buf_cur, "DPT", res, 4, ui16);
		break;

	case IPPROTO_UDP:
		buf_cur += sprintf(buf_cur, "PROTO=UDP ");
		pp_print(buf_cur, "SPT", res, 3, ui16);
		pp_print(buf_cur, "DPT", res, 4, ui16);
		break;

	case IPPROTO_ICMP:
		buf_cur += sprintf(buf_cur, "PROTO=ICMP ");
		pp_print(buf_cur, "TYPE", res, 7, ui8);
		pp_print(buf_cur, "CODE", res, 8, ui8);
		break;

	case IPPROTO_ESP:
		buf_cur += sprintf(buf_cur, "PROTO=ESP ");
		break;

	case IPPROTO_AH:
		buf_cur += sprintf(buf_cur, "PROTO=AH ");
		break;

	default:
		pp_print(buf_cur, "PROTO", res, 2, ui8);
		break;
	}

out:
	pp_print(buf_cur, "PKTS", res, 6, ui32);
	pp_print(buf_cur, "BYTES", res, 5, ui32);
	strcat(buf_cur, "\n");

	return 0;
}
