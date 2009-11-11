/*
 * ulogd_output_IPFIX.c
 *
 * ulogd IPFIX Exporter plugin.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Holger Eitzenberger <holger@eitzenberger.org>  Astaro AG 2009
 */
#include "config.h"
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/plugin.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "ipfix.h"

#define DEFAULT_MTU			512 /* RFC 5101, 10.3.3 */
#define DEFAULT_PORT		4739 /* RFC 5101, 10.3.4 */
#define DEFAULT_SPORT		4740


enum {
	OID_CE = 0,
	HOST_CE,
	PORT_CE,
	PROTO_CE,
};

static const struct config_keyset ipfix_kset = {
	.num_ces = 4,
	.ces = {
		[OID_CE] = CONFIG_KEY_INT("oid", 0),
		[HOST_CE] = CONFIG_KEY_STR("host", ""),
		[PORT_CE] = CONFIG_KEY_INT("port", DEFAULT_PORT ),
		[PROTO_CE] = CONFIG_KEY_STR("proto", "tcp"),
	},
};

#define oid_ce(pi)		ulogd_config_int(pi, OID_CE)
#define host_ce(pi)		ulogd_config_str(pi, HOST_CE)
#define port_ce(pi)		ulogd_config_int(pi, PORT_CE)
#define proto_ce(pi)	ulogd_config_str(pi, PROTO_CE)


struct ipfix_templ {
	struct ipfix_templ *next;
};

struct ipfix_flow {
	struct llist_head link;
	struct ulogd_value value[];
};

struct ipfix_priv {
	struct ulogd_fd ufd;
	uint32_t seqno;
	struct vy_ipfix_hdr *hdr;
	char *end;
	int num_flows;
	struct ipfix_templ *templates;
	int proto;
	struct ulogd_timer timer;
	struct sockaddr_in sa;
};

enum {
	InIpSaddr = 0,
	InIpDaddr,
	/* InOobIfiIn, */
	/* InOobIfiOut, */
	InRawInPktCount,
	InRawInPktLen,
	InRawOutPktCount,
	InRawOutPktLen,
	InFlowStartSec,
	InFlowStartUsec,
	InFlowEndSec,
	InFlowEndUsec,
	InL4SPort,
	InL4DPort,
	InIpProto,
};

static struct ulogd_key ipfix_in_keys[] = {
	[InIpSaddr] = KEY(IPADDR, "ip.saddr"),
	[InIpDaddr] = KEY(IPADDR, "ip.daddr"),
	/* [InOobIfiIn] = KEY(UINT32, "oob.ifindex_in"), */
	/* [InOobIfiOut] = KEY(UINT32, "oob.ifindex_out"), */
	[InRawInPktCount] = KEY(UINT64, "raw.in.pktcount"),
	[InRawInPktLen] = KEY(UINT64, "raw.in.pktlen"),
	[InRawOutPktCount] = KEY(UINT64, "raw.out.pktcount"),
	[InRawOutPktLen] = KEY(UINT64, "raw.out.pktlen"),
	[InFlowStartSec] = KEY(UINT32, "flow.start.sec"),
	[InFlowStartUsec] = KEY(UINT32, "flow.start.usec"),
	[InFlowEndSec] = KEY(UINT32, "flow.end.sec"),
	[InFlowEndUsec] = KEY(UINT32, "flow.end.usec"),
	[InL4SPort] = KEY(UINT16, "l4.sport"),
	[InL4DPort] = KEY(UINT16, "l4.dport"),
	[InIpProto] = KEY(UINT8, "ip.protocol"),
};

static int
ipfix_ufd_cb(int fd, unsigned what, void *arg)
{
	struct ulogd_pluginstance *pi = arg;
	struct ipfix_priv *priv = upi_priv(pi);
	char buf[16];
	ssize_t nread;

	if (what & ULOGD_FD_READ) {
		nread = read(priv->ufd.fd, buf, sizeof(buf));
		if (nread < 0) {
			upi_log(pi, ULOGD_ERROR, "read: %m\n");

			/* FIXME plugin is not restarted */
			ulogd_upi_set_state(pi, PsConfigured);
		} else if (!nread) {
			upi_log(pi, ULOGD_INFO, "connection reset by peer\n");
			ulogd_unregister_fd(&priv->ufd);
		} else
			upi_log(pi, ULOGD_INFO, "unexpected data (%d bytes)\n", nread);
	}

	return 0;
}

static void
ipfix_timer_cb(struct ulogd_timer *t)
{
}

static int
ipfix_configure(struct ulogd_pluginstance *pi)
{
	struct ipfix_priv *priv = upi_priv(pi);
	int ret;

	if (!oid_ce(pi)) {
		upi_log(pi, ULOGD_FATAL, "invalid Observation ID\n");
		return ULOGD_IRET_ERR;
	}
	if (!host_ce(pi)) {
		upi_log(pi, ULOGD_FATAL, "no destination host specified\n");
		return ULOGD_IRET_ERR;
	}
	if (!strcmp(proto_ce(pi), "udp"))
		priv->proto = IPPROTO_UDP;
	else if (!strcmp(proto_ce(pi), "tcp"))
		priv->proto = IPPROTO_TCP;

	memset(&priv->sa, 0, sizeof(priv->sa));
	priv->sa.sin_family = AF_INET;
	priv->sa.sin_port = htons(port_ce(pi));
	ret = inet_pton(AF_INET, host_ce(pi), &priv->sa.sin_addr);
	if (ret < 0) {
		upi_log(pi, ULOGD_FATAL, "inet_pton: %m\n");
		return ULOGD_IRET_ERR;
	} else if (!ret) {
		upi_log(pi, ULOGD_FATAL, "host: invalid address\n");
		return ULOGD_IRET_ERR;
	}

	ulogd_init_fd(&priv->ufd, -1, ULOGD_FD_READ, ipfix_ufd_cb, pi);
	ulogd_init_timer(&priv->timer, 1 SEC, ipfix_timer_cb, pi,
					 TIMER_F_PERIODIC);

	return ULOGD_IRET_OK;
}

static int
tcp_connect(struct ulogd_pluginstance *pi)
{
	struct ipfix_priv *priv = upi_priv(pi);
	int ret = ULOGD_IRET_ERR;

	if ((priv->ufd.fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		upi_log(pi, ULOGD_FATAL, "socket: %m\n");
		return ULOGD_IRET_ERR;
	}

	if (connect(priv->ufd.fd, &priv->sa, sizeof(priv->sa)) < 0) {
		upi_log(pi, ULOGD_ERROR, "connect: %m\n");
		ret = ULOGD_IRET_AGAIN;
		goto err_close;
	}

	return ULOGD_IRET_OK;

err_close:
	close(priv->ufd.fd);
	return ret;
}

static int
udp_connect(struct ulogd_pluginstance *pi)
{
	struct ipfix_priv *priv = upi_priv(pi);

	if ((priv->ufd.fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		upi_log(pi, ULOGD_FATAL, "socket: %m\n");
		return ULOGD_IRET_ERR;
	}

	if (connect(priv->ufd.fd, &priv->sa, sizeof(priv->sa)) < 0) {
		upi_log(pi, ULOGD_ERROR, "connect: %m\n");
		return ULOGD_IRET_AGAIN;
	}

	return 0;
}

static int
ipfix_start(struct ulogd_pluginstance *pi)
{
	struct ipfix_priv *priv = upi_priv(pi);
	struct vy_ipfix_hdr *hdr = priv->hdr;
	char addr[16];
	int ret;

	switch (priv->proto) {
	case IPPROTO_UDP:
		if ((ret = udp_connect(pi)) < 0)
			return ret;
		break;
	case IPPROTO_TCP:
		if ((ret = tcp_connect(pi)) < 0)
			return ret;
		break;

	default:
		break;
	}

	upi_log(pi, ULOGD_INFO, "connected to %s:%d\n",
			inet_ntop(AF_INET, &priv->sa.sin_addr, addr, sizeof(addr)),
			port_ce(pi));

	if (ulogd_register_fd(&priv->ufd) < 0)
		return ULOGD_IRET_ERR;

	ulogd_register_timer(&priv->timer);

	hdr = priv->hdr = malloc(sizeof(struct vy_ipfix_hdr)
					   + 2 * sizeof(struct vy_ipfix_data));
	if (!priv->hdr) {
		upi_log(pi, ULOGD_ERROR, "out of memory\n");
		return -1;
	}

	hdr->version = VY_IPFIX_VERSION;
	hdr->cnt = 2;
	hdr->dev_id = 42;

	return ULOGD_IRET_OK;
}

static int
ipfix_stop(struct ulogd_pluginstance *pi) 
{
	struct ipfix_priv *priv = upi_priv(pi);

	close(priv->ufd.fd);
	priv->ufd.fd = -1;

	free(priv->hdr);

	return 0;
}

static int
ipfix_interp(struct ulogd_pluginstance *pi, unsigned *flags)
{
	struct ipfix_priv *priv = upi_priv(pi);
	struct ulogd_key *in = pi->input.keys;
	struct vy_ipfix_hdr *hdr = priv->hdr;
	struct vy_ipfix_data *data;
	int ret;

	BUG_ON(priv->num_flows < 0 || priv->num_flows >= 2);
	data = ((struct vy_ipfix_data *)hdr->data) + priv->num_flows;

	if (!key_src_valid(&in[InIpSaddr]))
		return ULOGD_IRET_OK;

	key_src_in(&in[InIpSaddr], &data->saddr.sin_addr);
	key_src_in(&in[InIpDaddr], &data->daddr.sin_addr);
	data->ifi_in = data->ifi_out = 0U;
	data->packets = (uint32_t)(key_src_u64(&in[InRawInPktCount])
							   + key_src_u64(&in[InRawOutPktCount]));
	data->bytes = (uint32_t)(key_src_u64(&in[InRawInPktLen])
							 + key_src_u64(&in[InRawOutPktLen]));
	data->start = key_src_u32(&in[InFlowStartSec])
		+ key_src_u32(&in[InFlowStartUsec]) / 1000;
	data->end = key_src_u32(&in[InFlowEndSec])
		+ key_src_u32(&in[InFlowEndUsec]) / 1000;
	if (key_src_valid(&in[InL4SPort])) {
		data->sport = key_src_u16(&in[InL4SPort]);
		data->dport = key_src_u16(&in[InL4DPort]);
	}
	data->l4_proto = key_src_u8(&in[InIpProto]);
	data->dscp = 0;

	if (++priv->num_flows >= 2) {
		ret = send(priv->ufd.fd, priv->hdr, sizeof(struct vy_ipfix_hdr)
				   + 2 * sizeof(struct vy_ipfix_data), 0);
		priv->num_flows = 0;
	}

	return 0;
}

static struct ulogd_plugin ipfix_plugin = { 
	.name = "IPFIX",
	.input = {
		.keys = ipfix_in_keys,
		.num_keys = ARRAY_SIZE(ipfix_in_keys),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW, 
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.config_kset = &ipfix_kset,
	.priv_size = sizeof(struct ipfix_priv),
	.configure = ipfix_configure,
	.start = ipfix_start,
	.stop = ipfix_stop,
	.interp = ipfix_interp,
	.rev = ULOGD_PLUGIN_REVISION,
};

void __upi_ctor init(void);

void init(void)
{
	ulogd_register_plugin(&ipfix_plugin);
}