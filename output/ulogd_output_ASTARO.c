/*
 * ulogd_output_ASTARO.c
 *
 * A variant of the SYSLOG plugin with Astaro conformable logging.
 *
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
 * H. Eitzenberger, 2006  Astaro AG
 */

#define SYSLOG_NAMES

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/ifi.h>
#include <ulogd/conffile.h>

#define HIPQUAD(addr) \
        ((unsigned char *)&addr)[3], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]

#define PRINT_MAC(mac) 	*mac, (mac)[1], (mac)[2], (mac)[3], (mac)[4], (mac)[5]

/* config accessors */
#define CFG_FACILITY(pi)	((pi)->config_kset->ces[0].u.string)
#define CFG_LEVEL(pi)		((pi)->config_kset->ces[1].u.string)

/* packetfilter range */
#define __PF_BASE		2000
#define LOG_ID_LOG			(__PF_BASE + 0)
#define LOG_ID_DROP			(__PF_BASE + 1)
#define LOG_ID_ACCEPT		(__PF_BASE + 2)
#define LOG_ID_REJECT		(__PF_BASE + 3)
#define LOG_ID_INVAL_PKT	(__PF_BASE + 4)
#define LOG_ID_SPOOFING_DROP (__PF_BASE + 5)
#define LOG_ID_ICMP_REDIR	(__PF_BASE + 9)
#define LOG_ID_H323_RTP		(__PF_BASE + 10)
#define LOG_ID_Q931_GK		(__PF_BASE + 11)
#define LOG_ID_STRICT_TCP	(__PF_BASE + 12)
#define LOG_ID_FTP_DATA		(__PF_BASE + 13)
#define LOG_ID_DNS_REQ		(__PF_BASE + 14)
#define LOG_ID_SIP_RTP		(__PF_BASE + 16)

/* IPS range */
#define __IPS_BASE	2100
#define LOG_ID_PORTSCAN		(__IPS_BASE + 2)
#define LOG_ID_SYN_FLOOD	(__IPS_BASE + 3)
#define LOG_ID_ICMP_FLOOD	(__IPS_BASE + 4)
#define LOG_ID_UDP_FLOOD	(__IPS_BASE + 5)

/* logging flags for custom log handler */
#define LH_F_NOLOG		0x0001
#define LH_F_NOTNULL	0x0002


/* one entry for each entry in astaro_in_keys */
struct log_handler {
	/* alternative logging prefix (instead of ulogd_key name) */
	char *name;

	/* custom log handler */
	int (* fn)(const struct ulogd_pluginstance *, unsigned, char *, size_t);

	unsigned flags;
};


/* map log prefix to descriptive text and ID */
static struct log_type {
	char *prefix;				/* same as LOG target --log-prefix */
	char *desc;					/* descriptive text */
	unsigned id;			 /* Astaro log ID, see Wiki for details */
	char *action;
	size_t prefix_len;
} log_types[] = {
	/* the first entry is the fallback entry */
	{ "LOG:", "Packet logged", LOG_ID_LOG, "log" },
	{ "DROP:", "Packet dropped", LOG_ID_DROP, "drop" },
	{ "ACCEPT:", "Packet accepted", LOG_ID_ACCEPT, "accept" },
	{ "REJECT:", "Packet rejected", LOG_ID_REJECT, "reject" },
	{ "INVALID_PKT:", "Invalid packet", LOG_ID_INVAL_PKT, "invalid packet" },
	{ "IP-SPOOFING DROP:", "IP spoofing drop", LOG_ID_SPOOFING_DROP,
		"IP spoofing drop" },
	{ "SYN_FLOOD:", "SYN flood detected", LOG_ID_SYN_FLOOD, "SYN flood" },
	{ "ICMP_FLOOD:", "ICMP flood detected", LOG_ID_ICMP_FLOOD, "ICMP flood" },
	{ "UDP_FLOOD:", "UDP flood detected", LOG_ID_UDP_FLOOD, "UDP flood" },
	{ "ICMP REDIRECT:", "ICMP redirect", LOG_ID_ICMP_REDIR, "ICMP redirect" },
	{ "H.323  RTP:", "H.323 RTP", LOG_ID_H323_RTP, "H.323 RTP" },
	{ "Q.931 Gatekeeper connection:", "Q.931 Gatekeeper", LOG_ID_Q931_GK,
	  "Q.931 Gatekeeper" },
	{ "STRICT_TCP_STATE:", "strict TCP state", LOG_ID_STRICT_TCP,
	  "strict TCP state" },
	{ "FTP_DATA:", "FTP data", LOG_ID_FTP_DATA, "FTP data" },
	{ "DNS_REQUEST:", "DNS request", LOG_ID_DNS_REQ, "DNS request" },
	{ "PORTSCAN:", "portscan detected", LOG_ID_PORTSCAN, "portscan" },
	{ "SIP Call RTP:", "SIP call RTP", LOG_ID_SIP_RTP, "SIP call RTP" },
	{ NULL, }
};

struct ulogd_key astaro_in_keys[] = {
	{ .type = ULOGD_RET_STRING, .name = "oob.prefix", },
	{ .type = ULOGD_RET_UINT32, .name = "oob.logmark", },
	{ .type = ULOGD_RET_UINT32, .name = "oob.seq.local" },
	{ .type = ULOGD_RET_UINT32, .name = "oob.ifindex_in" },
	{ .type = ULOGD_RET_UINT32, .name = "oob.ifindex_out" },
	{ .type = ULOGD_RET_RAW, .name = "raw.mac",	},
	{ .type = ULOGD_RET_IPADDR, .name = "ip.saddr",	},
	{ .type = ULOGD_RET_IPADDR, .name = "ip.daddr",	},
	{ .type = ULOGD_RET_UINT8, .name = "ip.protocol", },
	{ .type = ULOGD_RET_UINT32, .name = "raw.pktlen", },
	{ .type = ULOGD_RET_UINT8, .name = "ip.tos", },
	{ .type = ULOGD_RET_UINT8, .name = "ip.ttl", },
	{ .type = ULOGD_RET_UINT16, .name = "tcp.sport", },
	{ .type = ULOGD_RET_UINT16, .name = "tcp.dport", },
	{ .type = ULOGD_RET_UINT16, .name = "udp.sport", },
	{ .type = ULOGD_RET_UINT16, .name = "udp.dport", },
	{ .type = ULOGD_RET_BOOL, .name = "tcp.ack", },
	{ .type = ULOGD_RET_BOOL, .name = "tcp.psh", },
	{ .type = ULOGD_RET_BOOL, .name = "tcp.rst", },
	{ .type = ULOGD_RET_BOOL, .name = "tcp.syn", },
	{ .type = ULOGD_RET_BOOL, .name = "tcp.fin", },
	{ .type = ULOGD_RET_UINT8, .name = "icmp.type", },
	{ .type = ULOGD_RET_UINT8, .name = "icmp.code", },
};

/* indexes into tables */
#define KEY_IDX_ITFIN			3
#define KEY_IDX_ITFOUT			4

/* ret-value accessors */
#define KEY_RET(pi, idx)		((pi)->input.keys[(idx)].u.source)

#define KEY_PREFIX(pi)			KEY_RET(pi, 0)
#define KEY_ITFIN(pi)			KEY_RET(pi, KEY_IDX_ITFIN)
#define KEY_ITFOUT(pi)			KEY_RET(pi, KEY_IDX_ITFOUT)
#define KEY_PROTO(pi)			KEY_RET(pi, 8)
#define KEY_TCP_ACK(pi)			KEY_RET(pi, 16)
#define KEY_TCP_PSH(pi)			KEY_RET(pi, 17)
#define KEY_TCP_RST(pi)			KEY_RET(pi, 18)
#define KEY_TCP_SYN(pi)			KEY_RET(pi, 19)
#define KEY_TCP_FIN(pi)			KEY_RET(pi, 20)
#define KEY_ICMP_TYPE(pi)		KEY_RET(pi, 21)
#define KEY_ICMP_CODE(pi)		KEY_RET(pi, 22)

static int
avail(const char *buf, const char *pch, size_t max_len)
{
	return buf + max_len - pch;
}


/* mac address log helper */
static int
lh_log_mac(const struct ulogd_pluginstance *pi, unsigned idx,
		   char *buf, size_t len)
{
	const struct ulogd_key *k = pi->input.keys[idx].u.source;
	static unsigned char mac_unknown[6];
	struct ifi *ifi;
	unsigned char *src, *dst;

	if (KEY_ITFIN(pi)->u.value.ui32 > 0) {
		ifi = ifi_find_by_idx(KEY_ITFIN(pi)->u.value.i32);
		dst = (ifi != NULL) ? ifi->lladdr : mac_unknown;

		src = (unsigned char *)k->u.value.ptr;
	} else if (KEY_ITFOUT(pi)->u.value.ui32 > 0) {
		ifi = ifi_find_by_idx(KEY_ITFOUT(pi)->u.value.i32);
		src = (ifi != NULL) ? ifi->lladdr : mac_unknown;
		
		dst = (unsigned char *)k->u.value.ptr;
	} else {
		ulogd_log(ULOGD_ERROR, "%s: srcmac = dstmac = 0!\n", __func__);
		return 0;
	}
	
	return snprintf(buf, len, "dstmac=\"%02x:%02x:%02x:%02x:%02x:%02x\" "
					"srcmac=\"%02x:%02x:%02x:%02x:%02x:%02x\" ",
					PRINT_MAC(dst), PRINT_MAC(src));
}


static int
lh_log_tos(const struct ulogd_pluginstance *pi, unsigned idx,
		   char *buf, size_t len)
{
	const struct ulogd_key *k = pi->input.keys[idx].u.source;
	
	return snprintf(buf, len, "tos=\"0x%02x\" prec=\"0x%02x\" ",
					IPTOS_TOS(k->u.value.ui8), IPTOS_PREC(k->u.value.ui8));
}


static struct log_handler log_handler[];

static int
lh_log_itf(const struct ulogd_pluginstance *pi, unsigned idx,
		   char *buf, size_t len)
{
	const struct ulogd_key *k = pi->input.keys[idx].u.source;
	struct ifi *ifi = ifi_find_by_idx(k->u.value.ui32);
	char *key_name = log_handler[idx].name ? log_handler[idx].name : "itf";

	return snprintf(buf, len, "%s=\"%s\" ", key_name, ifi ? ifi->name
					: "unknown");
}

static struct log_handler log_handler[ARRAY_SIZE(astaro_in_keys)] = {
	{ NULL, NULL, LH_F_NOLOG },	/* oob.prefix */
	{ "fwrule", },
	{ "seq", },					/* oob.seq.local */
	{ "initf", lh_log_itf, },
	{ "outitf", lh_log_itf, },
	{ NULL, lh_log_mac },		/* mac address */
	{ "srcip", },
	{ "dstip", },
	{ "proto", NULL },
	{ "length", },
	{ "tos", lh_log_tos },
	{ "ttl", },
	{ "srcport", NULL, LH_F_NOTNULL }, /* tcp.spt */
	{ "dstport", NULL, LH_F_NOTNULL }, /* tcp.dpt */
	{ "srcport", NULL, LH_F_NOTNULL }, /* udp.spt */
	{ "dstport", NULL, LH_F_NOTNULL }, /* udp.dpt */
	{ NULL, NULL, LH_F_NOLOG },	/* tcp.ack */
	{ NULL, NULL, LH_F_NOLOG },	/* tcp.psh */
	{ NULL, NULL, LH_F_NOLOG },	/* tcp.rst */
	{ NULL, NULL, LH_F_NOLOG },	/* tcp.syn */
	{ NULL, NULL, LH_F_NOLOG },	/* tcp.fin */
	{ NULL, NULL, LH_F_NOLOG },	/* icmp.type */
	{ NULL, NULL, LH_F_NOLOG },	/* icmp.code */
};

static struct config_keyset astaro_kset = { 
	.num_ces = 2,
	.ces = {
		{
			.key = "facility", 
			.type = CONFIG_TYPE_STRING, 
			.options = CONFIG_OPT_NONE, 
		},
		{ 
			.key = "level", 
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE, 
		},
	},
};

struct astaro_priv {
	int level;
	int facility;
};

/* map LOG target prefix to type, use first entry as fallback */
static unsigned
log_prefix2type(const struct log_type *t, const char *prefix)
{
	unsigned n;

	if (prefix == NULL)
		return 0;

	for (n = 0; t[n].prefix != NULL; n++) {
		if (strncmp(t[n].prefix, prefix, t[n].prefix_len) == 0)
			return n;
	}

	return 0;
}

/* append to string, thereby advancing current pointer */
static void
str_append(char **pch, const char *append, int len, int *delim)
{
	if (len < 0) len = strlen(append);

	strcat(*pch, append);
	*pch += len;

	if (delim == NULL)
		return;

	if (*delim) {
		strcat(*pch, " ");
		(*pch)++;
	} else
		*delim = 1;
}

/* print key in standard logging format */
static int
print_key(char *buf, size_t len, const struct ulogd_key *k, const char *name)
{
	char *pch = buf;

	switch (k->type) {
	case ULOGD_RET_STRING:
		pch += snprintf(pch, avail(buf, pch, len), "%s=\"%s\" ", name,
						(char *)k->u.value.ptr);
		break;
		
	case ULOGD_RET_IPADDR:
		pch += snprintf(pch, avail(buf, pch, len), "%s=\"%u.%u.%u.%u\" ", name,
						HIPQUAD(k->u.value.ui32));
		break;
		
	case ULOGD_RET_UINT8:
		pch += snprintf(pch, avail(buf, pch, len), "%s=\"%u\" ", name,
						k->u.value.ui8);
		break;
		
	case ULOGD_RET_UINT16:
		if (k->u.value.ui16 != 0)
			pch += snprintf(pch, avail(buf, pch, len), "%s=\"%u\" ", name,
							k->u.value.ui16);
		break;
		
	case ULOGD_RET_UINT32:
		if (k->u.value.ui32 != 0)
			pch += snprintf(pch, avail(buf, pch, len), "%s=\"%u\" ", name,
							k->u.value.ui32);
		break;
		
	default:
		break;
	};

	return pch - buf;
}

static int
print_proto_tcp(const struct ulogd_pluginstance *pi, char *buf, size_t len)
{
	char *pch = buf;
	int delim = 0;

	/* srcport/dstport are handled through generic logging handler */

	str_append(&pch, "tcpflags=\"", 10, NULL);

	if (KEY_TCP_ACK(pi)->u.value.b)
		str_append(&pch, "ACK", 3, &delim);
	if (KEY_TCP_PSH(pi)->u.value.b)
		str_append(&pch, "PSH", 3, &delim);
	if (KEY_TCP_RST(pi)->u.value.b)
		str_append(&pch, "RST", 3, &delim);
	if (KEY_TCP_SYN(pi)->u.value.b)
		str_append(&pch, "SYN", 3, &delim);
	if (KEY_TCP_FIN(pi)->u.value.b)
		str_append(&pch, "FIN", 3, &delim);

	str_append(&pch, "\"", 1, NULL);
		
	return pch - buf;
}

static int
print_proto_icmp(const struct ulogd_pluginstance *pi, char *buf, size_t len)
{
	char *pch = buf;

	pch += print_key(pch, len, KEY_ICMP_TYPE(pi), "type");
	pch += print_key(pch, avail(buf, pch, len), KEY_ICMP_CODE(pi), "code");

	return pch - buf;
}

static int
print_dyn_part(const struct ulogd_pluginstance *pi, char *buf, size_t max_len)
{
	char *pch = buf;
	int i;

	for (i = 0; i < pi->input.num_keys; i++) {
		struct ulogd_key *k = pi->input.keys[i].u.source;
		char *name;

 		if (k == NULL || (k->flags & ULOGD_RETF_VALID) == 0)
			continue;

		if (log_handler[i].flags & LH_F_NOLOG)
			continue;

		/* log handler name takes precedence */
		name = log_handler[i].name ? log_handler[i].name : k->name;

		/* custom logging handler? */
		if (log_handler[i].fn != NULL) {
			pch += (log_handler[i].fn)(pi, i, pch, avail(buf, pch, max_len));
			continue;
		}

		pch += print_key(pch, avail(buf, pch, max_len), k, name);
	}

	/* print proto specific part */
	if (KEY_PROTO(pi)->u.value.ui8 == IPPROTO_TCP)
		pch += print_proto_tcp(pi, pch, avail(buf, pch, max_len));
	else if (KEY_PROTO(pi)->u.value.ui8 == IPPROTO_ICMP)
		pch += print_proto_icmp(pi, pch, avail(buf, pch, max_len));

	return pch - buf;
}


/* map log ID to subsystem (packetfilter, ips) */
static const char *
id_to_sub(unsigned id)
{
	if (id >= __IPS_BASE)
		return "ips";
	if (id >= __PF_BASE)
		return "packetfilter";

	return "unknown";
}

static int
astaro_output(struct ulogd_pluginstance *pi)
{
	struct astaro_priv *priv = (struct astaro_priv *)pi->private;
	struct ulogd_key *ces = pi->input.keys;
	static char buf[1024];
	char *pch = buf, *end = buf + sizeof(buf);
	unsigned type;
	
	if ((ces[0].u.source->flags & ULOGD_RETF_VALID) == 0)
		return 0;
	
	type = log_prefix2type(log_types, KEY_PREFIX(pi) ?
						   KEY_PREFIX(pi)->u.value.ptr : NULL);
	
	/* static part */
	pch += snprintf(pch, end - pch,
					"id=\"%u\" severity=\"info\" sys=\"SecureNet\" " 
					"sub=\"%s\" name=\"%s\" action=\"%s\" ",
					log_types[type].id, id_to_sub(log_types[type].id),
					log_types[type].desc, log_types[type].action);

	pch += print_dyn_part(pi, pch, end - pch);
	
	syslog(priv->level | priv->facility, "%s\n", buf);

	return 0;
}


/* name-value pair */
static struct nv {
	char *name;
	int val;
} nv_facility[] = {
	{ "LOG_DAEMON", LOG_DAEMON },
	{ "LOG_KERN", LOG_KERN },
	{ "LOG_LOCAL0", LOG_LOCAL0 },
	{ "LOG_LOCAL1", LOG_LOCAL1 },
	{ "LOG_LOCAL2", LOG_LOCAL2 },
	{ "LOG_LOCAL3", LOG_LOCAL3 },
	{ "LOG_LOCAL4", LOG_LOCAL4 },
	{ "LOG_LOCAL5", LOG_LOCAL5 },
	{ "LOG_LOCAL6", LOG_LOCAL6 },
	{ "LOG_LOCAL7", LOG_LOCAL7 },
	{ "LOG_USER", LOG_USER },
	{ 0, }
};
static struct nv nv_level[] = {
	{ "LOG_EMERG", LOG_EMERG },
	{ "LOG_ALERT", LOG_ALERT },
	{ "LOG_CRIT", LOG_CRIT },
	{ "LOG_ERR", LOG_ERR },
	{ "LOG_WARNING", LOG_WARNING },
	{ "LOG_NOTICE", LOG_NOTICE },
	{ "LOG_INFO", LOG_INFO },
	{ "LOG_DEBUG", LOG_DEBUG },
	{ 0, }
};

static int
nv_get_value(struct nv *nv, const char *name, int def_val)
{
	if (*name == '\0')
		return def_val;

	for (; nv->name != NULL; nv++) {
		if (strcmp(nv->name, name) == 0)
			return nv->val;
	}

	return -1;
};

static int
astaro_configure(struct ulogd_pluginstance *pi,
				 struct ulogd_pluginstance_stack *stack)
{
	struct astaro_priv *priv = (struct astaro_priv *)pi->private;

	/* FIXME: error handling */
	config_parse_file(pi->id, pi->config_kset);

	priv->facility = nv_get_value(nv_facility, CFG_FACILITY(pi), LOG_KERN);
	if (priv->facility < 0) {
		ulogd_log(ULOGD_FATAL, "unknown facility '%s'\n", CFG_FACILITY(pi));
		return -EINVAL;
	}

	priv->level = nv_get_value(nv_level, CFG_LEVEL(pi), LOG_NOTICE);
	if (priv->level < 0) {
		ulogd_log(ULOGD_FATAL, "unknown level '%s'\n", CFG_LEVEL(pi));
		return -EINVAL;
	}

	return 0;
}

static int
astaro_fini(struct ulogd_pluginstance *pi)
{
	closelog();

	return 0;
}

static int
astaro_start(struct ulogd_pluginstance *pi)
{
	int i;

	openlog("ulogd", LOG_NDELAY | LOG_PID, LOG_DAEMON);

	for (i = 0; log_types[i].prefix !=  NULL; i++)
		log_types[i].prefix_len = strlen(log_types[i].prefix);

	return 0;
}

static struct ulogd_plugin astaro_plugin = {
	.name = "ASTARO",
	.input = {
		.keys = astaro_in_keys,
		.num_keys = ARRAY_SIZE(astaro_in_keys),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.config_kset		= &astaro_kset,
	
	.configure	= astaro_configure,
	.start		= astaro_start,
	.stop		= astaro_fini,
	.interp		= astaro_output,
	.version	= ULOGD_VERSION,
};

void __attribute__ ((constructor)) init(void);

void
init(void)
{
	ulogd_register_plugin(&astaro_plugin);
}
