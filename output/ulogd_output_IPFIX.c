/* ulogd_output_IPFIX.c, Version $Revision: 1628 $
 *
 * ulogd output plugin for IPFIX
 *
 * This target produces a file which looks the same like the syslog-entries
 * of the LOG target.
 *
 * (C) 2005 by Harald Welte <laforge@gnumonks.org>
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
 * $Id: ulogd_output_LOGEMU.c 1628 2005-11-04 15:23:12Z laforge $
 *
 * TODO:
 * - where to get a useable <sctp.h> for linux ?
 * - implement PR-SCTP (no api definition in draft sockets api)
 *
 */
#include "config.h"
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/plugin.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#ifdef IPPROTO_SCTP
/* temporarily disable sctp until we know which headers to use */
#undef IPPROTO_SCTP
#endif

#ifdef IPPROTO_SCTP
typedef u_int32_t sctp_assoc_t;

/* glibc doesn't yet have this, as defined by
 * draft-ietf-tsvwg-sctpsocket-11.txt */
struct sctp_sndrcvinfo {
	u_int16_t	sinfo_stream;
	u_int16_t	sinfo_ssn;
	u_int16_t	sinfo_flags;
	u_int32_t	sinfo_ppid;
	u_int32_t	sinfo_context;
	u_int32_t	sinfo_timetolive;
	u_int32_t	sinfo_tsn;
	u_int32_t	sinfo_cumtsn;
	sctp_assoc_t	sinfo_assoc_id;
};
#endif

#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include <ulogd/linuxlist.h>
#include <ulogd/ipfix_protocol.h>

#define IPFIX_DEFAULT_TCPUDP_PORT	4739

/* bitmask stuff */
struct bitmask {
	int size_bits;
	char *buf;
};

#define SIZE_OCTETS(x)	((x/8)+1)

void bitmask_clear(struct bitmask *bm)
{
	memset(bm->buf, 0, SIZE_OCTETS(bm->size_bits));
}

struct bitmask *bitmask_alloc(unsigned int num_bits)
{
	struct bitmask *bm;
	unsigned int size_octets = SIZE_OCTETS(num_bits);

	bm = malloc(sizeof(*bm) + size_octets);
	if (!bm)
		return NULL;

	bm->size_bits = num_bits;

	bitmask_clear(bm);

	return bm;
}

void bitmask_free(struct bitmask *bm)
{
	free(bm);
}

int bitmask_set_bit_to(struct bitmask *bm, unsigned int bits, int to)
{
	unsigned int byte = bits / 8;
	unsigned int bit = bits % 8;

	if (byte > SIZE_OCTETS(bm->size_bits))
		return -EINVAL;

	if (to == 0)
		bm->buf[byte] &= ~(1 << bit);
	else
		bm->buf[byte] |= (1 << bit);

	return 0;
}

#define bitmask_clear_bit(bm, bit) \
	bitmask_set_bit_to(bm, bit, 0)

#define bitmask_set_bit(bm, bit) \
	bitmask_set_bit_to(bm, bit, 1)

int bitmasks_equal(const struct bitmask *bm1, const struct bitmask *bm2)
{
	if (bm1->size_bits != bm2->size_bits)
		return -1;

	if (!memcmp(bm1->buf, bm2->buf, SIZE_OCTETS(bm1->size_bits)))
		return 1;
	else
		return 0;
}

struct bitmask *bitmask_dup(const struct bitmask *bm_orig)
{
	struct bitmask *bm_new;
	int size = sizeof(*bm_new) + SIZE_OCTETS(bm_orig->size_bits);

	bm_new = malloc(size);
	if (!bm_new)
		return NULL;

	memcpy(bm_new, bm_orig, size);

	return bm_new;
}

static struct config_keyset ipfix_kset = {
	.num_ces = 3,
	.ces = {
		{
			.key 	 = "host",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
		{
			.key	 = "port",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u	 = { .string = "4739" },
		},
		{
			.key	 = "protocol",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u	= { .string = "udp" },
		},
	},
};

#define host_ce(x)	(x->ces[0])
#define port_ce(x)	(x->ces[1])
#define proto_ce(x)	(x->ces[2])

struct ipfix_template {
	struct ipfix_templ_rec_hdr hdr;
	char buf[0];
};

struct ulogd_ipfix_template {
	struct llist_head list;
	struct bitmask *bitmask;
	unsigned int total_length;	/* length of the DATA */
	char *tmpl_cur;		/* cursor into current template position */
	struct ipfix_template tmpl;
};

struct ipfix_instance {
	int fd;		/* socket that we use for sending IPFIX data */
	int sock_type;	/* type (SOCK_*) */
	int sock_proto;	/* protocol (IPPROTO_*) */

	struct llist_head template_list;

	struct ipfix_template *tmpl;
	unsigned int tmpl_len;

	struct bitmask *valid_bitmask;	/* bitmask of valid keys */

	unsigned int total_length;	/* total size of all data elements */
};

#define ULOGD_IPFIX_TEMPL_BASE 1024
static u_int16_t next_template_id = ULOGD_IPFIX_TEMPL_BASE;

/* Build the IPFIX template from the input keys */
struct ulogd_ipfix_template *
build_template_for_bitmask(struct ulogd_pluginstance *upi,
			   struct bitmask *bm)
{
	struct ulogd_ipfix_template *tmpl;
	unsigned int i, j;
	int size = sizeof(struct ulogd_ipfix_template)
		   + (upi->input.num_keys * sizeof(struct ipfix_vendor_field));

	tmpl = malloc(size);
	if (!tmpl)
		return NULL;
	memset(tmpl, 0, size);

	tmpl->bitmask = bitmask_dup(bm);
	if (!tmpl->bitmask) {
		free(tmpl);
		return NULL;
	}

	/* initialize template header */
	tmpl->tmpl.hdr.templ_id = htons(next_template_id++);

	tmpl->tmpl_cur = tmpl->tmpl.buf;

	tmpl->total_length = 0;

	for (i = 0; i < upi->input.num_keys; i++) {
		struct ulogd_key *key = &upi->input.keys[i];
		int length = ulogd_key_size(key);

		if (!(key->u.source->flags & ULOGD_RETF_VALID))
			continue;

		if (length < 0 || length > 0xfffe) {
			upi_log(upi, ULOGD_INFO, "ignoring key '%s' because "
				  "it has an ipfix incompatible length\n",
				  key->name);
			continue;
		}

		if (key->ipfix.field_id == 0) {
			upi_log(upi, ULOGD_INFO, "ignoring key '%s' because "
				  "it has no field_id\n", key->name);
			continue;
		}

		if (key->ipfix.vendor == IPFIX_VENDOR_IETF) {
			struct ipfix_ietf_field *field = 
				(struct ipfix_ietf_field *) tmpl->tmpl_cur;

			field->type = htons(key->ipfix.field_id | 0x8000000);
			field->length = htons(length);
			tmpl->tmpl_cur += sizeof(*field);
		} else {
			struct ipfix_vendor_field *field =
				(struct ipfix_vendor_field *) tmpl->tmpl_cur;

			field->enterprise_num = htonl(key->ipfix.vendor);
			field->type = htons(key->ipfix.field_id);
			field->length = htons(length);
			tmpl->tmpl_cur += sizeof(*field);
		}
		tmpl->total_length += length;
		j++;
	}

	tmpl->tmpl.hdr.field_count = htons(j);

	return 0;
}



static struct ulogd_ipfix_template *
find_template_for_bitmask(struct ulogd_pluginstance *upi,
			  struct bitmask *bm)
{
	struct ipfix_instance *ii = upi_priv(upi);
	struct ulogd_ipfix_template *tmpl;
	
	/* FIXME: this can be done more efficient! */
	llist_for_each_entry(tmpl, &ii->template_list, list) {
		if (bitmasks_equal(bm, tmpl->bitmask))
			return tmpl;
	}
	return NULL;
}

static int output_ipfix(struct ulogd_pluginstance *upi)
{
	struct ipfix_instance *ii = upi_priv(upi);
	struct ulogd_ipfix_template *template;
	unsigned int total_size;
	int i;

	/* FIXME: it would be more cache efficient if the IS_VALID
	 * flags would be a separate bitmask outside of the array.
	 * ulogd core could very easily flush it after every packet,
	 * too. */

	bitmask_clear(ii->valid_bitmask);

	for (i = 0; i < upi->input.num_keys; i++) {
		struct ulogd_key *key = upi->input.keys[i].u.source;

		if (key->flags & ULOGD_RETF_VALID)
			bitmask_set_bit(ii->valid_bitmask, i);
	}
	
	/* lookup template ID for this bitmask */
	template = find_template_for_bitmask(upi, ii->valid_bitmask);
	if (!template) {
		upi_log(upi, ULOGD_INFO, "building new template\n");
		template = build_template_for_bitmask(upi, ii->valid_bitmask);
		if (!template) {
			upi_log(upi, ULOGD_ERROR, "error building template\n");
			return -1;
		}
		/* FIXME: prepend? */
		llist_add(&ii->template_list, &template->list);
	}
	
	total_size = template->total_length;

	/* decide if it's time to retransmit our template and (optionally)
	 * prepend it into the to-be-sent IPFIX message */
	if (0 /* FIXME */) {
		/* add size of template */
		//total_size += (template->tmpl_cur - (void *)&template->tmpl);
		total_size += sizeof(template->tmpl);
	}

	return 0;
}

static int open_connect_socket(struct ulogd_pluginstance *pi)
{
	struct ipfix_instance *ii = upi_priv(pi);
	struct addrinfo hint, *res, *resave;
	int ret;

	memset(&hint, 0, sizeof(hint));
	hint.ai_socktype = ii->sock_type;
	hint.ai_protocol = ii->sock_proto;
	hint.ai_flags = AI_ADDRCONFIG;

	ret = getaddrinfo(host_ce(pi->config_kset).u.string,
			  port_ce(pi->config_kset).u.string,
			  &hint, &res);
	if (ret != 0) {
		upi_log(pi, ULOGD_ERROR, "can't resolve host/service: %s\n",
			  gai_strerror(ret));
		return -1;
	}

	resave = res;

	for (; res; res = res->ai_next) {
		ii->fd = socket(res->ai_family, res->ai_socktype,
				res->ai_protocol);
		if (ii->fd < 0) {
			switch (errno) {
			case EACCES:
			case EAFNOSUPPORT:
			case EINVAL:
			case EPROTONOSUPPORT:
				/* try next result */
				continue;
			default:
				upi_log(pi, ULOGD_ERROR, "error: %s\n", strerror(errno));
				break;
			}
		}

#ifdef IPPROTO_SCTP
		/* Set the number of SCTP output streams */
		if (res->ai_protocol == IPPROTO_SCTP) {
			struct sctp_initmsg initmsg;
			int ret; 
			memset(&initmsg, 0, sizeof(initmsg));
			initmsg.sinit_num_ostreams = 2;
			ret = setsockopt(ii->fd, IPPROTO_SCTP, SCTP_INITMSG,
					 &initmsg, sizeof(initmsg));
			if (ret < 0) {
				upi_log(pi, ULOGD_ERROR, "cannot set number of"
					  "sctp streams: %m\n");
				close(ii->fd);
				freeaddrinfo(resave);
				return ret;
			}
#endif

		if (connect(ii->fd, res->ai_addr, res->ai_addrlen) != 0) {
			close(ii->fd);
			/* try next result */
			continue;
		}

		/* if we reach this, we have a working connection */
		upi_log(pi, ULOGD_NOTICE, "connection established\n");
		freeaddrinfo(resave);
		return 0;
	}

	freeaddrinfo(resave);
	return -1;
}

static int start_ipfix(struct ulogd_pluginstance *pi)
{
	struct ipfix_instance *priv = upi_priv(pi);
	int ret;

	priv->valid_bitmask = bitmask_alloc(pi->input.num_keys);
	if (priv->valid_bitmask == NULL)
		return ULOGD_IRET_ERR;

	if (open_connect_socket(pi) < 0) {
		ret = ULOGD_IRET_AGAIN;
		goto out_bm_free;
	}

	build_template_for_bitmask(pi, priv->valid_bitmask);

	return 0;

out_sock_close:
	close(priv->fd);
out_bm_free:
	bitmask_free(priv->valid_bitmask);
	priv->valid_bitmask = NULL;

	return ret;
}

static int stop_ipfix(struct ulogd_pluginstance *pi) 
{
	struct ipfix_instance *ii = upi_priv(pi);

	close(ii->fd);

	bitmask_free(ii->valid_bitmask);
	ii->valid_bitmask = NULL;

	return 0;
}

static int configure_ipfix(struct ulogd_pluginstance *pi)
{
	struct ipfix_instance *ii = upi_priv(pi);
	char *proto_str = proto_ce(pi->config_kset).u.string;
	int ret;

	/* determine underlying protocol */
	if (!strcasecmp(proto_str, "udp")) {
		ii->sock_type = SOCK_DGRAM;
		ii->sock_proto = IPPROTO_UDP;
	} else if (!strcasecmp(proto_str, "tcp")) {
		ii->sock_type = SOCK_STREAM;
		ii->sock_proto = IPPROTO_TCP;
#ifdef IPPROTO_SCTP
	} else if (!strcasecmp(proto_str, "sctp")) {
		ii->sock_type = SOCK_SEQPACKET;
		ii->sock_proto = IPPROTO_SCTP;
#endif
#ifdef _HAVE_DCCP
	} else if (!strcasecmp(proto_str, "dccp")) {
		ii->sock_type = SOCK_SEQPACKET;
		ii->sock_proto = IPPROTO_DCCP;
#endif
	} else {
		upi_log(pi, ULOGD_ERROR, "unknown protocol '%s'\n",
				proto_ce(pi->config_kset).u.string);
		return -EINVAL;
	}

	return ulogd_wildcard_inputkeys(pi);
}

static struct ulogd_plugin ipfix_plugin = { 
	.name = "IPFIX",
	.input = {
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW, 
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.config_kset 	= &ipfix_kset,
	.priv_size 	= sizeof(struct ipfix_instance),
	.configure	= &configure_ipfix,
	.start	 	= &start_ipfix,
	.stop	 	= &stop_ipfix,

	.interp 	= &output_ipfix, 
	.rev		= ULOGD_PLUGIN_REVISION,
};

void __upi_ctor init(void);

void init(void)
{
	ulogd_register_plugin(&ipfix_plugin);
}
