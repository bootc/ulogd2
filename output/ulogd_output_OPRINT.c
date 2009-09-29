/*
 * ulogd_output_OPRINT.c
 *
 * ulogd output target for logging to a file 
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 
 * as published by the Free Software Foundation
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
 * (c) 2009  Holger Eitzenberger <holger@eitzenberger.org>
 */
#include "config.h"
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/conffile.h>
#include <ulogd/plugin.h>
#include <string.h>
#include <arpa/inet.h>

#define OPR_BUF_LEN		64
#define OPR_DEFAULT_LOG	"/var/log/ulogd.pktlog"


struct opr_priv {
	FILE *of;
	char buf[OPR_BUF_LEN];
};

static const struct config_keyset opr_kset = {
	.num_ces = 2,
	.ces = {
		CONFIG_KEY_STR("file", OPR_DEFAULT_LOG),
		CONFIG_KEY_INT("sync", 1),
	},
};

static int
opr_configure(struct ulogd_pluginstance *upi)
{
	int ret;

	pr_fn_debug("pi=%p\n", upi);

	ret = ulogd_wildcard_inputkeys(upi);
	if (ret < 0)
		return ret;

	return 0;
}

static int
opr_start(struct ulogd_pluginstance *upi)
{
	struct opr_priv *op = upi_priv(upi);

	pr_fn_debug("pi=%p file=%p\n", upi, upi->config_kset->ces[0].u.string);

	op->of = fopen(upi->config_kset->ces[0].u.string, "a");
	if (!op->of) {
		upi_log(upi, ULOGD_FATAL, "can't open PKTLOG: %m\n");
		return -1;
	}		
	return 0;
}

static int
opr_stop(struct ulogd_pluginstance *pi)
{
	struct opr_priv *op = upi_priv(pi);

	if (op->of) {
		fclose(op->of);
		op->of = NULL;
	}

	return 0;
}

static int
opr_interp(struct ulogd_pluginstance *upi, unsigned *flags)
{
	struct opr_priv *opi = upi_priv(upi);
	unsigned int i;
	
	fprintf(opi->of, "===>PACKET BOUNDARY\n");
	for (i = 0; i < upi->input.num_keys; i++) {
		struct ulogd_key *key = key_src(&upi->input.keys[i]);

		if (!key || !key_valid(key)) {
			upi_log(upi, ULOGD_NOTICE, "no result for '%s'\n", key->name);
			continue;
		}

		fprintf(opi->of,"%s=", key->name);
		switch (key->type) {
		case ULOGD_RET_STRING:
			fprintf(opi->of, "%s\n", key_str(key));
			break;

		case ULOGD_RET_BOOL:
			fprintf(opi->of, "%d\n", key_bool(key));
			break;

		case ULOGD_RET_INT8:
			fprintf(opi->of, "%d\n", key_i8(key));
			break;

		case ULOGD_RET_INT16:
			fprintf(opi->of, "%d\n", key_i16(key));
			break;

		case ULOGD_RET_INT32:
			fprintf(opi->of, "%d\n", key_i32(key));
			break;

		case ULOGD_RET_UINT8:
			fprintf(opi->of, "%u\n", key_u8(key));
			break;
			
		case ULOGD_RET_UINT16:
			fprintf(opi->of, "%u\n", key_u16(key));
			break;
			
		case ULOGD_RET_UINT32:
			fprintf(opi->of, "%u\n", key_u32(key));
			break;
			
		case ULOGD_RET_IPADDR:
		{
			struct in_addr addr = (struct in_addr){ key_u32(key), };
			
			inet_ntop(AF_INET, &addr, opi->buf, OPR_BUF_LEN);
			fprintf(opi->of, "%s\n", opi->buf);
			break;
		}
		
		case ULOGD_RET_NONE:
			ulogd_abort("%s: invalid key '%s' (type %d)\n", upi->id,
						key->name, key->type);
			break;
			
		case ULOGD_RET_RAW:
		default:
			break;
		}
	}

	if (upi->config_kset->ces[1].u.value)
		fflush(opi->of);

	return 0;
}

static struct ulogd_plugin opr_plugin = {
	.name = "OPRINT", 
	.input = {
			.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
		},
	.output = {
			.type = ULOGD_DTYPE_SINK,
		},
	.configure = opr_configure,
	.start 	= opr_start,
	.stop	= opr_stop,
	.interp	= opr_interp,
	.config_kset = &opr_kset,
	.rev = ULOGD_PLUGIN_REVISION,
	.priv_size = sizeof(struct opr_priv),
};

void __upi_ctor init(void);

void init(void)
{
	ulogd_register_plugin(&opr_plugin);
}
