/*
 * ulogd_filter_STATIC.c
 *
 * ulogd filter plugin for accounting.
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
 * Holger Eitzenberger <holger@eitzenberger.org>  Astaro AG 2008
 */
#include "config.h"
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/plugin.h>

/* days from Jan. 1 1970 to Jan 1 01 */
#define DAY_OFFSET		719163

enum InKeys {
	InFlowStartSec = 0,
};

enum OutKeys {
	OutFlowCount = 0,
	OutFlowStartDay,
};


static struct ulogd_key static_in_keys[] = {
	[InFlowStartSec] = KEY(UINT32, "flow.start.sec"),
};

static struct ulogd_key static_out_keys[] = {
	[OutFlowCount] = KEY(INT32, "flow.count"),
	[OutFlowStartDay] = KEY(UINT32, "flow.start.day"),
};


static int
static_interp(struct ulogd_pluginstance *pi, unsigned *flags)
{
	struct ulogd_key *out = pi->output.keys;
	struct ulogd_key *in = pi->input.keys;

	pr_debug("%s: pi=%p\n", __func__, pi);

	key_set_i32(&out[OutFlowCount], 1);
	key_set_u32(&out[OutFlowStartDay], key_src_u32(&in[InFlowStartSec])
			/ (1 DAY) + DAY_OFFSET);

	return 0;
}

static struct ulogd_plugin static_plugin = {
	.name = "STATIC",
	.flags = ULOGD_PF_RECONF,
	.input = {
		.keys = static_in_keys,
		.num_keys = ARRAY_SIZE(static_in_keys),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
	},
	.output = {
		.keys = static_out_keys,
		.num_keys = ARRAY_SIZE(static_out_keys),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
	},
	.interp = &static_interp,
	.rev = ULOGD_PLUGIN_REVISION,
};

void __upi_ctor init(void);

void
init(void)
{
	ulogd_register_plugin(&static_plugin);
}
