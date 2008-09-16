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
#include <ulogd/ulogd.h>
#include <ulogd/common.h>

/*
 * Currently the sole purpose of this plugin is to provide the static
 * 'flow.count' row in the accounting database.  It thus supersedes
 * previous hacks in the SQLITE3 module e. g.
 */
enum OKeys {
	FlowCount = 0,
};

static struct ulogd_key static_keys[] = {
	[FlowCount] = {
		.type = ULOGD_RET_INT32,
		.flags = ULOGD_RETF_NONE,
		.name = "flow.count",
	},
};


static int
static_interp(struct ulogd_pluginstance *pi)
{
	struct ulogd_key *ret = pi->output.keys;

	pr_debug("%s: pi=%p\n", __func__, pi);

	ret[FlowCount].u.value.i32 = 1;
	ret[FlowCount].flags |= ULOGD_RETF_VALID;

	return 0;
}

static struct ulogd_plugin static_plugin = {
	.name = "STATIC",
	.output = {
		.keys = static_keys,
		.num_keys = ARRAY_SIZE(static_keys),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
	},
	.interp = &static_interp,
	.version = ULOGD_VERSION,
};

void __attribute__ ((constructor)) init(void);

void
init(void)
{
	ulogd_register_plugin(&static_plugin);
}
