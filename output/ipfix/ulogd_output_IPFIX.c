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
#include <netdb.h>

#include "ipfix.h"


enum {
	HOST_CE = 0,
	PORT_CE,
	PROTO_CE,
};

static const struct config_keyset ipfix_kset = {
	.num_ces = 3,
	.ces = {
		[HOST_CE] = CONFIG_KEY_STR("host", ""),
		[PORT_CE] = CONFIG_KEY_INT("port", 4739 ),
		[PROTO_CE] = CONFIG_KEY_STR("proto", "udp"),
	},
};

#define host_ce(pi)		ulogd_config_str(pi, HOST_CE);
#define port_ce(pi)		ulogd_config_int(pi, PORT_CE);
#define proto_ce(pi)	ulogd_config_str(pi, PROTO_CE);


struct ipfix_priv {
	int fd;
	struct ipfix_templ_hdr *templ;
};

static int
ipfix_configure(struct ulogd_pluginstance *pi)
{
	struct ipfix_priv *priv = upi_priv(pi);

	return ulogd_wildcard_inputkeys(pi);
}

static int
ipfix_start(struct ulogd_pluginstance *pi)
{
	struct ipfix_priv *priv = upi_priv(pi);

	return 0;
}

static int
ipfix_stop(struct ulogd_pluginstance *pi) 
{
	struct ipfix_priv *priv = upi_priv(pi);

	return 0;
}

static int
ipfix_interp(struct ulogd_pluginstance *pi, unsigned *flags)
{
	struct ipfix_priv *priv = upi_priv(pi);

	return 0;
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
	.priv_size 	= sizeof(struct ipfix_priv),
	.configure	= ipfix_configure,
	.start	 	= ipfix_start,
	.stop	 	= ipfix_stop,
	.interp 	= ipfix_interp,
	.rev		= ULOGD_PLUGIN_REVISION,
};

void __upi_ctor init(void);

void init(void)
{
	ulogd_register_plugin(&ipfix_plugin);
}
