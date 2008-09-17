/*
 * plugin.h
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
 *
 * Holger Eitzenberger <holger@eitzenberger.org>  Astaro AG 2008
 */
#ifndef PLUGIN_H
#define PLUGIN_H


static inline void *
upi_key_priv(const struct ulogd_key *key)
{
	return key->priv;
}

struct ulogd_key *ulogd_alloc_keyset(int n, size_t priv_size);

struct ulogd_key *ulogd_key_find(const struct ulogd_keyset *,
								 const char *name);

#endif /* SIGNAL_H */
