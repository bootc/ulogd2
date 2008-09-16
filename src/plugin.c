/*
 * plugin.c
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
#include <ulogd/plugin.h>


struct ulogd_key *
ulogd_key_find(const struct ulogd_keyset *set, const char *name)
{
	int i;

	for (i = 0; i < set->num_keys; i++) {
		if (strcmp(set->keys[i].name, name) == 0)
			return &set->keys[i];
	}

	return NULL;
}

