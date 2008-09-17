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


/**
 * Allocate a keyset for use with ulogd_pluginstance.  The keys are
 * optionally setup with private data.
 *
 * @arg num_keys  Number of keys to use.
 * @arg priv_size Size of private area per key.
 * @return Newly allocated key space or %NULL.
 */
struct ulogd_key *
ulogd_alloc_keyset(int num_keys, size_t priv_size)
{
	struct ulogd_key *keys;
	void *priv;
	size_t size;
	int i;

	if (num_keys <= 0)
		return NULL;

	size = num_keys * (sizeof(struct ulogd_key) + priv_size);
	if ((priv = keys = malloc(size)) == NULL)
		return NULL;

	memset(keys, 0, size);

	if (priv_size > 0) {
		priv += num_keys * sizeof(struct ulogd_key);
		for (i = 0; i < num_keys; i++)
			keys[i].priv = priv + i * priv_size;
	}

	return keys;
}

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
