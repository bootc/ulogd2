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

int
ulogd_upi_configure(struct ulogd_pluginstance *pi,
					struct ulogd_pluginstance_stack *stack)
{
	if (pi->plugin->configure == NULL)
		return 0;

	return pi->plugin->configure(pi, stack);
}

int
ulogd_upi_start(struct ulogd_pluginstance *pi)
{
	if (pi->plugin->start == NULL)
		return 0;

	return pi->plugin->start(pi);
}

int
ulogd_upi_stop(struct ulogd_pluginstance *pi)
{
	return pi->plugin->stop(pi);
}

int
ulogd_upi_interp(struct ulogd_pluginstance *pi)
{
	return pi->plugin->interp(pi);
}

void
ulogd_upi_signal(struct ulogd_pluginstance *pi, int signo)
{
	if (pi->plugin->signal == NULL)
		return;

	pi->plugin->signal(pi, signo);
}

/* key API */
static void
__check_get(const struct ulogd_key *key, unsigned type)
{
#ifdef DEBUG
	if (key == NULL || key->u.source == NULL)
		abort();

	if ((key->u.source->type & type) == 0) {
		pr_fn_debug("%s: type check failed (%d <-> %d)\n",
					key->name, key->type, type);
		abort();
	}
#endif /* DEBUG */
}

static void
__check(const struct ulogd_key *key, unsigned type)
{
#ifdef DEBUG
	if (key == NULL)
		abort();

	if ((key->type & type) == 0) {
		pr_fn_debug("%s: type check failed (%d <-> %d)\n",
					key->name, key->type, type);
		abort();
	}
#endif /* DEBUG */
}

void
key_i8(struct ulogd_key *key, int v)
{
	__check(key, ULOGD_RET_INT8);

	key->u.value.i8 = v;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_i16(struct ulogd_key *key, int v)
{
	__check(key, ULOGD_RET_INT16);

	key->u.value.i16 = v;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_i32(struct ulogd_key *key, int v)
{
	__check(key, ULOGD_RET_INT32);

	key->u.value.i32 = v;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_u8(struct ulogd_key *key, unsigned v)
{
	__check(key, ULOGD_RET_UINT8);

	key->u.value.ui8 = v;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_u16(struct ulogd_key *key, unsigned v)
{
	__check(key, ULOGD_RET_UINT16);

	key->u.value.ui16 = v;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_u32(struct ulogd_key *key, unsigned v)
{
	__check(key, ULOGD_RET_UINT32 | ULOGD_RET_IPADDR);

	key->u.value.ui32 = v;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_bool(struct ulogd_key *key, bool v)
{
	__check(key, ULOGD_RET_BOOL);

	key->u.value.b = v;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_ptr(struct ulogd_key *key, void *ptr)
{
	__check(key, ULOGD_RET_RAW);

	key->u.value.ptr = ptr;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_str(struct ulogd_key *key, char *str)
{
	__check(key, ULOGD_RET_STRING);

	key->u.value.str = str;
	key->flags |= ULOGD_RETF_VALID;
}

int
key_get_i8(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_INT8);

	return key->u.source->u.value.i8;
}

int
key_get_i16(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_INT16);

	return key->u.source->u.value.i16;
}

int
key_get_i32(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_INT32);

	return key->u.source->u.value.i32;
}

unsigned
key_get_u8(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_UINT8);

	return key->u.source->u.value.ui8;
}

unsigned
key_get_u16(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_UINT16);

	return key->u.source->u.value.ui16;
}

unsigned
key_get_u32(const struct ulogd_key *key)
{
	/* currently, IP addresses are encoded as u32.  A strong typesafety
	   might require to add key_get_ipaddr() as well. */
	__check_get(key, ULOGD_RET_UINT32 | ULOGD_RET_IPADDR);

	return key->u.source->u.value.ui32;
}

bool
key_get_bool(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_BOOL);

	return !!key->u.source->u.value.b;
}

void *
key_get_ptr(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_RAW);

	return key->u.source->u.value.ptr;
}

char *
key_get_str(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_STRING);

	return key->u.source->u.value.str;
}

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

