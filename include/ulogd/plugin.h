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

extern struct llist_head ulogd_plugins;
extern struct llist_head ulogd_pi_stacks;

int ulogd_upi_configure(struct ulogd_pluginstance *,
						struct ulogd_pluginstance_stack *);
int ulogd_upi_start(struct ulogd_pluginstance *);
int ulogd_upi_stop(struct ulogd_pluginstance *);
int ulogd_upi_interp(struct ulogd_pluginstance *);
void ulogd_upi_signal(struct ulogd_pluginstance *, int);
int ulogd_upi_error(struct ulogd_pluginstance *, int);
void ulogd_upi_set_state(struct ulogd_pluginstance *, enum UpiState);
int ulogd_upi_reset_cfg(struct ulogd_pluginstance *);

int ulogd_upi_stop_all(void);

/* set key values */
void key_i8(struct ulogd_key *, int);
void key_i16(struct ulogd_key *, int);
void key_i32(struct ulogd_key *, int);
void key_u8(struct ulogd_key *, unsigned);
void key_u16(struct ulogd_key *, unsigned);
void key_u32(struct ulogd_key *, unsigned);
void key_bool(struct ulogd_key *, bool);
void key_ptr(struct ulogd_key *, void *);
void key_str(struct ulogd_key *, char *);

/* get key values */
int key_get_i8(const struct ulogd_key *);
int key_get_i16(const struct ulogd_key *);
int key_get_i32(const struct ulogd_key *);
unsigned key_get_u8(const struct ulogd_key *);
unsigned key_get_u16(const struct ulogd_key *);
unsigned key_get_u32(const struct ulogd_key *);
bool key_get_bool(const struct ulogd_key *);
void *key_get_ptr(const struct ulogd_key *);
char *key_get_str(const struct ulogd_key *);

static inline bool
key_valid(const struct ulogd_key *key)
{
	return key != NULL && (key->flags & ULOGD_RETF_VALID);
}

int upi_for_each(int (*)(struct ulogd_pluginstance *, void *), void *);

static inline void *
upi_key_priv(const struct ulogd_key *key)
{
	return key->priv;
}

struct ulogd_key *ulogd_alloc_keyset(int n, size_t priv_size);

struct ulogd_key *ulogd_key_find(const struct ulogd_keyset *,
								 const char *name);

int ulogd_plugin_init(void);
int stack_fsm(struct ulogd_pluginstance_stack *);
int stack_reconfigure(struct ulogd_pluginstance_stack *);
int stack_resolve_keys(const struct ulogd_pluginstance_stack *);

#endif /* PLUGIN_H */
