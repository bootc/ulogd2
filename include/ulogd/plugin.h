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

/**
 * Plugin instance state handling
 *
 * PsInit		Plugin initialized.
 * PsConfigured	Plugin configured, if this step fails the daemon is stopped.
 * PsStarting	Plugin is in the process of starting.  If the start() fails
 *				there is a chance to restart if start() returns
 *				%ULOGD_IRET_AGAIN.
 * PsStart		Plugin up and running.
 */
enum UpiState {
	PsInit = 0,
	PsConfigured,
	PsStarting,
	PsStarted,
};

int ulogd_upi_configure(struct ulogd_pluginstance *,
						struct ulogd_pluginstance_stack *);
int ulogd_upi_start(struct ulogd_pluginstance *);
int ulogd_upi_stop(struct ulogd_pluginstance *);
int ulogd_upi_interp(struct ulogd_pluginstance *);
void ulogd_upi_signal(struct ulogd_pluginstance *, int);
void ulogd_upi_set_state(struct ulogd_pluginstance *, enum UpiState);
int ulogd_upi_reset_cfg(struct ulogd_pluginstance *);

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

static inline void *
upi_key_priv(const struct ulogd_key *key)
{
	return key->priv;
}

struct ulogd_key *ulogd_alloc_keyset(int n, size_t priv_size);

struct ulogd_key *ulogd_key_find(const struct ulogd_keyset *,
								 const char *name);

#endif /* SIGNAL_H */
