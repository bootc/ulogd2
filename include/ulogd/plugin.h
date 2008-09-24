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

/* key types */
enum ulogd_ktype {
	ULOGD_RET_NONE = 0,
    ULOGD_RET_INT8,
	ULOGD_RET_INT16,
	ULOGD_RET_INT32,
	ULOGD_RET_INT64,
	ULOGD_RET_UINT8,
	ULOGD_RET_UINT16,
	ULOGD_RET_UINT32,
	ULOGD_RET_UINT64,
	ULOGD_RET_BOOL,
	ULOGD_RET_IPADDR,
	ULOGD_RET_IP6ADDR,
	ULOGD_RET_STRING,
	ULOGD_RET_RAW,
};

/* key flags */
#define ULOGD_RETF_NONE		0x0000
#define ULOGD_RETF_VALID	0x0001	/* contains a valid result */
#define ULOGD_RETF_FREE		0x0002	/* ptr needs to be free()d */
#define ULOGD_RETF_NEEDED	0x0004	/* this parameter is actually needed
					 * by some downstream plugin */

#define ULOGD_KEYF_OPTIONAL	0x0100	/* this key is optional */
#define ULOGD_KEYF_INACTIVE	0x0200	/* marked as inactive (i.e. totally
					   to be ignored by everyone */


/* maximum length of ulogd key */
#define ULOGD_MAX_KEYLEN 31

/* ulogd data type */
enum ulogd_dtype {
	ULOGD_DTYPE_NULL	= 0x0000,
	ULOGD_DTYPE_SOURCE	= 0x0001, /* source of data, no input keys */
	ULOGD_DTYPE_RAW		= 0x0002, /* raw packet data */
	ULOGD_DTYPE_PACKET	= 0x0004, /* packet metadata */
	ULOGD_DTYPE_FLOW	= 0x0008, /* flow metadata */
	ULOGD_DTYPE_SINK	= 0x0010, /* sink of data, no output keys */
};

/* structure describing an input  / output parameter of a plugin */
struct ulogd_key {
	/* length of the returned value (only for lengthed types */
	u_int32_t len;

	/* type of the returned value */
	enum ulogd_ktype type;

	u_int16_t flags;

	/* name of this key */
	char name[ULOGD_MAX_KEYLEN+1];

	/* IETF IPFIX attribute ID */
	struct {
		u_int32_t	vendor;
		u_int16_t	field_id;
	} ipfix;

	union {
		/* and finally the returned value */
		union {
			u_int8_t	b;
			u_int8_t	ui8;
			u_int16_t	ui16;
			u_int32_t	ui32;
			u_int64_t	ui64;
			int8_t		i8;
			int16_t		i16;
			int32_t		i32;
			int64_t		i64;
			void		*ptr;
			char		*str;
		} value;
		struct ulogd_key *source;
	} u;

	/* private date owned by plugin */
	void *priv;
};

struct ulogd_keyset {
	/* possible input keys of this interpreter */
	struct ulogd_key *keys;
	/* number of input keys */
	unsigned int num_keys;
	/* bitmask of possible types */
	unsigned int type;
};

/* key initializers */
#define IPFIX(v, f)								\
		{										\
			.vendor = IPFIX_VENDOR_ ## v,		\
			.field_id = IPFIX_ ## f,			\
		}

#define KEY(t,n)					\
	{								\
		.type = ULOGD_RET_ ## t,	\
		.name = (n),				\
	}
#define KEY_IPFIX(t, n, v, f)			\
	{									\
		.type = ULOGD_RET_ ## t,		\
		.name = (n),					\
		.ipfix = IPFIX(v, f),			\
	}

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

bool key_type_eq(const struct ulogd_key *, const struct ulogd_key *);

static inline struct ulogd_key *
key_src(const struct ulogd_key *key)
{
	return key->u.source;
}

static inline bool
key_valid(const struct ulogd_key *key)
{
	return key != NULL && key->flags & ULOGD_RETF_VALID;
}

static inline bool
key_src_valid(const struct ulogd_key *key)
{
	return key_valid(key_src(key));
}

int ulogd_key_size(const struct ulogd_key *key);
struct ulogd_key *ulogd_alloc_keyset(int n, size_t priv_size);
struct ulogd_key *ulogd_key_find(const struct ulogd_keyset *,
								 const char *name);

/* plugin/pluginstance interface */
struct ulogd_pluginstance_stack;
struct ulogd_pluginstance;

/* will be incremented on each API change */
#define ULOGD_PLUGIN_REVISION	2

/* plugin flags */
#define ULOGD_PF_RECONF			0x00000001

struct ulogd_plugin {
	/* global list of plugins */
	struct llist_head list;

	/* revision number, incremented on API changes */
	unsigned rev;

	/* name of this plugin (set by plugin) */
	char name[ULOGD_MAX_KEYLEN+1];

	unsigned flags;

	const struct ulogd_keyset input;
	const struct ulogd_keyset output;

	/* called per packet, may return ULOGD_IRET_AGAIN */
	int (* interp)(struct ulogd_pluginstance *pi);

	/* may return ULOGD_IRET_AGAIN */
	int (* configure)(struct ulogd_pluginstance *pi,
					  struct ulogd_pluginstance_stack *stack);

	/* may return ULOGD_IRET_AGAIN */
	int (* start)(struct ulogd_pluginstance *pi);

	/* function to destruct an existing pluginstance */
	int (* stop)(struct ulogd_pluginstance *pi);

	/* function to receive a signal, may return ULOGD_IRET_AGAIN */
	int (* signal)(struct ulogd_pluginstance *pi, int signal);

	/* configuration parameters */
	const struct config_keyset *config_kset;

	/* size of instance->priv */
	unsigned priv_size;
};

#define ULOGD_IRET_ERR		-1
#define ULOGD_IRET_STOP		-2
#define ULOGD_IRET_AGAIN    -3	/* try again later */
#define ULOGD_IRET_OK		0

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
	PsConfiguring,
	PsConfigured,
	PsStarting,
	PsStarted,
	__PsMax = PsStarted
};

/* an instance of a plugin, element in a stack */
struct ulogd_pluginstance {
	/* local list of plugins in this stack */
	struct llist_head list;

	/* state dependant usage (e. g. restart handling) */
	struct llist_head state_link;

	enum UpiState state;

	struct ulogd_plugin *plugin;

	/* stack that we're part of */
	struct ulogd_pluginstance_stack *stack;

	/* name / id  of this instance*/
	char id[ULOGD_MAX_KEYLEN+1];

	/* per-instance input keys */
	struct ulogd_keyset input;

	/* per-instance output keys */
	struct ulogd_keyset output;

	/* per-instance config parameters (array) */
	struct config_keyset *config_kset;

	/* private data */
	char private[];
};

static inline void *
upi_priv(const struct ulogd_pluginstance *upi)
{
	return (void *)&upi->private;
}

/* stack flags */
#define ULOGD_SF_FSM			0x00000001		/* FSM running */

struct ulogd_pluginstance_stack {
	/* global list of pluginstance stacks */
	struct llist_head stack_list;

	/* list of plugins in this stack */
	struct llist_head list;

	unsigned flags;

	enum UpiState state;

	/* for state handling */
	struct llist_head state_link;

	char *name;
};

#define upi_log(pi, lvl, fmt, ...) \
	ulogd_log((lvl), "%s: " fmt, pi->id, ## __VA_ARGS__)

int upi_for_each(int (*)(struct ulogd_pluginstance *, void *), void *);

static inline void *
upi_key_priv(const struct ulogd_key *key)
{
	return key->priv;
}

/* register a new interpreter plugin */
void ulogd_register_plugin(struct ulogd_plugin *me);

struct ulogd_plugin *ulogd_find_plugin(const char *);

struct ulogd_pluginstance *ulogd_upi_alloc_init(struct ulogd_plugin *,
			const char *, struct ulogd_pluginstance_stack *);

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

int ulogd_wildcard_inputkeys(struct ulogd_pluginstance *upi);
void ulogd_propagate_results(struct ulogd_pluginstance *pi);

int ulogd_plugin_init(void);

void stack_add(struct ulogd_pluginstance_stack *);
bool stack_have_stacks(void);
int stack_for_each(int (*)(struct ulogd_pluginstance_stack *, void *),
				   void *);
int stack_fsm(struct ulogd_pluginstance_stack *);
int stack_reconfigure(struct ulogd_pluginstance_stack *);

#endif /* PLUGIN_H */
