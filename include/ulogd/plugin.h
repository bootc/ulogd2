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

#include <netinet/in.h>


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

struct ulogd_value {
	enum ulogd_ktype type;

	union {
		int8_t i8;
		int16_t i16;
		int32_t i32;
		int64_t i64;
		uint8_t b;
		uint8_t ui8;
		uint16_t ui16;
		uint32_t ui32;
		uint64_t ui64;
		void *ptr;
		char *str;
		struct in6_addr in6;
	};
};

int ulogd_value_to_ascii(const struct ulogd_value *, char *, size_t);


struct db_column;

/* structure describing an input  / output parameter of a plugin */
struct ulogd_key {
	union {
		struct ulogd_value val;
		struct ulogd_key *source;
	} u;

	uint16_t flags;

	/*
	 * Map to database column
	 */
	struct db_column *col;

	/* name of this key */
	char name[ULOGD_MAX_KEYLEN+1];

	/* IETF IPFIX attribute ID */
	struct {
		uint32_t	vendor;
		uint16_t	field_id;
	} ipfix;

	/* length of the returned value (for variable-length types) */
	uint32_t len;
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
#define KEY(t, n)						\
	{									\
		.u.val.type = ULOGD_RET_ ## t,	\
		.name = (n),					\
	}
#define KEY_FLAGS(t, n, fl)				\
	{									\
		.flags = (fl),					\
		.u.val.type = ULOGD_RET_ ## t,	\
		.name = (n),					\
	}
#define IPFIX(v, f)								\
	{											\
		.vendor = IPFIX_VENDOR_ ## v,			\
		.field_id = IPFIX_ ## f,				\
	}
#define KEY_IPFIX(t, n, v, f)				\
	{										\
		.u.val.type = ULOGD_RET_ ## t,		\
		.name = (n),						\
		.ipfix = IPFIX(v, f),				\
	}
#define KEY_IPFIX_FLAGS(t, n, v, f, fl)		\
	{										\
		.flags = (fl),						\
		.u.val.type = ULOGD_RET_ ## t,		\
		.name = (n),					\
		.ipfix = IPFIX(v, f),			\
	}

/* set key values */
void key_set_i8(struct ulogd_key *, int);
void key_set_i16(struct ulogd_key *, int);
void key_set_i32(struct ulogd_key *, int);
void key_set_u8(struct ulogd_key *, unsigned);
void key_set_u16(struct ulogd_key *, unsigned);
void key_set_u32(struct ulogd_key *, unsigned);
void key_set_i64(struct ulogd_key *, int64_t);
void key_set_u64(struct ulogd_key *, uint64_t);
void key_set_bool(struct ulogd_key *, bool);
void key_set_ptr(struct ulogd_key *, void *);
void key_set_str(struct ulogd_key *, char *);
void key_set_in6(struct ulogd_key *, const struct in6_addr *);

/* key accessors */
int key_i8(const struct ulogd_key *);
int key_i16(const struct ulogd_key *);
int key_i32(const struct ulogd_key *);
unsigned key_u8(const struct ulogd_key *);
unsigned key_u16(const struct ulogd_key *);
unsigned key_u32(const struct ulogd_key *);
int64_t key_i64(const struct ulogd_key *);
uint64_t key_u64(const struct ulogd_key *);
bool key_bool(const struct ulogd_key *);
void *key_ptr(const struct ulogd_key *);
char *key_str(const struct ulogd_key *);
void key_in6(const struct ulogd_key *, struct in6_addr *);

/* src key accessors */
int key_src_i8(const struct ulogd_key *);
int key_src_i16(const struct ulogd_key *);
int key_src_i32(const struct ulogd_key *);
unsigned key_src_u8(const struct ulogd_key *);
unsigned key_src_u16(const struct ulogd_key *);
unsigned key_src_u32(const struct ulogd_key *);
int64_t key_src_i64(const struct ulogd_key *);
uint64_t key_src_u64(const struct ulogd_key *);
bool key_src_bool(const struct ulogd_key *);
void *key_src_ptr(const struct ulogd_key *);
char *key_src_str(const struct ulogd_key *);
void key_src_in6(const struct ulogd_key *, struct in6_addr *);

enum ulogd_ktype key_type(const struct ulogd_key *);
bool key_type_eq(const struct ulogd_key *, const struct ulogd_key *);
void key_free(struct ulogd_key *key);
void key_reset(struct ulogd_key *key);

static inline struct ulogd_key *
key_src(const struct ulogd_key *key)
{
	return key->u.source;
}

static inline void
key_set_src(struct ulogd_key *key, struct ulogd_key *src_key)
{
	key->u.source = src_key;
}

static inline bool
key_valid(const struct ulogd_key *key)
{
	return key->flags & ULOGD_RETF_VALID;
}

static inline bool
key_src_valid(const struct ulogd_key *key)
{
	return key_valid(key_src(key));
}

int ulogd_key_size(const struct ulogd_key *key);
struct ulogd_key *ulogd_alloc_keyset(int n);
void ulogd_free_keyset(struct ulogd_keyset *);
void ulogd_dump_keyset(const struct ulogd_keyset *);
struct ulogd_key *ulogd_key_find(const struct ulogd_keyset *,
								 const char *name);

/* plugin/pluginstance interface */
struct ulogd_pluginstance_stack;
struct ulogd_pluginstance;

/* will be incremented on each API change */
#define ULOGD_PLUGIN_REVISION	2

/* plugin flags */
#define ULOGD_PF_RECONF			0x00000001

/* propagation flags */
#define ULOGD_PROP_FOLLOW		0x00000001 /* follow this propagation */

struct ulogd_plugin {
	/* global list of plugins */
	struct llist_head list;

	unsigned flags;

	const struct ulogd_keyset input;
	const struct ulogd_keyset output;

	/**
	 * Per-packet interpreter function
	 *
	 * Usually not used by input plugins, which usually ahve their own
	 * event sources.  You can use %flags to pass additional info
	 * to all downstream plugintances, which is currently only used
	 * for debugging.
	 *
	 * May return ULOGD_IRET_AGAIN.
	 */
	int (* interp)(struct ulogd_pluginstance *pi, unsigned *flags);

	/**
	 * Configuration handler for a %ulogd_pluginstance
	 *
	 * This function should be completely stateless as there currently
	 * is no %unconfigure handler.  Instead you should add such code
	 * to the %start handler of the plugin, which is called later.
	 *
	 * May return ULOGD_IRET_AGAIN.
	 */
	int (* configure)(struct ulogd_pluginstance *pi);

	/**
	 * Start a pluginstance
	 *
	 * May return ULOGD_IRET_AGAIN, in which case a start is triggered
	 * later.
	 */
	int (* start)(struct ulogd_pluginstance *pi);

	/**
	 * Stop an %ulogd_pluginstance
	 *
	 * Usually reverts everything which was done in the %start handler.
	 */
	int (* stop)(struct ulogd_pluginstance *pi);

	/**
	 * Signal handler for a %ulogd_pluginstance
	 *
	 * On error the plugin is stopped.  May return %ULOGD_IRET_AGAIN,
	 * in which case a restart is triggered later.
	 */
	int (* signal)(struct ulogd_pluginstance *pi, int signal);

	/* configuration parameters */
	const struct config_keyset *config_kset;

	/* name of this plugin (set by plugin) */
	const char *name;

	/* revision number, incremented on API changes */
	unsigned rev;

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
	return (void *)upi->private;
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

/* all plugin initializers should be tagged with this */
#define __upi_ctor		__attribute__((constructor))

#define upi_log(pi, lvl, fmt, ...) \
	ulogd_log((lvl), "%s: " fmt, pi->id, ## __VA_ARGS__)

int upi_for_each(int (*)(struct ulogd_pluginstance *, void *), void *);

/* register a new interpreter plugin */
void ulogd_register_plugin(struct ulogd_plugin *me);

struct ulogd_plugin *ulogd_find_plugin(const char *);

struct ulogd_pluginstance *ulogd_upi_alloc_init(struct ulogd_plugin *,
			const char *, struct ulogd_pluginstance_stack *);

int ulogd_upi_configure(struct ulogd_pluginstance *);
int ulogd_upi_start(struct ulogd_pluginstance *);
int ulogd_upi_stop(struct ulogd_pluginstance *);
int ulogd_upi_interp(struct ulogd_pluginstance *, unsigned *);
void ulogd_upi_signal(struct ulogd_pluginstance *, int);
int ulogd_upi_error(struct ulogd_pluginstance *, int);
void ulogd_upi_set_state(struct ulogd_pluginstance *, enum UpiState);
int ulogd_upi_reset_cfg(struct ulogd_pluginstance *);

int ulogd_upi_stop_all(void);

int ulogd_wildcard_inputkeys(struct ulogd_pluginstance *upi);
void ulogd_propagate_results(struct ulogd_pluginstance *pi, unsigned *flags);

int ulogd_plugin_init(void);

void stack_add(struct ulogd_pluginstance_stack *);
void stack_dump(const struct ulogd_pluginstance_stack *);
bool stack_have_stacks(void);
int stack_for_each(int (*)(struct ulogd_pluginstance_stack *, void *),
				   void *);
int stack_fsm(struct ulogd_pluginstance_stack *);
int stack_reconfigure(struct ulogd_pluginstance_stack *);

/* pluginstance config space API */
int ulogd_config_int(const struct ulogd_pluginstance *pi, int off);
char *ulogd_config_str(const struct ulogd_pluginstance *pi, int off);
void ulogd_config_set_int(struct ulogd_pluginstance *pi, int off, int v);
void ulogd_config_set_str(struct ulogd_pluginstance *pi, int off,
						  const char *str);

#endif /* PLUGIN_H */
