/* config file parser functions
 *
 * (C) 2000 by Harald Welte <laforge@gnumonks.org>
 *
 * $Id$
 * 
 * This code is distributed under the terms of GNU GPL */

#ifndef _CONFFILE_H
#define _CONFFILE_H

#include <sys/types.h>

/* errors returned by config functions */
enum {
	ERRNONE = 0,
	ERROPEN,	/* unable to open config file */
	ERROOM,		/* out of memory */
	ERRMULT,	/* non-multiple option occured more  than once */
	ERRMAND,	/* mandatory option not found */
	ERRUNKN,	/* unknown config key */
	ERRSECTION,	/* section not found */
	ERRPLUGIN,	/* plugin error */
};

/* maximum line lenght of config file entries */
#define LINE_LEN 		255

/* maximum lenght of config key name */
#define CONFIG_KEY_LEN		30

/* valid config types */
#define CONFIG_TYPE_INT		0x0001
#define CONFIG_TYPE_STRING	0x0002
#define CONFIG_TYPE_CALLBACK	0x0003

/* valid config options */
#define CONFIG_OPT_NONE		0x0000
#define CONFIG_OPT_MANDATORY	0x0001
#define CONFIG_OPT_MULTI	0x0002

struct config_entry {
	char key[CONFIG_KEY_LEN];	/* name of config directive */
	u_int8_t type;			/* type; see above */
	u_int8_t options;		/* options; see above  */
	u_int8_t hit;			/* found? */
	union {
		char *string;
		int value;
		int (*parser)(const char *argstr);
	} u;
};

/**
 * config key initializers
 */
#define __CONFIG_KEY_INT(k, o, v) {				\
			.key = k,							\
			.type = CONFIG_TYPE_INT,			\
			.options = o,						\
			.u.value = v,						\
		}
#define CONFIG_KEY_INT(k, v)			__CONFIG_KEY_INT(k, 0, v)
#define CONFIG_KEY_INT_OPTS(k, o, v)	__CONFIG_KEY_INT(k, o, v)

#define __CONFIG_KEY_STR(k, o, s) {				\
			.key = k,							\
			.type = CONFIG_TYPE_STRING,			\
			.options = o,						\
			.u.string = s,						\
		}
#define CONFIG_KEY_STR(k, s)			__CONFIG_KEY_STR(k, 0, s)
#define CONFIG_KEY_STR_OPTS(k, o, s)	__CONFIG_KEY_STR(k, o, s)

#define __CONFIG_KEY_CALLBACK(k, o, c) {		\
			.key = k,							\
			.type = CONFIG_TYPE_CALLBACK,		\
			.options = o,						\
			.u.parser = c,						\
		}
#define CONFIG_KEY_CALLBACK(k, c)			__CONFIG_KEY_CALLBACK(k, 0, c)
#define CONFIG_KEY_CALLBACK_OPTS(k, o, c)	__CONFIG_KEY_CALLBACK(k, o, c)

#define CONFIG_KEY(k, t, o) {			\
			.key = k,					\
			.type = CONFIG_TYPE_ ## t,	\
			.options = o,				\
		}

struct config_keyset {
	unsigned int num_ces;
	struct config_entry ces[];
};

/* if an error occurs, config_errce is set to the erroneous ce */
extern struct config_entry *config_errce;

/* tell us the name of the config file */
int config_register_file(const char *file);

/* parse the config file */
int config_parse_file(const char *section, struct config_keyset *kset);

#endif /* ifndef _CONFFILE_H */
