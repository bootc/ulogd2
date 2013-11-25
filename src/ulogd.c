/* ulogd
 *
 * unified network logging daemon for Linux.
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
 * (C) 2013 by Eric Leblond <eric@regit.org>
 * (C) 2013 Chris Boot <bootc@bootc.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Modifications:
 * 	14 Jun 2001 Martin Josefsson <gandalf@wlug.westbo.se>
 * 		- added SIGHUP handler for logfile cycling
 *
 * 	10 Feb 2002 Alessandro Bono <a.bono@libero.it>
 * 		- added support for non-fork mode
 * 		- added support for logging to stdout
 *
 * 	09 Sep 2003 Magnus Boden <sarek@ozaba.cx>
 * 		- added support for more flexible multi-section conffile
 *
 * 	20 Apr 2004 Nicolas Pougetoux <nicolas.pougetoux@edelweb.fr>
 * 		- added suppurt for seteuid()
 *
 * 	22 Jul 2004 Harald Welte <laforge@gnumonks.org>
 * 		- major restructuring for flow accounting / ipfix work
 *
 * 	03 Oct 2004 Harald Welte <laforge@gnumonks.org>
 * 		- further unification towards generic network event logging
 * 		  and support for lnstat
 *
 * 	07 Oct 2005 Harald Welte <laforge@gnumonks.org>
 * 		- finally get ulogd2 into a running state
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <ulogd/conffile.h>
#include <ulogd/ulogd.h>
#ifdef DEBUG
#define DEBUGP(format, args...) fprintf(stderr, format, ## args)
#else
#define DEBUGP(format, args...) 
#endif

#define COPYRIGHT \
	"(C) 2000-2006 Harald Welte <laforge@netfilter.org>\n" \
	"(C) 2008-2012 Pablo Neira Ayuso <pablo@netfilter.org>\n" \
	"(C) 2008-2012 Eric Leblond <eric@regit.org>\n"

/* global variables */
static FILE *logfile = NULL;		/* logfile pointer */
static char *ulogd_logfile = NULL;
static const char *ulogd_configfile = ULOGD_CONFIGFILE;
static const char *ulogd_pidfile = NULL;
static int ulogd_pidfile_fd = -1;
static FILE syslog_dummy;

static int info_mode = 0;

static int verbose = 0;
static int created_pidfile = 0;

/* linked list for all registered plugins */
static LLIST_HEAD(ulogd_plugins);
/* linked list for all plugins handle */
static LLIST_HEAD(ulogd_plugins_handle);
static LLIST_HEAD(ulogd_pi_stacks);


static int load_plugin(const char *file);
static int create_stack(const char *file);
static int logfile_open(const char *name);
static void cleanup_pidfile();

static struct config_keyset ulogd_kset = {
	.num_ces = 4,
	.ces = {
		{
			.key = "logfile",
			.type = CONFIG_TYPE_CALLBACK,
			.options = CONFIG_OPT_NONE,
			.u.parser = &logfile_open,
		},
		{
			.key = "plugin",
			.type = CONFIG_TYPE_CALLBACK,
			.options = CONFIG_OPT_MULTI,
			.u.parser = &load_plugin,
		},
		{
			.key = "loglevel", 
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = ULOGD_NOTICE,
		},
		{
			.key = "stack",
			.type = CONFIG_TYPE_CALLBACK,
			.options = CONFIG_OPT_MULTI,
			.u.parser = &create_stack,
		},
	},
};

#define logfile_ce	ulogd_kset.ces[0]
#define plugin_ce	ulogd_kset.ces[1]
#define loglevel_ce	ulogd_kset.ces[2]
#define stack_ce	ulogd_kset.ces[3]

/***********************************************************************
 * UTILITY FUNCTIONS FOR PLUGINS
 ***********************************************************************/

int ulogd_key_size(struct ulogd_key *key)
{
	int ret;

	switch (key->type) {
	case ULOGD_RET_INT8:
	case ULOGD_RET_UINT8:
	case ULOGD_RET_BOOL:
		ret = 1;
		break;
	case ULOGD_RET_INT16:
	case ULOGD_RET_UINT16:
		ret = 2;
		break;
	case ULOGD_RET_INT32:
	case ULOGD_RET_UINT32:
	case ULOGD_RET_IPADDR:
		ret = 4;
		break;
	case ULOGD_RET_INT64:
	case ULOGD_RET_UINT64:
		ret = 8;
		break;
	case ULOGD_RET_IP6ADDR:
		ret = 16;
		break;
	case ULOGD_RET_STRING:
		ret = strlen(key->u.value.ptr);
		break;
	case ULOGD_RET_RAW:
		ret = key->len;
		break;
	default:
		ulogd_log(ULOGD_ERROR, "don't know sizeof unknown key "
			  "`%s' type 0x%x\n", key->name, key->type);
		ret = -1;
		break;
	}

	return ret;
}

int ulogd_wildcard_inputkeys(struct ulogd_pluginstance *upi)
{
	struct ulogd_pluginstance_stack *stack = upi->stack;
	struct ulogd_pluginstance *pi_cur;
	unsigned int num_keys = 0;
	unsigned int index = 0;

	/* ok, this is a bit tricky, and probably requires some documentation.
	 * Since we are a output plugin (SINK), we can only be the last one
	 * in the stack.  Therefore, all other (input/filter) plugins, area
	 * already linked into the stack.  This means, we can iterate over them,
	 * get a list of all the keys, and create one input key for every output
	 * key that any of the upstream plugins provide.  By the time we resolve
	 * the inter-key pointers, everything will work as expected. */

	if (upi->input.keys)
		free(upi->input.keys);

	/* first pass: count keys */
	llist_for_each_entry(pi_cur, &stack->list, list) {
		ulogd_log(ULOGD_DEBUG, "iterating over pluginstance '%s'\n",
			  pi_cur->id);
		num_keys += pi_cur->plugin->output.num_keys;
	}

	ulogd_log(ULOGD_DEBUG, "allocating %u input keys\n", num_keys);
	upi->input.keys = malloc(sizeof(struct ulogd_key) * num_keys);
	if (!upi->input.keys)
		return -ENOMEM;

	/* second pass: copy key names */
	llist_for_each_entry(pi_cur, &stack->list, list) {
		unsigned int i;

		for (i = 0; i < pi_cur->plugin->output.num_keys; i++)
			upi->input.keys[index++] = pi_cur->output.keys[i];
	}

	upi->input.num_keys = num_keys;

	return 0;
}


/***********************************************************************
 * PLUGIN MANAGEMENT 
 ***********************************************************************/

/* try to lookup a registered plugin for a given name */
static struct ulogd_plugin *find_plugin(const char *name)
{
	struct ulogd_plugin *pl;

	llist_for_each_entry(pl, &ulogd_plugins, list) {
		if (strcmp(name, pl->name) == 0)
			return pl;
	}

	return NULL;
}

char *type_to_string(int type)
{
	switch (type) {
		case ULOGD_RET_INT8:
			return strdup("int 8");
			break;
		case ULOGD_RET_INT16:
			return strdup("int 16");
			break;
		case ULOGD_RET_INT32:
			return strdup("int 32");
			break;
		case ULOGD_RET_INT64:
			return strdup("int 64");
			break;
		case ULOGD_RET_UINT8:
			return strdup("unsigned int 8");
			break;
		case ULOGD_RET_UINT16:
			return strdup("unsigned int 16");
			break;
		case ULOGD_RET_UINT32:
			return strdup("unsigned int 32");
			break;
		case ULOGD_RET_UINT64:
			return strdup("unsigned int 64");
			break;
		case ULOGD_RET_BOOL:
			return strdup("boolean");
			break;
		case ULOGD_RET_IPADDR:
			return strdup("IP addr");
			break;
		case ULOGD_RET_STRING:
			return strdup("string");
			break;
		case ULOGD_RET_RAW:
			return strdup("raw data");
			break;
		default:
			return strdup("Unknown type");
	}
}


void get_plugin_infos(struct ulogd_plugin *me)
{
	unsigned int i;
	printf("Name: %s\n", me->name);
	if (me->config_kset) {
		printf("Config options:\n");
		for(i = 0; i < me->config_kset->num_ces; i++) {
			printf("\tVar: %s (", me->config_kset->ces[i].key);
			switch (me->config_kset->ces[i].type) {
				case CONFIG_TYPE_STRING:
					printf("String");
					printf(", Default: %s", 
					       me->config_kset->ces[i].u.string);
					break;
				case CONFIG_TYPE_INT:
					printf("Integer");
					printf(", Default: %d",
					       me->config_kset->ces[i].u.value);
					break;
				case CONFIG_TYPE_CALLBACK:
					printf("Callback");
					break;
				default:
					printf("Unknown");
					break;
			}
			if (me->config_kset->ces[i].options == 
						CONFIG_OPT_MANDATORY) {
				printf(", Mandatory");
			}
			printf(")\n");
		}
	}
	printf("Input keys:\n");
	if (me->input.type != ULOGD_DTYPE_SOURCE) {
		if (me->input.num_keys == 0) {
			printf("\tNo statically defined keys\n");
		} else {
			for(i = 0; i < me->input.num_keys; i++) {
				char *tstring = 
					type_to_string(me->input.keys[i].type);
				printf("\tKey: %s (%s",
				       me->input.keys[i].name,
				       tstring);
				if (me->input.keys[i].flags
						& ULOGD_KEYF_OPTIONAL)
					printf(", optional)\n");
				else
					printf(")\n");
				free(tstring);
			}
		}
	} else {
		printf("\tInput plugin, No keys\n");
	}
	printf("Output keys:\n");
	if (me->output.type != ULOGD_DTYPE_SINK) {
		if (me->output.num_keys == 0) {
			printf("\tNo statically defined keys\n");
		} else {
			for(i = 0; i < me->output.num_keys; i++) {
				char *tstring =
					type_to_string(me->output.keys[i].type);
				printf("\tKey: %s (%s)\n",
				       me->output.keys[i].name,
				       tstring);
				free(tstring);
			}
		}
	} else {
		printf("\tOutput plugin, No keys\n");
	}
}

/* the function called by all plugins for registering themselves */
void ulogd_register_plugin(struct ulogd_plugin *me)
{
	if (strcmp(me->version, VERSION)) { 
		ulogd_log(ULOGD_NOTICE, 
			  "plugin `%s' has incompatible version %s\n",
			  me->version);
		return;
	}
	if (info_mode == 0) {
		if (find_plugin(me->name)) {
			ulogd_log(ULOGD_NOTICE,
				  "plugin `%s' already registered\n",
				  me->name);
			exit(EXIT_FAILURE);
		}
		ulogd_log(ULOGD_DEBUG, "registering plugin `%s'\n", me->name);
		llist_add(&me->list, &ulogd_plugins);
	} else {
		get_plugin_infos(me);
	}
}

/***********************************************************************
 * MAIN PROGRAM
 ***********************************************************************/

static inline int ulogd2syslog_level(int level)
{
	int syslog_level = LOG_WARNING;

	switch (level) {
		case ULOGD_DEBUG:
			syslog_level = LOG_DEBUG;
			break;
		case ULOGD_INFO:
			syslog_level = LOG_INFO;
			break;
		case ULOGD_NOTICE:
			syslog_level = LOG_NOTICE;
			break;
		case ULOGD_ERROR:
			syslog_level = LOG_ERR;
			break;
		case ULOGD_FATAL:
			syslog_level = LOG_CRIT;
			break;
	}

	return syslog_level;
}

/* log message to the logfile */
void __ulogd_log(int level, char *file, int line, const char *format, ...)
{
	char *timestr;
	va_list ap;
	time_t tm;
	FILE *outfd;

	/* log only messages which have level at least as high as loglevel */
	if (level < loglevel_ce.u.value)
		return;

	if (logfile == &syslog_dummy) {
		/* FIXME: this omits the 'file' string */
		va_start(ap, format);
		vsyslog(ulogd2syslog_level(level), format, ap);
		va_end(ap);
	} else {
		if (logfile)
			outfd = logfile;
		else
			outfd = stderr;

		tm = time(NULL);
		timestr = ctime(&tm);
		timestr[strlen(timestr)-1] = '\0';
		fprintf(outfd, "%s <%1.1d> %s:%d ", timestr, level, file, line);
		if (verbose)
			fprintf(stderr, "%s <%1.1d> %s:%d ", timestr, level, file, line);


		va_start(ap, format);
		vfprintf(outfd, format, ap);
		va_end(ap);
		/* flush glibc's buffer */
		fflush(outfd);

		if (verbose) {
			va_start(ap, format);
			vfprintf(stderr, format, ap);
			va_end(ap);
			fflush(stderr);
		}

	}
}

static void warn_and_exit(int daemonize)
{
	cleanup_pidfile();

	if (!daemonize) {
		if (logfile && !verbose) {
			fprintf(stderr, "Fatal error, check logfile \"%s\""
				" or use '-v' flag.\n",
				ulogd_logfile);

		} else
			fprintf(stderr, "Fatal error.\n");
	}
exit(1);
}

/* clean results (set all values to 0 and free pointers) */
static void ulogd_clean_results(struct ulogd_pluginstance *pi)
{
	struct ulogd_pluginstance *cur;

	DEBUGP("cleaning up results\n");

	/* iterate through plugin stack */
	llist_for_each_entry(cur, &pi->stack->list, list) {
		unsigned int i;
		
		/* iterate through input keys of pluginstance */
		for (i = 0; i < cur->output.num_keys; i++) {
			struct ulogd_key *key = &cur->output.keys[i];

			if (!(key->flags & ULOGD_RETF_VALID))
				continue;

			if (key->flags & ULOGD_RETF_FREE) {
				free(key->u.value.ptr);
				key->u.value.ptr = NULL;
			}
			memset(&key->u.value, 0, sizeof(key->u.value));
			key->flags &= ~ULOGD_RETF_VALID;
		}
	}
}

/* propagate results to all downstream plugins in the stack */
void ulogd_propagate_results(struct ulogd_pluginstance *pi)
{
	struct ulogd_pluginstance *cur = pi;
	int abort_stack = 0;
	/* iterate over remaining plugin stack */
	llist_for_each_entry_continue(cur, &pi->stack->list, list) {
		int ret;
		
		ret = cur->plugin->interp(cur);
		switch (ret) {
		case ULOGD_IRET_ERR:
			ulogd_log(ULOGD_NOTICE,
				  "error during propagate_results\n");
			/* fallthrough */
		case ULOGD_IRET_STOP:
			/* we shall abort further iteration of the stack */
			abort_stack = 1;
			break;
		case ULOGD_IRET_OK:
			/* we shall continue travelling down the stack */
			continue;
		default:
			ulogd_log(ULOGD_NOTICE,
				  "unknown return value `%d' from plugin %s\n",
				  ret, cur->plugin->name);
			abort_stack = 1;
			break;
		}

		if (abort_stack)
			break;
	}

	ulogd_clean_results(pi);
}

static struct ulogd_pluginstance *
pluginstance_alloc_init(struct ulogd_plugin *pl, char *pi_id,
			struct ulogd_pluginstance_stack *stack)
{
	unsigned int size;
	struct ulogd_pluginstance *pi;
	void *ptr;

	size = sizeof(struct ulogd_pluginstance);
	size += pl->priv_size;
	if (pl->config_kset) {
		size += sizeof(struct config_keyset);
		if (pl->config_kset->num_ces)
			size += pl->config_kset->num_ces * 
						sizeof(struct config_entry);
	}
	size += pl->input.num_keys * sizeof(struct ulogd_key);
	size += pl->output.num_keys * sizeof(struct ulogd_key);
	pi = malloc(size);
	if (!pi)
		return NULL;

	/* initialize */
	memset(pi, 0, size);
	INIT_LLIST_HEAD(&pi->list);
	INIT_LLIST_HEAD(&pi->plist);
	pi->plugin = pl;
	pi->stack = stack;
	memcpy(pi->id, pi_id, sizeof(pi->id));

	ptr = (void *)pi + sizeof(*pi);

	ptr += pl->priv_size;
	/* copy config keys */
	if (pl->config_kset) {
		pi->config_kset = ptr;
		ptr += sizeof(struct config_keyset);
		pi->config_kset->num_ces = pl->config_kset->num_ces;
		if (pi->config_kset->num_ces) {
			ptr += pi->config_kset->num_ces 
						* sizeof(struct config_entry);
			memcpy(pi->config_kset->ces, pl->config_kset->ces, 
			       pi->config_kset->num_ces
						* sizeof(struct config_entry));
		}
	} else
		pi->config_kset = NULL;

	/* copy input keys */
	if (pl->input.num_keys) {
		pi->input.num_keys = pl->input.num_keys;
		pi->input.keys = ptr;
		memcpy(pi->input.keys, pl->input.keys, 
		       pl->input.num_keys * sizeof(struct ulogd_key));
		ptr += pl->input.num_keys * sizeof(struct ulogd_key);
	}
	
	/* copy input keys */
	if (pl->output.num_keys) {
		pi->output.num_keys = pl->output.num_keys;
		pi->output.keys = ptr;
		memcpy(pi->output.keys, pl->output.keys, 
		       pl->output.num_keys * sizeof(struct ulogd_key));
	}

	return pi;
}


/* plugin loader to dlopen() a plugins */
static int load_plugin(const char *file)
{
	void * handle;
	struct ulogd_plugin_handle *ph;
	if ((handle = dlopen(file, RTLD_NOW)) == NULL) {
		ulogd_log(ULOGD_ERROR, "load_plugin: '%s': %s\n", file,
			  dlerror());
		return -1;
	}

	ph = (struct ulogd_plugin_handle *) calloc(1, sizeof(*ph));
	ph->handle = handle;
	llist_add(&ph->list, &ulogd_plugins_handle);
	return 0;
}

/* find an output key in a given stack, starting at 'start' */
static struct ulogd_key *
find_okey_in_stack(char *name,
		   struct ulogd_pluginstance_stack *stack,
		   struct ulogd_pluginstance *start)
{
	struct ulogd_pluginstance *pi;

	llist_for_each_entry_reverse(pi, &start->list, list) {
		unsigned int i;

		if ((void *)&pi->list == &stack->list)
			return NULL;

		for (i = 0; i < pi->output.num_keys; i++) {
			struct ulogd_key *okey = &pi->output.keys[i];
			if (!strcmp(name, okey->name)) {
				ulogd_log(ULOGD_DEBUG, "%s(%s)\n",
					  pi->id, pi->plugin->name);
				return okey;
			}
		}
	}

	return NULL;
}

/* resolve key connections from bottom to top of stack */
static int
create_stack_resolve_keys(struct ulogd_pluginstance_stack *stack)
{
	int i = 0;
	struct ulogd_pluginstance *pi_cur;

	/* pre-configuration pass */
	llist_for_each_entry_reverse(pi_cur, &stack->list, list) {
		ulogd_log(ULOGD_DEBUG, "traversing plugin `%s'\n", 
			  pi_cur->plugin->name);
		/* call plugin to tell us which keys it requires in
		 * given configuration */
		if (pi_cur->plugin->configure) {
			int ret = pi_cur->plugin->configure(pi_cur, 
							    stack);
			if (ret < 0) {
				ulogd_log(ULOGD_ERROR, "error during "
					  "configure of plugin %s\n",
					  pi_cur->plugin->name);
				return ret;
			}
		}
	}

	/* PASS 2: */
	ulogd_log(ULOGD_DEBUG, "connecting input/output keys of stack:\n");
	llist_for_each_entry_reverse(pi_cur, &stack->list, list) {
		struct ulogd_pluginstance *pi_prev =
					llist_entry(pi_cur->list.prev,
						   struct ulogd_pluginstance,
						   list);
		i++;
		ulogd_log(ULOGD_DEBUG, "traversing plugin `%s'\n",
			  pi_cur->plugin->name);

		if (i == 1) {
			/* first round: output plugin */
			if (!(pi_cur->plugin->output.type & ULOGD_DTYPE_SINK)) {
				ulogd_log(ULOGD_ERROR, "last plugin in stack "
					  "has to be output plugin\n");
				return -EINVAL;
			}
			/* continue further down */
		} /* no "else' since first could be the last one, too ! */

		if (&pi_prev->list == &stack->list) {
			/* this is the last one in the stack */
			if (!(pi_cur->plugin->input.type 
						& ULOGD_DTYPE_SOURCE)) {
				ulogd_log(ULOGD_ERROR, "first plugin in stack "
					  "has to be source plugin\n");
				return -EINVAL;
			}
			/* no need to match keys */
		} else {
			unsigned int j;

			/* not the last one in the stack */
			if (!(pi_cur->plugin->input.type &
					pi_prev->plugin->output.type)) {
				ulogd_log(ULOGD_ERROR, "type mismatch between "
					  "%s and %s in stack\n",
					  pi_cur->plugin->name,
					  pi_prev->plugin->name);
			}
	
			for (j = 0; j < pi_cur->input.num_keys; j++) {
				struct ulogd_key *okey;
				struct ulogd_key *ikey = &pi_cur->input.keys[j];

				/* skip those marked as 'inactive' by
				 * pl->configure() */
				if (ikey->flags & ULOGD_KEYF_INACTIVE)
					continue;

				if (ikey->u.source) { 
					ulogd_log(ULOGD_ERROR, "input key `%s' "
						  "already has source\n",
						  ikey->name);

					return -EINVAL;
				}

				okey = find_okey_in_stack(ikey->name, 
							  stack, pi_cur);
				if (!okey) {
					if (ikey->flags & ULOGD_KEYF_OPTIONAL)
						continue;
					ulogd_log(ULOGD_ERROR, "cannot find "
						  "key `%s' in stack\n",
						  ikey->name);
					return -EINVAL;
				}

				ulogd_log(ULOGD_DEBUG, "assigning `%s(?)' as "
					  "source for %s(%s)\n", okey->name,
					  pi_cur->plugin->name, ikey->name);
				ikey->u.source = okey;
			}
		}
	}

	return 0;
}

/* iterate on already defined stack to find a plugininstance matching */
static int pluginstance_started(struct ulogd_pluginstance *npi)
{
	struct ulogd_pluginstance_stack *stack;
	struct ulogd_pluginstance *pi;

	/* Only SOURCE plugin need to be started once */
	if (npi->plugin->input.type == ULOGD_DTYPE_SOURCE) {
		llist_for_each_entry(stack, &ulogd_pi_stacks, stack_list) {
			llist_for_each_entry(pi, &stack->list, list) {
				if (!strcmp(pi->id, npi->id)) {
					ulogd_log(ULOGD_INFO,
							"%s instance already "
							"loaded\n", pi->id);
					llist_add(&npi->plist, &pi->plist);
					return 1;
				}
			}
		}
	}
	return 0;
}

static int pluginstance_stop(struct ulogd_pluginstance *npi)
{
	if (--npi->plugin->usage > 0 &&
	    npi->plugin->input.type == ULOGD_DTYPE_SOURCE) {
		return 0;
	}
	return 1;
}

static int create_stack_start_instances(struct ulogd_pluginstance_stack *stack)
{
	int ret;
	struct ulogd_pluginstance *pi;

	/* start from input to output plugin */
	llist_for_each_entry(pi, &stack->list, list) {
		if (!pi->plugin->start)
			continue;

		/* only call start if a plugin with same ID was not started */
		if (!pluginstance_started(pi)) {
			ret = pi->plugin->start(pi);
			if (ret < 0) {
				ulogd_log(ULOGD_ERROR, 
					  "error starting `%s'\n",
					  pi->id);
				return ret;
			}
		}
	}
	return 0;
}

/* create a new stack of plugins */
static int create_stack(const char *option)
{
	struct ulogd_pluginstance_stack *stack;
	char *buf = strdup(option);
	char *tok;
	int ret;

	if (!buf) {
		ulogd_log(ULOGD_ERROR, "");
		ret = -ENOMEM;
		goto out_buf;
	}

	stack = malloc(sizeof(*stack));
	if (!stack) {
		ret = -ENOMEM;
		goto out_stack;
	}
	INIT_LLIST_HEAD(&stack->list);

	ulogd_log(ULOGD_NOTICE, "building new pluginstance stack: '%s'\n",
		  option);

	/* PASS 1: find and instanciate plugins of stack, link them together */
	for (tok = strtok(buf, ",\n"); tok; tok = strtok(NULL, ",\n")) {
		char *plname, *equals;
		char pi_id[ULOGD_MAX_KEYLEN];
		struct ulogd_pluginstance *pi;
		struct ulogd_plugin *pl;

		ulogd_log(ULOGD_DEBUG, "tok=`%s'\n", tok);

		/* parse token into sub-tokens */
		equals = strchr(tok, ':');
		if (!equals || (equals - tok >= ULOGD_MAX_KEYLEN)) {
			ulogd_log(ULOGD_ERROR, "syntax error while parsing `%s'"
				  "of line `%s'\n", tok, buf);
			ret = -EINVAL;
			goto out;
		}
		strncpy(pi_id, tok, ULOGD_MAX_KEYLEN-1);
		pi_id[equals-tok] = '\0';
		plname = equals+1;
	
		/* find matching plugin */
		pl = find_plugin(plname);
		if (!pl) {
			ulogd_log(ULOGD_ERROR, "can't find requested plugin "
				  "%s\n", plname);
			ret = -ENODEV;
			goto out;
		}
		pl->usage++;

		/* allocate */
		pi = pluginstance_alloc_init(pl, pi_id, stack);
		if (!pi) {
			ulogd_log(ULOGD_ERROR, 
				  "unable to allocate pluginstance for %s\n",
				  pi_id);
			ret = -ENOMEM;
			goto out;
		}
	
		/* FIXME: call constructor routine from end to beginning,
		 * fix up input/output keys */
			
		ulogd_log(ULOGD_DEBUG, "pushing `%s' on stack\n", pl->name);
		llist_add_tail(&pi->list, &stack->list);
	}

	/* PASS 2: resolve key connections from bottom to top of stack */
	ret = create_stack_resolve_keys(stack);
	if (ret < 0) {
		ulogd_log(ULOGD_DEBUG, "destroying stack\n");
		goto out;
	}

	/* PASS 3: start each plugin in stack */
	ret = create_stack_start_instances(stack);
	if (ret < 0) {
		ulogd_log(ULOGD_DEBUG, "destroying stack\n");
		goto out;
	}

	/* add head of pluginstance stack to list of stacks */
	llist_add(&stack->stack_list, &ulogd_pi_stacks);
	free(buf);
	return 0;

out:
	free(stack);
out_stack:
	free(buf);
out_buf:
	return ret;
}
	

static void ulogd_main_loop(void)
{
	int ret;
	struct timeval next_alarm;
	struct timeval *next = NULL;

	while (1) {
		/* XXX: signal blocking? */
		if (next != NULL && !timerisset(next))
			next = ulogd_do_timer_run(&next_alarm);
		else
			next = ulogd_get_next_timer_run(&next_alarm);

		ret = ulogd_select_main(next);
		if (ret < 0 && errno != EINTR)
	                ulogd_log(ULOGD_ERROR, "select says %s\n",
				  strerror(errno));
	}
}

/* open the logfile */
static int logfile_open(const char *name)
{
	if (name) {
	        free(ulogd_logfile);
		ulogd_logfile = strdup(name);
	}

	if (!strcmp(name, "stdout")) {
		logfile = stdout;
	} else if (!strcmp(name, "syslog")) {
		openlog("ulogd", LOG_PID, LOG_DAEMON);
		logfile = &syslog_dummy;
	} else {
		logfile = fopen(ulogd_logfile, "a");
		if (!logfile) {
			fprintf(stderr, "ERROR: can't open logfile '%s': %s\n", 
				name, strerror(errno));
			exit(2);
		}
	}
	ulogd_log(ULOGD_INFO, "ulogd Version %s (re-)starting\n", VERSION);
	return 0;
}

/* wrapper to handle conffile error codes */
static int parse_conffile(const char *section, struct config_keyset *ce)
{
	int err;

	err = config_parse_file(section, ce);

	switch(err) {
		case 0:
			return 0;
			break;
		case -ERROPEN:
			ulogd_log(ULOGD_ERROR,
				"unable to open configfile: %s\n",
				ulogd_configfile);
			break;
		case -ERRMAND:
			ulogd_log(ULOGD_ERROR,
				"mandatory option \"%s\" not found\n",
				config_errce->key);
			break;
		case -ERRMULT:
			ulogd_log(ULOGD_ERROR,
				"option \"%s\" occurred more than once\n",
				config_errce->key);
			break;
		case -ERRUNKN:
			ulogd_log(ULOGD_ERROR,
				"unknown config key \"%s\"\n",
				config_errce->key);
			break;
		case -ERRSECTION:
			ulogd_log(ULOGD_ERROR,
				"section \"%s\" not found\n", section);
			break;
		case -ERRTOOLONG:
			if (config_errce->key)
				ulogd_log(ULOGD_ERROR,
					  "string value too long for key \"%s\"\n",
					  config_errce->key);
			else
				ulogd_log(ULOGD_ERROR,
					  "string value is too long\n");
			break;
	}
	return 1;
}

/*
 * Apply F_WRLCK to fd using fcntl().
 *
 * This function is copied verbatim from atd's daemon.c file, published under
 * the GPL2+ license with the following copyright statement:
 * Copyright (C) 1996 Thomas Koenig
 */
static int lock_fd(int fd, int wait)
{
	struct flock lock;

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (wait)
		return fcntl(fd, F_SETLKW, &lock);
	else
		return fcntl(fd, F_SETLK, &lock);
}

/*
 * Manage ulogd's pidfile.
 *
 * This function is based on atd's daemon.c:daemon_setup() function, published
 * under the GPL2+ license with the following copyright statement:
 * Copyright (C) 1996 Thomas Koenig
 */
static int create_pidfile()
{
	int fd;
	FILE *fp;
	pid_t pid = -1;

	if (!ulogd_pidfile)
		return 0;

	fd = open(ulogd_pidfile, O_RDWR | O_CREAT | O_EXCL, 0644);
	if (fd < 0) {
		if (errno != EEXIST) {
			ulogd_log(ULOGD_ERROR, "cannot open %s: %d\n",
					ulogd_pidfile, errno);
			return -1;
		}

		fd = open(ulogd_pidfile, O_RDWR);
		if (fd < 0) {
			ulogd_log(ULOGD_ERROR, "cannot open %s: %d\n",
					ulogd_pidfile, errno);
			return -1;
		}

		fp = fdopen(fd, "rw");
		if (fp == NULL) {
			ulogd_log(ULOGD_ERROR, "cannot fdopen %s: %d\n",
					ulogd_pidfile, errno);
			close(fd);
			return -1;
		}

		if ((fscanf(fp, "%d", &pid) != 1) || (pid == getpid())
				|| (lock_fd(fd, 0) == 0)) {
			ulogd_log(ULOGD_NOTICE,
				  "removing stale pidfile for pid %d\n", pid);

			if (unlink(ulogd_pidfile) < 0) {
				ulogd_log(ULOGD_ERROR, "cannot unlink %s: %d\n",
						ulogd_pidfile, errno);
				return -1;
			}
		} else {
			ulogd_log(ULOGD_FATAL,
				"another ulogd already running with pid %d\n",
				pid);
			fclose(fp);
			close(fd);
			return -1;
		}

		close(fd);
		fclose(fp);
		unlink(ulogd_pidfile);

		fd = open(ulogd_pidfile, O_RDWR | O_CREAT | O_EXCL, 0644);

		if (fd < 0) {
			ulogd_log(ULOGD_ERROR,
				"cannot open %s (2nd time round): %d\n",
				ulogd_pidfile, errno);
			return -1;
		}
	}

	if (lock_fd(fd, 0) < 0) {
		ulogd_log(ULOGD_ERROR, "cannot lock %s: %s\n", ulogd_pidfile,
				strerror(errno));
		close(fd);
		return -1;
	}
	ulogd_pidfile_fd = fd;
	return 0;
}

static int write_pidfile(int daemonize)
{
	FILE *fp;
	if (!ulogd_pidfile)
		return 0;

	if (ulogd_pidfile_fd == -1) {
		ulogd_log(ULOGD_ERROR, "unset pid file fd\n");
		return -1;
	}

	if (daemonize) {
		/* relocking as lock is not inherited */
		if (lock_fd(ulogd_pidfile_fd, 1) < 0) {
			ulogd_log(ULOGD_ERROR, "cannot lock %s: %d\n", ulogd_pidfile,
					errno);
			close(ulogd_pidfile_fd);
			return -1;
		}
	}

	fp = fdopen(ulogd_pidfile_fd, "w");
	if (fp == NULL) {
		ulogd_log(ULOGD_ERROR, "cannot fdopen %s: %d\n", ulogd_pidfile,
				errno);
		close(ulogd_pidfile_fd);
		return -1;
	}

	fprintf(fp, "%d\n", getpid());
	fflush(fp);

	if (ftruncate(fileno(fp), ftell(fp)) < 0)
		ulogd_log(ULOGD_NOTICE, "cannot ftruncate %s: %d\n",
				ulogd_pidfile, errno);

	/*
	 * We do NOT close fd, since we want to keep the lock. However, we don't
	 * want to keep the file descriptor in case of an exec().
	 */
	fcntl(ulogd_pidfile_fd, F_SETFD, FD_CLOEXEC);

	created_pidfile = 1;

	return 0;
}

static void cleanup_pidfile()
{
	if (!ulogd_pidfile || !created_pidfile)
		return;

	if (unlink(ulogd_pidfile) != 0)
		ulogd_log(ULOGD_ERROR, "PID file %s could not be deleted: %d\n",
				ulogd_pidfile, errno);
}

static void deliver_signal_pluginstances(int signal)
{
	struct ulogd_pluginstance_stack *stack;
	struct ulogd_pluginstance *pi;

	llist_for_each_entry(stack, &ulogd_pi_stacks, stack_list) {
		llist_for_each_entry(pi, &stack->list, list) {
			if (pi->plugin->signal)
				(*pi->plugin->signal)(pi, signal);
		}
	}
}

static void stop_pluginstances()
{
	struct ulogd_pluginstance_stack *stack;
	struct ulogd_pluginstance *pi, *npi;

	llist_for_each_entry(stack, &ulogd_pi_stacks, stack_list) {
		llist_for_each_entry_safe(pi, npi, &stack->list, list) {
			if ((pi->plugin->priv_size > 0 || *pi->plugin->stop) &&
			    pluginstance_stop(pi)) {
				ulogd_log(ULOGD_DEBUG, "calling stop for %s\n",
					  pi->plugin->name);
				(*pi->plugin->stop)(pi);
				pi->private[0] = 0;
			}
			free(pi);
		}
	}
}

#ifndef DEBUG_VALGRIND
static void unload_plugins()
{
	struct ulogd_plugin_handle *ph, *nph;
	llist_for_each_entry_safe(ph, nph, &ulogd_plugins_handle, list) {
		dlclose(ph->handle);
		free(ph);
	}
}
#endif

static void stop_stack()
{
	struct ulogd_pluginstance_stack *stack, *nstack;

	llist_for_each_entry_safe(stack, nstack, &ulogd_pi_stacks, stack_list) {
		free(stack);
	}
}


static void sigterm_handler(int signal)
{

	ulogd_log(ULOGD_NOTICE, "Terminal signal received, exiting\n");

	deliver_signal_pluginstances(signal);

	stop_pluginstances();

	stop_stack();

#ifndef DEBUG_VALGRIND
	unload_plugins();
#endif

	if (logfile != NULL  && logfile != stdout && logfile != &syslog_dummy) {
		fclose(logfile);
		logfile = NULL;
	}

	if (ulogd_logfile)
		free(ulogd_logfile);

	config_stop();

	cleanup_pidfile();

	exit(0);
}

static void signal_handler(int signal)
{
	ulogd_log(ULOGD_NOTICE, "signal received, calling pluginstances\n");
	
	switch (signal) {
	case SIGHUP:
		/* reopen logfile */
		if (logfile != stdout && logfile != &syslog_dummy) {
			fclose(logfile);
			logfile = fopen(ulogd_logfile, "a");
 			if (!logfile) {
				fprintf(stderr, 
					"ERROR: can't open logfile %s: %s\n", 
					ulogd_logfile, strerror(errno));
				sigterm_handler(signal);
			}
	
		}
		break;
	default:
		break;
	}

	deliver_signal_pluginstances(signal);
}

static void print_usage(void)
{
	printf("ulogd Version %s\n", VERSION);
	printf(COPYRIGHT);
	printf("This is free software with ABSOLUTELY NO WARRANTY.\n\n");
	printf("Parameters:\n");
	printf("\t-h --help\tThis help page\n");
	printf("\t-V --version\tPrint version information\n");
	printf("\t-d --daemon\tDaemonize (fork into background)\n");
	printf("\t-v --verbose\tOutput info on standard output\n");
	printf("\t-l --loglevel\tSet log level\n");
	printf("\t-c --configfile\tUse alternative Configfile\n");
	printf("\t-p --pidfile\tRecord ulogd PID in file\n");
	printf("\t-u --uid\tChange UID/GID\n");
	printf("\t-i --info\tDisplay infos about plugin\n");
}

static struct option opts[] = {
	{ "version", 0, NULL, 'V' },
	{ "daemon", 0, NULL, 'd' },
	{ "help", 0, NULL, 'h' },
	{ "configfile", 1, NULL, 'c'},
	{ "uid", 1, NULL, 'u' },
	{ "info", 1, NULL, 'i' },
	{ "verbose", 0, NULL, 'v' },
	{ "loglevel", 1, NULL, 'l' },
	{ "pidfile", 1, NULL, 'p' },
	{NULL, 0, NULL, 0}
};

int main(int argc, char* argv[])
{
	int argch;
	int daemonize = 0;
	int change_uid = 0;
	char *user = NULL;
	struct passwd *pw;
	uid_t uid = 0;
	gid_t gid = 0;
	int loglevel = 0;

	ulogd_logfile = strdup(ULOGD_LOGFILE_DEFAULT);

	while ((argch = getopt_long(argc, argv, "c:p:dvl:h::Vu:i:", opts, NULL)) != -1) {
		switch (argch) {
		default:
		case '?':
			if (isprint(optopt))
				fprintf(stderr, "Unknown option `-%c'.\n", 
					optopt);
			else
				fprintf(stderr, "Unknown option character "
					"`\\x%x'.\n", optopt);

			print_usage();
			exit(1);
			break;
		case 'h':
			print_usage();
			exit(0);
			break;
		case 'd':
			daemonize = 1;
			break;
		case 'V':
			printf("ulogd Version %s\n", VERSION);
			printf(COPYRIGHT);
			exit(0);
			break;
		case 'c':
			ulogd_configfile = optarg;
			break;
		case 'p':
			ulogd_pidfile = optarg;
			break;
		case 'u':
			change_uid = 1;
			user = strdup(optarg);
			pw = getpwnam(user);
			if (!pw) {
				printf("Unknown user %s.\n", user);
				free(user);
				exit(1);
			}
			uid = pw->pw_uid;
			gid = pw->pw_gid;
			break;
		case 'i':
			info_mode = 1;
			load_plugin(optarg);
			exit(0);
			break;
		case 'v':
			verbose = 1;
			break;
		case 'l':
			loglevel = atoi(optarg);
			break;
		}
	}

	/* command line has precedence on config file */
	if (loglevel)
		loglevel_ce.u.value = loglevel;
		loglevel_ce.flag |= CONFIG_FLAG_VAL_PROTECTED;

	if (ulogd_pidfile) {
		if (create_pidfile() < 0)
			warn_and_exit(0);
	}

	if (daemonize && verbose) {
		verbose = 0;
		ulogd_log(ULOGD_ERROR,
		          "suppressing verbose output (not compatible"
			  " with daemon mode).\n");
	}

	if (daemonize){
		if (daemon(0, 0) < 0) {
			ulogd_log(ULOGD_FATAL, "can't daemonize: %s (%d)",
				  errno, strerror(errno));
			warn_and_exit(daemonize);
		}
	}

	if (ulogd_pidfile) {
		if (write_pidfile(daemonize) < 0)
			warn_and_exit(0);
	}

	if (config_register_file(ulogd_configfile)) {
		ulogd_log(ULOGD_FATAL, "error registering configfile \"%s\"\n",
			  ulogd_configfile);
		warn_and_exit(daemonize);
	}

	/* parse config file */
	if (parse_conffile("global", &ulogd_kset)) {
		ulogd_log(ULOGD_FATAL, "unable to parse config file\n");
		warn_and_exit(daemonize);
	}

	if (llist_empty(&ulogd_pi_stacks)) {
		ulogd_log(ULOGD_FATAL, 
			  "not even a single working plugin stack\n");
		warn_and_exit(daemonize);
	}

	errno = 0;
	if (nice(-1) == -1) {
		if (errno != 0)
			ulogd_log(ULOGD_ERROR, "Could not nice process: %s\n",
				  strerror(errno));
	}

	if (change_uid) {
		ulogd_log(ULOGD_NOTICE, "Changing UID / GID\n");
		if (setgid(gid)) {
			ulogd_log(ULOGD_FATAL, "can't set GID %u\n", gid);
			warn_and_exit(daemonize);
		}
		if (setegid(gid)) {
			ulogd_log(ULOGD_FATAL, "can't set effective GID %u\n",
				  gid);
			warn_and_exit(daemonize);
		}
		if (initgroups(user, gid)) {
			ulogd_log(ULOGD_FATAL, "can't set user secondary GID\n");
			warn_and_exit(daemonize);
		}
		if (setuid(uid)) {
			ulogd_log(ULOGD_FATAL, "can't set UID %u\n", uid);
			warn_and_exit(daemonize);
		}
		if (seteuid(uid)) {
			ulogd_log(ULOGD_FATAL, "can't set effective UID %u\n",
				  uid);
			warn_and_exit(daemonize);
		}
	}

	signal(SIGTERM, &sigterm_handler);
	signal(SIGINT, &sigterm_handler);
	signal(SIGHUP, &signal_handler);
	signal(SIGALRM, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);

	ulogd_log(ULOGD_INFO, 
		  "initialization finished, entering main loop\n");

	ulogd_main_loop();

	/* hackish, but result is the same */
	sigterm_handler(SIGTERM);	
	return(0);
}
