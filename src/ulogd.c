/* ulogd, Version $LastChangedRevision$
 *
 * $Id$
 *
 * unified network logging daemon for Linux.
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
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
#include "config.h"
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/plugin.h>
#include <ulogd/conffile.h>
#include <ulogd/signal.h>
#include <ulogd/ifi.h>

#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <dirent.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <pthread.h>
#include <syslog.h>

#define COPYRIGHT \
	"Copyright (C) 2000-2005 Harald Welte <laforge@netfilter.org>\n"

/* global variables */
static FILE *logfile;
static char *ulogd_configfile = ULOGD_CONFIGFILE;
static char *ulogd_logfile = ULOGD_LOGFILE_DEFAULT;
static char pid_file[PATH_MAX] = "/var/run/ulogd.pid";
static enum GlobalState state;

static int load_plugin(const char *file);
static int create_stack(const char *file);
static int logfile_open(const char *name);

static struct config_keyset ulogd_kset = {
	.num_ces = 4,
	.ces = {
		{
			.key = "logfile",
			.type = CONFIG_TYPE_CALLBACK,
			.options = CONFIG_OPT_NONE,
			.u.string = ULOGD_LOGFILE_DEFAULT,
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


void
ulogd_set_state(enum GlobalState s)
{
	state = s;
}

enum GlobalState
ulogd_get_state(void)
{
	return state;
}

/***********************************************************************
 * MAIN PROGRAM
 ***********************************************************************/
static const int
ulogd2syslog_loglevel[] = {
	[ULOGD_DEBUG] = LOG_DEBUG,
	[ULOGD_INFO] = LOG_INFO,
	[ULOGD_NOTICE] = LOG_NOTICE,
	[ULOGD_ERROR] = LOG_ERR,
	[ULOGD_FATAL] = LOG_CRIT,
};

/* log message to the logfile */
void
__ulogd_log(enum ulogd_loglevel level, const char *file, int line,
			const char *fmt, ...)
{
	va_list ap;

	/* log only messages which have level at least as high as loglevel */
	if (level < loglevel_ce.u.value)
		return;

	if (logfile == NULL) {
		va_start(ap, fmt);
		vsyslog(ulogd2syslog_loglevel[level], fmt, ap);
		va_end(ap);

		return;
	}
}

void
__ulogd_abort(const char *file, int line, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	/* __ulogd_log(ULOGD_FATAL, fmt, ap); */

	va_end(ap);

	/* TODO backtrace */

	abort();
}

/* plugin loader to dlopen() a plugins */
static int
load_plugin(const char *file)
{
	if (dlopen(file, RTLD_NOW) == NULL) {
		ulogd_log(ULOGD_ERROR, "%s: %s\n", file, dlerror());
		return -1;
	}

	return 0;
}

static int
create_stack(const char *option)
{
	struct ulogd_pluginstance_stack *stack;
	char *buf = strdup(option);
	char *tok;
	int ret;

	if (buf == NULL) {
		ulogd_log(ULOGD_ERROR, "%s: out of memory\n", __func__);
		ret = -ENOMEM;
		goto out_buf;
	}

	stack = malloc(sizeof(*stack));
	if (!stack) {
		ret = -ENOMEM;
		goto out_stack;
	}
	INIT_LLIST_HEAD(&stack->list);
	stack->state = PsInit;

	ulogd_log(ULOGD_DEBUG, "building new pluginstance stack (%s):\n",
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
 		pl = ulogd_find_plugin(plname);
		if (!pl) {
			ulogd_log(ULOGD_ERROR, "can't find requested plugin "
				  "%s\n", plname);
			ret = -ENODEV;
			goto out;
		}

		/* allocate */
		pi = ulogd_upi_alloc_init(pl, pi_id, stack);
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

	if (stack_fsm(stack) < 0)
		goto out;

	stack_add(stack);

	free(buf);

	return 0;

out:
	free(stack);
out_stack:
	free(buf);
out_buf:
	return ret;
}

static int logfile_open(const char *name)
{
	if (name)
		ulogd_logfile = (char *)name;

	if (!strcmp(name, "stdout"))
		logfile = stdout;
	else if (strcmp(name, "syslog") == 0)
		logfile = NULL;
	else {
		logfile = fopen(ulogd_logfile, "a");
		if (!logfile) {
			fprintf(stderr, "ERROR: can't open logfile %s: %s\n", 
				name, strerror(errno));
			exit(2);
		}
	}

	ulogd_log(ULOGD_INFO, "ulogd Version %s starting\n", VERSION);

	return 0;
}

/* wrapper to handle conffile error codes */
static int
parse_conffile(const char *section, struct config_keyset *ce)
{
	int err;

	err = config_parse_file(section, ce);
	if (err == 0)
		return 0;

	switch (-err) {
	case ERROPEN:
		ulogd_log(ULOGD_ERROR, "unable to open configfile: %s\n",
				  ulogd_configfile);
		break;

	case ERRMAND:
		ulogd_log(ULOGD_ERROR, "mandatory option \"%s\" not found\n",
				  config_errce->key);
		break;

	case ERRMULT:
		ulogd_log(ULOGD_ERROR, "option \"%s\" occurred more than once\n",
				  config_errce->key);
		break;

	case ERRUNKN:
		ulogd_log(ULOGD_ERROR,
				  "unknown config key \"%s\"\n",config_errce->key);
		break;

	case ERRSECTION:
		ulogd_log(ULOGD_ERROR, "section \"%s\" not found\n", section);
		break;

	case ERRPLUGIN:
		ulogd_log(ULOGD_ERROR, "plugin error\n");
		break;
	}

	return 1;
}

static int
__stack_reconfigure(struct ulogd_pluginstance_stack *stack, void *arg)
{
	if (stack_reconfigure(stack) < 0)
		return -1;

	return 1;
}

static int
__do_signal(struct ulogd_pluginstance *pi, void *arg)
{
	int signo = (int)arg;

	if (pi->plugin->signal) {
		ulogd_upi_signal(pi, signo);

		return 1;
	}

	return 0;
}

static void
sync_sig_handler(int signo)
{
	char *sig_name = NULL;

	switch (signo) {
	case SIGHUP:
		sig_name = "HUP";
		break;

	case SIGTERM:
		sig_name = "TERM";
		break;

	default:
		break;
	}

	if (sig_name != NULL)
		ulogd_log(ULOGD_INFO, "SIG%s received\n", sig_name);

	if (ulogd_get_state() != GS_RUNNING)
		return;

	switch (signo) {
	case SIGHUP:
		ulogd_log(ULOGD_INFO, "reconfiguring plugins\n");

		ulogd_set_state(GS_INITIALIZING);
		stack_for_each(__stack_reconfigure, NULL);
		ulogd_set_state(GS_RUNNING);
		break;

	case SIGALRM:
		ulogd_timer_handle();
		break;

	case SIGTERM:
		ulogd_upi_stop_all();
		exit(EXIT_SUCCESS);
		break;

	default:
		upi_for_each(__do_signal, (void *)signo);
		break;
	}
}

static void
sig_handler(int signo)
{
	switch (signo) {
	case SIGABRT:
		ulogd_log(ULOGD_INFO, "SIGABRT received\n");
		exit(EXIT_FAILURE);

	case SIGINT:
		ulogd_log(ULOGD_INFO, "SIGINT received\n");
		exit(EXIT_SUCCESS);
		break;

	default:
		break;
	}
}

static int
write_pid_file(void)
{
	FILE *fp;

	if ((fp = fopen(pid_file, "w")) != NULL) {
		fprintf(fp, "%d\n", (int)getpid());
		fclose(fp);
	}

	return 0;
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
	printf("\t-c --configfile\tUse alternative Configfile\n");
	printf("\t-u --uid\tChange UID/GID\n");
}

static struct option opts[] = {
	{ "version", 0, NULL, 'V' },
	{ "daemon", 0, NULL, 'd' },
	{ "help", 0, NULL, 'h' },
	{ "configfile", 1, NULL, 'c'},
	{ "uid", 1, NULL, 'u' },
	{ 0 }
};

int
main(int argc, char* argv[])
{
	int argch;
	int daemonize = 0;
	int change_uid = 0;
	char *user = NULL;
	struct passwd *pw;
	uid_t uid = 0;
	gid_t gid = 0;

	ulogd_set_state(GS_INITIALIZING);

	while ((argch = getopt_long(argc, argv, "c:dh::Vu:", opts, NULL)) != -1) {
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
		}
	}

	if (ulogd_signal_init() < 0)
		exit(EXIT_FAILURE);

	ulogd_timer_init();
	ulogd_plugin_init();

	if (config_register_file(ulogd_configfile)) {
		ulogd_log(ULOGD_FATAL, "error registering configfile \"%s\"\n",
			  ulogd_configfile);
		exit(1);
	}
	
	/* parse config file */
	if (parse_conffile("global", &ulogd_kset))
		exit(EXIT_FAILURE);

	if (!stack_have_stacks()) {
		ulogd_log(ULOGD_ERROR, "not even a single working plugin stack\n");
		exit(1);
	}

	if (change_uid) {
		ulogd_log(ULOGD_NOTICE, "Changing UID / GID\n");
		if (setgid(gid)) {
			ulogd_log(ULOGD_FATAL, "can't set GID %u\n", gid);
			exit(1);
		}
		if (setegid(gid)) {
			ulogd_log(ULOGD_FATAL, "can't sett effective GID %u\n",
				  gid);
			exit(1);
		}
		if (initgroups(user, gid)) {
			ulogd_log(ULOGD_FATAL, "can't set user secondary GID\n");
			exit(1);
		}
		if (setuid(uid)) {
			ulogd_log(ULOGD_FATAL, "can't set UID %u\n", uid);
			exit(1);
		}
		if (seteuid(uid)) {
			ulogd_log(ULOGD_FATAL, "can't set effective UID %u\n",
				  uid);
			exit(1);
		}
	}

	/* seems like some plugins (sqlite, ctnetlink) are quite sensible
	   on busy sites, therefore be a bit less nice here */
	nice(-1);

	if (daemonize){
		if (fork()) {
			exit(0);
		}
		if (logfile != NULL)
			fclose(stdout);

		fclose(stderr);
		fclose(stdin);

		setsid();
	}

	if (write_pid_file() < 0)
		exit(EXIT_FAILURE);

	ulogd_register_signal(SIGTERM, sync_sig_handler, ULOGD_SIGF_SYNC);
	ulogd_register_signal(SIGINT, sig_handler, 0);
	ulogd_register_signal(SIGABRT, sig_handler, 0);
	ulogd_register_signal(SIGHUP, sync_sig_handler, ULOGD_SIGF_SYNC);
	ulogd_register_signal(SIGALRM, sync_sig_handler, ULOGD_SIGF_SYNC);
	ulogd_register_signal(SIGUSR1, sync_sig_handler, ULOGD_SIGF_SYNC);
	ulogd_register_signal(SIGUSR2, sync_sig_handler, ULOGD_SIGF_SYNC);

	if (ifi_init() < 0)
		exit(EXIT_FAILURE);

	ulogd_timer_run();

	ulogd_log(ULOGD_INFO, "entering main loop\n");

	ulogd_set_state(GS_RUNNING);

	ulogd_dispatch();

	return 0;
}

