/* config file parser functions
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
 * (C) 2013 by Eric Leblond <eric@regit.org>
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
 */

#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/conffile.h>
#include <unistd.h>


/* points to config entry with error */
struct config_entry *config_errce = NULL;

/* Filename of the config file */
static char *fname = NULL;

/* get_word() - Function to parse a line into words.
 * Arguments:	line	line to parse
 * 		delim	possible word delimiters
 * 		buf	pointer to buffer where word is returned
 * Return value:	pointer to first char after word
 * This function can deal with "" quotes 
 */
static char *get_word(char *line, char *not, char *buf)
{
	char *p, *start = NULL, *stop = NULL;
	int inquote = 0;

	for (p = line; *p; p++) {
		if (*p == '"') {
			start  = p + 1;
			inquote = 1;
			break;
		}
		if (!strchr(not, *p)) {
			start = p;
			break;
		}
	}
	if (!start)
		return NULL;

	/* determine pointer to one char after word */
	for (p = start; *p; p++) {
		if (inquote) {
			if (*p == '"') {
				stop = p;
				break;
			}
		} else {
			if (strchr(not, *p)) {
				stop = p;
				break;
			}
		}
	}
	if (!stop)
		return NULL;

	strncpy(buf, start, (size_t) (stop-start));
	*(buf + (stop-start)) = '\0';

	/* skip quote character */
	if (inquote)
		/* yes, we can return stop + 1. If " was the last 
		 * character in string, it now points to NULL-term */
		return (stop + 1);

	return stop;
}

/***********************************************************************
 * PUBLIC INTERFACE
 ***********************************************************************/

/* register config file with us */
int config_register_file(const char *file)
{
	if (fname)
		return 1;

	if (access(file, R_OK) != 0) {
		ulogd_log(ULOGD_ERROR,
			 "unable to read configfile \"%s\": %s\n",
			 file,
			 strerror(errno));
		return 1;
	}

	pr_debug("%s: registered config file '%s'\n", __func__, file);

	fname = (char *) malloc(strlen(file)+1);
	if (!fname)
		return -ERROOM;

	strcpy(fname, file);

	return 0;
}

/* parse config file */
int config_parse_file(const char *section, struct config_keyset *kset)
{
	FILE *cfile;
	char *args;
	int err = 0;
	int found = 0;
	unsigned int i;
	char linebuf[LINE_LEN+1];
	char *line = linebuf;
	int linenum = 0;

	pr_debug("%s: section='%s' file='%s'\n", __func__, section, fname);

	cfile = fopen(fname, "r");
	if (!cfile)
		return -ERROPEN;

	/* Search for correct section */
	while (fgets(line, LINE_LEN, cfile)) {
		char wordbuf[LINE_LEN];
		char *wordend;

		linenum++;
		if (*line == '#')
			continue;

		/* if line was fetch completely, string ends with '\n' */
		if (! strchr(line, '\n')) {
			ulogd_log(ULOGD_ERROR, "line %d too long.\n", linenum);
			return -ERRTOOLONG;
		}

		if (!(wordend = get_word(line, " \t\n\r[]", (char *) wordbuf)))
			continue;
		pr_debug("word: \"%s\"\n", wordbuf);
		if (!strcmp(wordbuf, section)) {
			found = 1;
			break;
		}
	}

	if (!found) {
		fclose(cfile);
		return -ERRSECTION;
	}

	/* Parse this section until next section */
	while (fgets(line, LINE_LEN, cfile))
	{
		unsigned int i;
		char wordbuf[LINE_LEN];
		char *wordend;
		
		linenum++;
		pr_debug("line read: %s\n", line);
		if (*line == '#')
			continue;

		/* if line was fetch completely, string ends with '\n' */
		if (! strchr(line, '\n')) {
			ulogd_log(ULOGD_ERROR, "line %d too long.\n", linenum);
			return -ERRTOOLONG;
		}

		if (!(wordend = get_word(line, " =\t\n\r", (char *) &wordbuf)))
			continue;

		if (wordbuf[0] == '[' ) {
			pr_debug("Next section '%s' encountered\n", wordbuf);
			break;
		}

		pr_debug("parse_file: entering main loop\n");
		for (i = 0; i < kset->num_ces; i++) {
			struct config_entry *ce = &kset->ces[i];
			pr_debug("parse main loop, key: %s\n", ce->key);
			if ((strcmp(ce->key, (char *) &wordbuf)) ||
			     ce->flag & CONFIG_FLAG_VAL_PROTECTED) {
				continue;
			}

			wordend = get_word(wordend, " =\t\n\r", (char *) &wordbuf);
			args = (char *)&wordbuf;

			if (ce->hit && !(ce->options & CONFIG_OPT_MULTI))
			{
				pr_debug("->ce-hit and option not multi!\n");
				config_errce = ce;
				err = -ERRMULT;
				goto cpf_error;
			}
			ce->hit++;

			switch (ce->type) {
				case CONFIG_TYPE_STRING:
					if (strlen(args) < 
					    CONFIG_VAL_STRING_LEN ) {
						strcpy(ce->u.string, args);
					} else {
						config_errce = ce;
						err = -ERRTOOLONG;
						goto cpf_error;
					}
					break;
				case CONFIG_TYPE_INT:
					ce->u.value = strtoul(args, NULL, 0);
					break;
				case CONFIG_TYPE_CALLBACK:
					(ce->u.parser)(args);
					break;
			}
			break;
		}
		pr_debug("parse_file: exiting main loop\n");
	}


	for (i = 0; i < kset->num_ces; i++) {
		struct config_entry *ce = &kset->ces[i];
		pr_debug("ce post loop, ce=%s\n", ce->key);
		if ((ce->options & CONFIG_OPT_MANDATORY) && (ce->hit == 0)) {
			pr_debug("Mandatory config directive \"%s\" not found\n",
				ce->key);
			config_errce = ce;
			err = -ERRMAND;
			goto cpf_error;
		}

	}

cpf_error:
	fclose(cfile);
	return err;
}

void config_stop()
{
	free(fname);
}
