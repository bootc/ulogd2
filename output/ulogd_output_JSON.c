/* ulogd_output_JSON.c
 *
 * ulogd output target for logging to a file in JSON format.
 *
 * (C) 2014 by Eric Leblond <eric@regit.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <inttypes.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include <jansson.h>

#ifndef ULOGD_JSON_DEFAULT
#define ULOGD_JSON_DEFAULT	"/var/log/ulogd.json"
#endif

#ifndef ULOGD_JSON_DEFAULT_DEVICE
#define ULOGD_JSON_DEFAULT_DEVICE "Netfilter"
#endif

struct json_priv {
	FILE *of;
	int sec_idx;
	int usec_idx;
};

enum json_conf {
	JSON_CONF_FILENAME = 0,
	JSON_CONF_SYNC,
	JSON_CONF_TIMESTAMP,
	JSON_CONF_DEVICE,
	JSON_CONF_BOOLEAN_LABEL,
	JSON_CONF_MAX
};

static struct config_keyset json_kset = {
	.num_ces = JSON_CONF_MAX,
	.ces = {
		[JSON_CONF_FILENAME] = {
			.key = "file",
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u = {.string = ULOGD_JSON_DEFAULT },
		},
		[JSON_CONF_SYNC] = {
			.key = "sync",
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u = { .value = 0 },
		},
		[JSON_CONF_TIMESTAMP] = {
			.key = "timestamp",
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u = { .value = 1 },
		},
		[JSON_CONF_DEVICE] = {
			.key = "device",
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u = { .string = ULOGD_JSON_DEFAULT_DEVICE },
		},
		[JSON_CONF_BOOLEAN_LABEL] = {
			.key = "boolean_label",
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u = { .value = 0 },
		},
	},
};

#define MAX_LOCAL_TIME_STRING 32

static int json_interp(struct ulogd_pluginstance *upi)
{
	struct json_priv *opi = (struct json_priv *) &upi->private;
	unsigned int i;
	json_t *msg;

	msg = json_object();
	if (!msg) {
		ulogd_log(ULOGD_ERROR, "Unable to create JSON object\n");
		return ULOGD_IRET_ERR;
	}

	if (upi->config_kset->ces[JSON_CONF_TIMESTAMP].u.value != 0) {
		time_t now;
		char timestr[MAX_LOCAL_TIME_STRING];
		struct tm *t;
		struct tm result;
		struct ulogd_key *inp = upi->input.keys;


		if (pp_is_valid(inp, opi->sec_idx))
			now = (time_t) ikey_get_u64(&inp[opi->sec_idx]);
		else
			now = time(NULL);
		t = localtime_r(&now, &result);

		if (pp_is_valid(inp, opi->usec_idx)) {
			snprintf(timestr, MAX_LOCAL_TIME_STRING,
					"%04d-%02d-%02dT%02d:%02d:%02d.%06u",
					t->tm_year + 1900, t->tm_mon + 1,
					t->tm_mday, t->tm_hour,
					t->tm_min, t->tm_sec,
					ikey_get_u32(&inp[opi->usec_idx]));
		} else {
			snprintf(timestr, MAX_LOCAL_TIME_STRING,
					"%04d-%02d-%02dT%02d:%02d:%02d",
					t->tm_year + 1900, t->tm_mon + 1,
					t->tm_mday, t->tm_hour,
					t->tm_min, t->tm_sec);
		}

		json_object_set_new(msg, "timestamp", json_string(timestr));
	}

	if (upi->config_kset->ces[JSON_CONF_DEVICE].u.string) {
		char *dvc = upi->config_kset->ces[JSON_CONF_DEVICE].u.string;
		json_object_set_new(msg, "dvc", json_string(dvc));
	}



	for (i = 0; i < upi->input.num_keys; i++) {
		struct ulogd_key *key = upi->input.keys[i].u.source;
		char *field_name;

		if (!key)
			continue;

		if (!IS_VALID(*key))
			continue;

		field_name = key->cim_name ? key->cim_name : key->name;

		switch (key->type) {
		case ULOGD_RET_STRING:
			json_object_set_new(msg, field_name, json_string(key->u.value.ptr));
			break;
		case ULOGD_RET_BOOL:
		case ULOGD_RET_INT8:
		case ULOGD_RET_INT16:
		case ULOGD_RET_INT32:
			json_object_set_new(msg, field_name, json_integer(key->u.value.i32));
			break;
		case ULOGD_RET_UINT8:
			if ((upi->config_kset->ces[JSON_CONF_BOOLEAN_LABEL].u.value != 0)
					&& (!strcmp(key->name, "raw.label"))) {
				if (key->u.value.ui8)
					json_object_set_new(msg, "action", json_string("allowed"));
				else
					json_object_set_new(msg, "action", json_string("blocked"));
				break;
			}
		case ULOGD_RET_UINT16:
		case ULOGD_RET_UINT32:
		case ULOGD_RET_UINT64:
			json_object_set_new(msg, field_name, json_integer(key->u.value.ui64));
		default:
			/* don't know how to interpret this key. */
			break;
		}
	}

	json_dumpf(msg, opi->of, 0);
	fprintf(opi->of, "\n");

	json_decref(msg);

	if (upi->config_kset->ces[JSON_CONF_SYNC].u.value != 0)
		fflush(opi->of);

	return ULOGD_IRET_OK;
}

static void sighup_handler_print(struct ulogd_pluginstance *upi, int signal)
{
	struct json_priv *oi = (struct json_priv *) &upi->private;
	FILE *old = oi->of;

	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "JSON: reopening logfile\n");
		oi->of = fopen(upi->config_kset->ces[0].u.string, "a");
		if (!oi->of) {
			ulogd_log(ULOGD_ERROR, "can't open JSON "
					       "log file: %s\n",
				  strerror(errno));
			oi->of = old;
		} else {
			fclose(old);
		}
		break;
	default:
		break;
	}
}

static int json_configure(struct ulogd_pluginstance *upi,
			    struct ulogd_pluginstance_stack *stack)
{
	int ret;

	ret = ulogd_wildcard_inputkeys(upi);
	if (ret < 0)
		return ret;

	ret = config_parse_file(upi->id, upi->config_kset);
	if (ret < 0)
		return ret;

	return 0;
}

static int json_init(struct ulogd_pluginstance *upi)
{
	struct json_priv *op = (struct json_priv *) &upi->private;
	unsigned int i;

	op->of = fopen(upi->config_kset->ces[0].u.string, "a");
	if (!op->of) {
		ulogd_log(ULOGD_FATAL, "can't open JSON log file: %s\n",
			strerror(errno));
		return -1;
	}

	/* search for time */
	op->sec_idx = -1;
	op->usec_idx = -1;
	for (i = 0; i < upi->input.num_keys; i++) {
		struct ulogd_key *key = upi->input.keys[i].u.source;
		if (!strcmp(key->name, "oob.time.sec"))
			op->sec_idx = i;
		else if (!strcmp(key->name, "oob.time.usec"))
			op->usec_idx = i;
	}

	return 0;
}

static int json_fini(struct ulogd_pluginstance *pi)
{
	struct json_priv *op = (struct json_priv *) &pi->private;

	if (op->of != stdout)
		fclose(op->of);

	return 0;
}

static struct ulogd_plugin json_plugin = {
	.name = "JSON",
	.input = {
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW | ULOGD_DTYPE_SUM,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.configure = &json_configure,
	.interp	= &json_interp,
	.start 	= &json_init,
	.stop	= &json_fini,
	.signal = &sighup_handler_print,
	.config_kset = &json_kset,
	.version = VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&json_plugin);
}
