/*
 * common.c
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
 * Holger Eitzenberger <holger@eitzenberger.org>, 2007.
 */
#include "config.h"
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/plugin.h>

#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>


char *
xstrncpy(char *dst, const char *src, size_t n)
{
	strncpy(dst, src, n);
	dst[n - 1] = '\0';

	return dst;
}

int
set_sockbuf_len(int fd, int rcv_len, int snd_len)
{
	int ret;

	pr_debug("%s: fd=%d rcv-len=%d snd-len\n", __func__, fd, rcv_len,
			 snd_len);

	if (snd_len > 0) {
		ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &snd_len,
						 sizeof(snd_len));
		if (ret < 0) {
			ulogd_log(ULOGD_ERROR, "setsockopt: SO_SNDBUF: %m\n");
			return -1;
		}
	}

	if (rcv_len > 0) {
		ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv_len,
						 sizeof(rcv_len));
		if (ret < 0) {
			ulogd_log(ULOGD_ERROR, "setsockopt: SO_RCVBUF: %m\n");
			return -1;
		}
	}

	return 0;
}

/**
 * Translate character string.
 * @arg str		The string to translate.
 * @arg from	The character to translate from.
 * @arg to		The character to translate to.
 * @return		0 if succesfull, -1 on error.
 */
int
strntr(char *str, char from, char to)
{
	if (str == NULL	|| from == '\0')
		return -1;
	if (from == to)
		return 0;

	while ((str = strchr(str, from)) != NULL) {
		*str++ = to;
		if (to == '\0')
			break;
	}

	return 0;
}

/**
 * Return number as string.
 *
 * @return characters written, -1 on error.
 */
int
utoa(unsigned v, char *str, size_t len)
{
	char *pch = str;
	int i, written;

	do {
		unsigned mod = v % 10;

		v /= 10;
		*pch++ = '0' + mod;
	} while (v > 0 && pch < str + len - 1);

	*pch = '\0';
	written = pch - str;

	/* characters are in reverse order, therefore swap */
	len = pch - str;
	for (i = 0, pch--; i < (len / 2); i++) {
		char tmp = pch[-i];

		pch[-i] = str[i];
		str[i] = tmp;
	}

	return written;
}

static inline void
ulltoa(unsigned long long v, char *out, size_t outlen)
{
	snprintf(out, outlen, "%llu", v);
}

/**
 * Append to string with delimiter.
 *
 * @arg dst		Address of destination pointer.
 * @arg src		Source string to be appended.
 * @arg len		Length of source string (including '\0').
 * @arg delim	Pointer to delimiter (set to '0' before first call).
 * @return pointer to newly created string
 */
char *
strncat_delim(char **dst, const char *src, size_t len, int *delim)
{
	char *d = *dst;

	if (delim != NULL && *delim)
		*(*dst)++ = ' ';

	strcpy(*dst, src);
	*dst += len - 1;

	if (delim != NULL)
		(*delim)++;

	return d;
}

/**
 * time diff with second resolution
 */
unsigned
tv_diff_sec(const struct timeval *tv1, const struct timeval *tv2)
{
    if (tv2->tv_sec >= tv1->tv_sec)
        return max(tv2->tv_sec - tv1->tv_sec, 1);

    return tv1->tv_sec - tv2->tv_sec;
}

#define NV_INITIALIZER(val)		{ #val, val }

const struct nv nv_facility[FACILITY_LEN] = {
	NV_INITIALIZER(LOG_DAEMON),
	NV_INITIALIZER(LOG_KERN),
	NV_INITIALIZER(LOG_LOCAL0),
	NV_INITIALIZER(LOG_LOCAL1),
	NV_INITIALIZER(LOG_LOCAL2),
	NV_INITIALIZER(LOG_LOCAL3),
	NV_INITIALIZER(LOG_LOCAL4),
	NV_INITIALIZER(LOG_LOCAL5),
	NV_INITIALIZER(LOG_LOCAL6),
	NV_INITIALIZER(LOG_LOCAL7),
	NV_INITIALIZER(LOG_USER),
};

const struct nv nv_level[LEVEL_LEN] = {
	NV_INITIALIZER(LOG_EMERG),
	NV_INITIALIZER(LOG_ALERT),
	NV_INITIALIZER(LOG_CRIT),
	NV_INITIALIZER(LOG_ERR),
	NV_INITIALIZER(LOG_WARNING),
	NV_INITIALIZER(LOG_NOTICE),
	NV_INITIALIZER(LOG_INFO),
	NV_INITIALIZER(LOG_DEBUG),
};

int
nv_get_value(const struct nv *nv, size_t len, const char *name)
{
	int i;

	for (i = 0; i < len; i++) {
		if (strcmp(nv[i].name, name) == 0)
			return nv[i].val;
	}

	return -1;
}
