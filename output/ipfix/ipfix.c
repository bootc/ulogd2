/*
 * ipfix.c
 *
 * Holger Eitzenberger, 2009.
 */
#include "config.h"
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/plugin.h>

#include "ipfix.h"

size_t
ipfix_rec_len(uint16_t sid)
{
	BUG_ON(sid != htons(VY_IPFIX_SID));
	return sizeof(struct vy_ipfix_data);
}

size_t
ipfix_msg_len(const struct ipfix_hdr *hdr)
{
	struct ipfix_set_hdr *shdr = (struct ipfix_set_hdr *)hdr->data;

	/* TODO count all sets */
	return IPFIX_HDRLEN + shdr->len;
}
