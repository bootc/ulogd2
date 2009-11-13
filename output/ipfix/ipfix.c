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


struct ipfix_msg *
ipfix_msg_alloc(size_t len, uint32_t oid)
{
	struct ipfix_msg *msg;
	struct ipfix_hdr *hdr;

	if (len < IPFIX_HDRLEN + IPFIX_SET_HDRLEN)
		return NULL;

	msg = malloc(sizeof(struct ipfix_msg) + len);
	memset(msg, 0, sizeof(struct ipfix_msg));
	msg->tail = msg->data + IPFIX_HDRLEN;
	msg->end = msg->data + len;

	hdr = ipfix_msg_hdr(msg);
	memset(hdr, 0, IPFIX_HDRLEN);
	hdr->version = htons(IPFIX_VERSION);
	hdr->oid = htonl(oid);

	return msg;
}

void
ipfix_msg_free(struct ipfix_msg *msg)
{
	if (!msg)
		return;

	if (msg->nrecs > 0)
		ulogd_log(ULOGD_DEBUG, "%s: %d flows have been lost\n", __func__,
			msg->nrecs);

	free(msg);
}

struct ipfix_hdr *
ipfix_msg_hdr(const struct ipfix_msg *msg)
{
	return (struct ipfix_hdr *)msg->data;
}

void *
ipfix_msg_data(struct ipfix_msg *msg)
{
	return msg->data;
}

size_t
ipfix_msg_len(const struct ipfix_msg *msg)
{
	return msg->tail - msg->data;
}

struct ipfix_set_hdr *
ipfix_msg_add_set(struct ipfix_msg *msg, uint16_t sid)
{
	struct ipfix_set_hdr *shdr;

	if (msg->end - msg->tail < IPFIX_SET_HDRLEN)
		return NULL;

	if (msg->last_set) {
		shdr->id = htons(shdr->id);
		shdr->len = htons(shdr->len);
	}

	shdr = (struct ipfix_set_hdr *)msg->tail;
	shdr->id = sid;				/* leave host byte-order */
	shdr->len = IPFIX_SET_HDRLEN;
	msg->tail += IPFIX_SET_HDRLEN;
	msg->last_set = shdr;
	return shdr;
}

struct ipfix_set_hdr *
ipfix_msg_get_set(const struct ipfix_msg *msg)
{
	return msg->last_set;
}

/**
 * Add data record to an IPFIX message.  The data is accounted properly.
 *
 * @return pointer to data or %NULL if not that much space left.
 */
void *
ipfix_msg_add_data(struct ipfix_msg *msg, size_t len)
{
	void *data;

	BUG_ON(!msg->last_set);
	if (len > msg->end - msg->tail)
		return NULL;

	data = msg->tail;
	msg->tail += len;
	msg->nrecs++;
	msg->last_set->len += len;

	return data;
}

/* check and dump message */
int
ipfix_dump_msg(const struct ipfix_msg *msg)
{
	const struct ipfix_hdr *hdr = ipfix_msg_hdr(msg);
	const struct ipfix_set_hdr *shdr = (struct ipfix_set_hdr *)hdr->data;

	BUG_ON(ntohs(hdr->len) < IPFIX_HDRLEN);
	BUG_ON(ipfix_msg_len(msg) != IPFIX_HDRLEN + ntohs(shdr->len));

	ulogd_log(ULOGD_DEBUG, "msg: ver=%#x len=%#x t=%#x seq=%#x oid=%d\n",
			  ntohs(hdr->version), ntohs(hdr->len), htonl(hdr->time),
			  ntohl(hdr->seqno), ntohl(hdr->oid));

	return 0;
}

/* template management */
size_t
ipfix_rec_len(uint16_t sid)
{
	BUG_ON(sid != htons(VY_IPFIX_SID));
	return sizeof(struct vy_ipfix_data);
}
