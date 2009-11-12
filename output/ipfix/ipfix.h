/*
 * ipfix.h
 *
 * Holger Eitzenberger <holger@eitzenberger.org>, 2009.
 */
#ifndef IPFIX_H
#define IPFIX_H

#include <stdint.h>


struct ipfix_hdr {
#define IPFIX_VERSION			0xa
	uint16_t version;
	uint16_t len;
	uint32_t time;
	uint32_t seqno;
	uint32_t oid;				/* Observation Domain ID */
	uint8_t data[];
} __packed;

#define IPFIX_HDRLEN	sizeof(struct ipfix_hdr)

/*
 * IDs 0-255 are reserved for Template Sets.  IDs of Data Sets are > 255.
 */
struct ipfix_templ_hdr {
	uint16_t id;
	uint16_t cnt;
	uint8_t data[];
} __packed;

struct ipfix_set_hdr {
#define IPFIX_SET_TEMPL			2
#define IPFIX_SET_OPT_TEMPL		3
	uint16_t id;
	uint16_t len;
	uint8_t data[];
} __packed;

#define IPFIX_SET_HDRLEN		sizeof(struct ipfix_set_hdr)

struct vy_ipfix_data {
	struct sockaddr_in saddr;
	struct sockaddr_in daddr;
	uint16_t ifi_in;
	uint16_t ifi_out;
	uint32_t packets;
	uint32_t bytes;
	uint32_t start;				/* Unix time */
	uint32_t end;				/* Unix time */
	uint16_t sport;
	uint16_t dport;
	uint32_t aid;				/* Application ID */
	uint8_t l4_proto;
	uint8_t dscp;
	uint16_t __padding;
} __packed;

#define VY_IPFIX_SID		256

#define VY_IPFIX_FLOWS		36
#define VY_IPFIX_PKT_LEN	(IPFIX_HDRLEN + IPFIX_SET_HDRLEN \
							 + VY_IPFIX_FLOWS * sizeof(struct vy_ipfix_data))

/* template management */
size_t ipfix_rec_len(uint16_t);

/* message handling */
size_t ipfix_msg_len(const struct ipfix_hdr *);

#endif /* IPFIX_H */
