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
	uint32_t seq;
	uint32_t odid;				/* Observation Domain ID */
	uint8_t data[];
};

/*
 * IDs 0-255 are reserved for Template Sets.  IDs of Data Sets are > 255.
 */
struct ipfix_templ_hdr {
	uint16_t id;
	uint16_t cnt;
	uint8_t data[];
};

struct ipfix_set_hdr {
#define IPFIX_SET_TEMPL			2
#define IPFIX_SET_OPT_TEMPL		3
	uint16_t id;
	uint16_t len;
	uint8_t data[];
};

/* Vineyard IPFIX-like protocol */
struct vy_ipfix_hdr {
#define VY_IPFIX_VERSION		'A'
	uint16_t version;
	uint8_t cnt;				/* RecordCount */
	uint32_t dev_id;
	uint32_t uptime;			/* milliseconds */
	uint32_t unix_secs;
	uint32_t unix_nsecs;
	uint8_t data[];
} __packed;

struct vy_ipfix_data {
	struct sockaddr_in saddr;
	struct sockaddr_in daddr;
	uint16_t ifi_in;
	uint16_t ifi_out;
	uint32_t packets;
	uint32_t bytes;
	uint32_t start;				/* milliseconds */
	uint32_t end;				/* milliseconds */
	uint16_t sport;
	uint16_t dport;
	uint8_t l4_proto;
	uint8_t dscp;
	uint32_t appsig;
	uint32_t retrans_rate;
	uint32_t rtt;
	uint8_t policy;				/* discard, shape, ... */
} __packed;

#endif /* IPFIX_H */
