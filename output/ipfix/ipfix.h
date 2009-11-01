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

#endif /* IPFIX_H */
