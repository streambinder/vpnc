/*
   ISAKMP packing and unpacking routines.

   SPDX-FileCopyrightText: 2002 Geoffrey Keating
   SPDX-FileCopyrightText: 2003-2005 Maurice Massar

   SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef VPNC_ISAKMP_PKT_H
#define VPNC_ISAKMP_PKT_H
#if defined(__linux__)
#include <stdint.h>
#endif
#include <sys/types.h>

#include "isakmp.h"

struct isakmp_attribute {
	struct isakmp_attribute *next;
	uint16_t type;
	enum {
		isakmp_attr_lots,
		isakmp_attr_16,
		isakmp_attr_2x8,
		isakmp_attr_acl
	} af;
	union {
		uint16_t attr_16;
		uint8_t attr_2x8[2];
		struct {
			uint16_t length;
			uint8_t *data;
		} lots;
		struct {
			uint16_t count;
			struct acl_ent_s {
				struct in_addr addr, mask;
				uint16_t protocol, sport, dport;
			} *acl_ent;
		} acl;
	} u;
};

struct isakmp_payload {
	struct isakmp_payload *next;
	enum isakmp_payload_enum type;
	union {
		struct {
			uint32_t doi;
			uint32_t situation;
			struct isakmp_payload *proposals;
		} sa;
		struct {
			uint8_t number;
			uint8_t prot_id;
			uint8_t spi_size;
			uint8_t *spi;
			struct isakmp_payload *transforms;
		} p;
		struct {
			uint8_t number;
			uint8_t id;
			struct isakmp_attribute *attributes;
		} t;
		struct {
			uint16_t length;
			uint8_t *data;
		} ke, hash, sig, nonce, vid, natd;
		struct {
			uint8_t type;
			uint8_t protocol;
			uint16_t port;
			uint16_t length;
			uint8_t *data;
		} id;
		struct {
			uint8_t encoding;
			uint16_t length;
			uint8_t *data;
		} cert, cr;
		struct {
			uint32_t doi;
			uint8_t protocol;
			uint8_t spi_length;
			uint8_t *spi;
			uint16_t type;
			uint16_t data_length;
			uint8_t *data;
			struct isakmp_attribute *attributes; /* sometimes, data is an attributes array */
		} n;
		struct {
			uint32_t doi;
			uint8_t protocol;
			uint8_t spi_length;
			uint16_t num_spi;
			uint8_t **spi;
		} d;
		struct {
			uint8_t type;
			uint16_t id;
			struct isakmp_attribute *attributes;
		} modecfg;
	} u;
};

struct isakmp_packet {
	uint8_t i_cookie[ISAKMP_COOKIE_LENGTH];
	uint8_t r_cookie[ISAKMP_COOKIE_LENGTH];
	uint8_t isakmp_version;
	uint8_t exchange_type;
	uint8_t flags;
	uint32_t message_id;
	struct isakmp_payload *payload;
};

extern void *xallocc(size_t x);
extern struct isakmp_packet *new_isakmp_packet(void);
extern struct isakmp_payload *new_isakmp_payload(uint8_t);
extern struct isakmp_payload *new_isakmp_data_payload(uint8_t type, const void *data,
													  size_t data_length);
extern struct isakmp_attribute *new_isakmp_attribute(uint16_t, struct isakmp_attribute *);
extern struct isakmp_attribute *new_isakmp_attribute_16(uint16_t type, uint16_t data,
														struct isakmp_attribute *next);
extern void free_isakmp_packet(struct isakmp_packet *p);
extern void flatten_isakmp_payloads(struct isakmp_payload *p, uint8_t ** result, size_t * size);
extern void flatten_isakmp_payload(struct isakmp_payload *p, uint8_t ** result, size_t * size);
extern void flatten_isakmp_packet(struct isakmp_packet *p,
								  uint8_t ** result, size_t * size, size_t blksz);
extern struct isakmp_packet *parse_isakmp_packet(const uint8_t * data,
												 size_t data_len, int * reject);
extern void test_pack_unpack(void);

#endif /* VPNC_ISAKMP_PKT_H */
