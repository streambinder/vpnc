/* IPSec ESP and AH support.
   Copyright (C) 2005 Maurice Massar

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

   $Id$
*/

#ifndef __TUNIP_H__
#define __TUNIP_H__

#include "isakmp.h"

#include <net/if.h>

struct lifetime {
	time_t   start;
	uint32_t seconds;
	uint32_t kbytes;
	uint32_t rx;
	uint32_t tx;
};

struct ike_sa {
	uint32_t spi;
	uint8_t *key;
	struct sockaddr_in dest;
};

struct sa_block {
	const char *pidfile;
	int ike_fd; /* fd over isakmp traffic, and in case of NAT-T esp too */
	int tun_fd; /* fd to host via tun/tap */
	int esp_fd; /* raw socket for ip-esp or Cisco-UDP or ike_fd (NAT-T) */
	char tun_name[IFNAMSIZ];
	uint8_t tun_hwaddr[ETH_ALEN];
	struct {
		uint8_t i_cookie[ISAKMP_COOKIE_LENGTH];
		uint8_t r_cookie[ISAKMP_COOKIE_LENGTH];
		uint8_t *key; /* ike encryption key */
		size_t keylen;
		uint8_t *initial_iv;
		uint8_t *skeyid_a;
		uint8_t *skeyid_d;
		int auth_algo; /* PSK, PSK+Xauth, ToDo: Cert/Hybrid/... */
		int cry_algo, md_algo;
		size_t ivlen, md_len;
		uint8_t current_iv_msgid[4];
		uint8_t *current_iv;
		struct lifetime life;
	} ike;
	uint8_t our_address[4], our_netmask[4];
	struct {
		int do_pfs;
		int cry_algo, md_algo;
		size_t key_len, md_len;
		size_t blk_len, iv_len;
		uint16_t encap_mode;
		uint16_t peer_udpencap_port;
		struct lifetime life;
		struct ike_sa rx, tx;
	} ipsec;
};

extern struct sa_block oursa[1];

extern void vpnc_doit(struct sa_block *s);

extern int find_local_addr(struct sockaddr_in *dest,
	struct sockaddr_in *source);

#endif
