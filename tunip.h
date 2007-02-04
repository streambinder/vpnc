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

struct sa_block {
	int tun_fd;
	char tun_name[IFNAMSIZ];
	uint8_t tun_hwaddr[ETH_ALEN];
	uint8_t i_cookie[ISAKMP_COOKIE_LENGTH];
	uint8_t r_cookie[ISAKMP_COOKIE_LENGTH];
	uint8_t *key; /* ike encryption key */
	size_t keylen;
	uint8_t *initial_iv;
	uint8_t *skeyid_a;
	uint8_t *skeyid_d;
	int auth_algo, cry_algo, md_algo;
	size_t ivlen, md_len;
	uint8_t current_iv_msgid[4];
	uint8_t *current_iv;
	uint8_t our_address[4], our_netmask[4];
	uint32_t tous_esp_spi, tothem_esp_spi;
	uint8_t *kill_packet;
	size_t kill_packet_size;
	uint16_t peer_udpencap_port;
	int do_pfs;
};

extern struct sa_block oursa[1];

extern void vpnc_doit(unsigned long tous_spi,
        const unsigned char *tous_key,
        struct sockaddr_in *tous_dest,
        unsigned long tothem_spi,
        const unsigned char *tothem_key,
        struct sockaddr_in *tothem_dest,
        int tun_fd, uint8_t *tun_hwaddr,
	int md_algo, int cry_algo,
        uint8_t * kill_packet_p, size_t kill_packet_size_p,
        struct sockaddr *kill_dest_p,
        uint16_t encap_mode, int udp_fd,
        const char *pidfile);

extern int find_local_addr(struct sockaddr_in *dest,
	struct sockaddr_in *source);

#endif
