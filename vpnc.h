/* IPSec VPN client compatible with Cisco equipment.
   Copyright (C) 2002, 2003, 2004  Geoffrey Keating and Maurice Massar

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
*/

#ifndef __VPNC_H__
#define __VPNC_H__

#include <sys/socket.h>
#include <net/if.h>
#include "sysdep.h"
#include "isakmp.h"

typedef struct {
	const char *name;
	int my_id, ike_sa_id, ipsec_sa_id;
	int keylen;
} supported_algo_t;

struct sa_block {
	int tun_fd;
	char tun_name[IFNAMSIZ];
	uint8_t i_cookie[ISAKMP_COOKIE_LENGTH];
	uint8_t r_cookie[ISAKMP_COOKIE_LENGTH];
	uint8_t *key; /* ike encryption key */
	size_t keylen;
	uint8_t *initial_iv;
	uint8_t *skeyid_a;
	uint8_t *skeyid_d;
	int cry_algo, md_algo;
	size_t ivlen, md_len;
	uint8_t current_iv_msgid[4];
	uint8_t *current_iv;
	uint8_t our_address[4], our_netmask[4];
	uint32_t tous_esp_spi, tothem_esp_spi;
	uint8_t *kill_packet;
	size_t kill_packet_size;
	int do_pfs;
};

extern struct sa_block oursa[];

extern supported_algo_t supp_dh_group[];
extern supported_algo_t supp_hash[];
extern supported_algo_t supp_crypt[];

extern const supported_algo_t *get_dh_group_ike(void);
extern const supported_algo_t *get_dh_group_ipsec(int server_setting);

#endif
