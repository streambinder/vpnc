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

typedef struct {
	const char *name;
	int my_id, ike_sa_id, ipsec_sa_id;
	int keylen;
} supported_algo_t;

extern supported_algo_t supp_dh_group[];
extern supported_algo_t supp_hash[];
extern supported_algo_t supp_crypt[];

extern int tun_fd;
extern char tun_name[];

extern const supported_algo_t *get_dh_group_ike(void);
extern const supported_algo_t *get_dh_group_ipsec(int server_setting);

#endif
