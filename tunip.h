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

extern void vpnc_doit(unsigned long tous_spi,
        const unsigned char *tous_key,
        struct sockaddr_in *tous_dest,
        unsigned long tothem_spi,
        const unsigned char *tothem_key,
        struct sockaddr_in *tothem_dest,
        int tun_fd, int md_algo, int cry_algo,
        uint8_t * kill_packet_p, size_t kill_packet_size_p,
        struct sockaddr *kill_dest_p,
        uint16_t encap_mode, int udp_fd,
        const char *pidfile);

extern int find_local_addr(struct sockaddr_in *dest,
	struct sockaddr_in *source);

#endif
