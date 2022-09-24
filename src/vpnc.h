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

   $Id$
 */

#ifndef VPNC_VPNC_H
#define VPNC_VPNC_H

#include "tunip.h"

void process_late_ike(struct sa_block *s, uint8_t *r_packet, ssize_t r_length);
void keepalive_ike(struct sa_block *s);
void dpd_ike(struct sa_block *s);
void print_vid(const unsigned char *vid, uint16_t len);
void rekey_phase1(struct sa_block *s);


#endif /* VPNC_VPNC_H */
