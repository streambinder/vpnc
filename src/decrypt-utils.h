/* IPSec VPN client compatible with Cisco equipment.
   Copyright (C) 2004-2007 Maurice Massar
   A bit reorganized in 2007 by Wolfram Sang

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

#ifndef VPNC_DECRYPT_UTILS_H
#define VPNC_DECRYPT_UTILS_H

extern int hex2bin(const char *str, char **bin, int *len);
extern int deobfuscate(char *ct, int len, const char **resp, char *reslenp);

#endif /* VPNC_DECRYPT_UTILS_H */
