/*
   IPSec VPN client compatible with Cisco equipment.

   SPDX-FileCopyrightText: 2004-2007 Maurice Massar
   SPDX-FileCopyrightText: 2007 Wolfram Sang
   SPDX-FileCopyrightText: 2019 Davide Pucci

   SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef VPNC_DECRYPT_UTILS_H
#define VPNC_DECRYPT_UTILS_H

extern int hex2bin(const char *str, char **bin, int *len);
extern int deobfuscate(char *ct, int len, const char **resp, char *reslenp);

#endif /* VPNC_DECRYPT_UTILS_H */
