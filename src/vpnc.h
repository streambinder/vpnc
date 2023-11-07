/* IPSec VPN client compatible with Cisco equipment.

   SPDX-FileCopyrightText: 2002-2004 Geoffrey Keating
   SPDX-FileCopyrightText: 2002-2004 Maurice Massar
   SPDX-FileCopyrightText: 2023 Jolla Ltd.

   SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef VPNC_VPNC_H
#define VPNC_VPNC_H

#include "tunip.h"
#include "syslog.h"

void process_late_ike(struct sa_block *s, uint8_t *r_packet, ssize_t r_length);
void keepalive_ike(struct sa_block *s);
void dpd_ike(struct sa_block *s);
void print_vid(const unsigned char *vid, uint16_t len);
void rekey_phase1(struct sa_block *s);

#define ASPRINTF(strp, ...)	if (asprintf(strp, __VA_ARGS__) < 0) \
	{ if (**strp) { free(*strp);} logmsg(LOG_ERR, "Failed to call asprintf() at %s:%d", __FILE__, __LINE__);}

#endif /* VPNC_VPNC_H */
