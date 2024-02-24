/* borrowed from isakmpd-20030718 (-; */

/*	$OpenBSD: dh.h,v 1.5 2003/06/03 14:28:16 ho Exp $	*/
/*	$EOM: dh.h,v 1.4 1999/04/17 23:20:24 niklas Exp $	*/

/*
 * SPDX-FileCopyrightText: 1998 Niels Provos
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * This code was written under funding by Ericsson Radio Systems.
 */

#ifndef VPNC_DH_H
#define VPNC_DH_H

#include <sys/types.h>

struct group;

int dh_getlen(struct group *);
int dh_create_exchange(struct group *, unsigned char *);
int dh_create_shared(struct group *, unsigned char *, unsigned char *);

#endif /* VPNC_DH_H */
