/* borrowed from isakmpd-20030718 (-; */

/*	$OpenBSD: math_group.h,v 1.7 2003/06/03 14:28:16 ho Exp $	*/
/*	$EOM: math_group.h,v 1.7 1999/04/17 23:20:40 niklas Exp $	*/

/*
 * SPDX-FileCopyrightText: 1998 Niels Provos
 * SPDX-FileCopyrightText: 1999 Niklas Hallqvist
 * SPDX-FileCopyrightText: 2023 Jolla Ltd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * This code was written under funding by Ericsson Radio Systems.
 */

#ifndef VPNC_MATH_GROUP_H
#define VPNC_MATH_GROUP_H

#include <gcrypt.h>

enum groups {
	MODP  /* F_p, Z modulo a prime */
};

#define OAKLEY_GRP_1    1
#define OAKLEY_GRP_2    2
#define OAKLEY_GRP_5    3
#define OAKLEY_GRP_14   4
#define OAKLEY_GRP_15   5
#define OAKLEY_GRP_16   6
#define OAKLEY_GRP_17   7
#define OAKLEY_GRP_18   8

/*
 * The group on which diffie hellmann calculations are done.
 */

/* Description of F_p for Boot-Strapping */

struct modp_dscr {
	int id;
	int bits; /* Key Bits provided by this group, average of min and max estimates according to RFC 3526 section 8 */
	const char *prime; /* Prime */
	const char *gen; /* Generator */
};

struct modp_group {
	gcry_mpi_t gen; /* Generator */
	gcry_mpi_t p; /* Prime */
	gcry_mpi_t a, b, c, d;
};

struct group {
	enum groups type;
	int id; /* Group ID */
	int bits; /* Number of key bits provided by this group */
	struct modp_group *group;
	const struct modp_dscr *group_dscr;
	void *a, *b, *c, *d;
	void *gen; /* Group Generator */
	int (*getlen) (struct group *);
	void (*getraw) (struct group *, void *, unsigned char *);
	int (*setraw) (struct group *, void *, unsigned char *, int);
	int (*setrandom) (struct group *, void *);
	int (*operation) (struct group *, void *, void *, void *);
};

/* Prototypes */

void group_init(void);
void group_free(struct group *);
struct group *group_get(int);

#endif /* VPNC_MATH_GROUP_H */
