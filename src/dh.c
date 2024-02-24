/* borrowed from isakmpd-20030718 (-; */

/*	$OpenBSD: dh.c,v 1.8 2003/06/03 14:28:16 ho Exp $	*/
/*	$EOM: dh.c,v 1.5 1999/04/17 23:20:22 niklas Exp $	*/

/*
 * SPDX-FileCopyrightText: 1998 Niels Provos
 * SPDX-FileCopyrightText: 1999 Niklas Hallqvist
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * This code was written under funding by Ericsson Radio Systems.
 */

#include "math_group.h"
#include "dh.h"

/*
 * Returns the length of our exchange value.
 */

int dh_getlen(struct group *group)
{
	return group->getlen(group);
}

/*
 * Creates the exchange value we are offering to the other party.
 * Each time this function is called a new value is created, that
 * means the application has to save the exchange value itself,
 * dh_create_exchange should only be called once.
 */
int dh_create_exchange(struct group *group, unsigned char *buf)
{
	if (group->setrandom(group, group->c))
		return -1;
	if (group->operation(group, group->a, group->gen, group->c))
		return -1;
	group->getraw(group, group->a, buf);
	return 0;
}

/*
 * Creates the Diffie-Hellman shared secret in 'secret', where 'exchange'
 * is the exchange value offered by the other party. No length verification
 * is done for the value, the application has to do that.
 */
int dh_create_shared(struct group *group, unsigned char *secret, unsigned char *exchange)
{
	if (group->setraw(group, group->b, exchange, group->getlen(group)))
		return -1;
	if (group->operation(group, group->a, group->b, group->c))
		return -1;
	group->getraw(group, group->a, secret);
	return 0;
}
