/* borrowed from isakmpd-20030718 (-; */

/*	$OpenBSD: math_group.c,v 1.18 2003/06/03 14:28:16 ho Exp $	*/
/*	$EOM: math_group.c,v 1.25 2000/04/07 19:53:26 niklas Exp $	*/

/*
 * Copyright (c) 1998 Niels Provos.  All rights reserved.
 * Copyright (c) 1999, 2000 Niklas Hallqvist.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This code was written under funding by Ericsson Radio Systems.
 */

#include <assert.h>
#include <sys/param.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include <gcrypt.h>

#include "math_group.h"

/* We do not want to export these definitions.  */
static void modp_free(struct group *);
static struct group *modp_clone(struct group *, struct group *);
static void modp_init(struct group *);

static int modp_getlen(struct group *);
static void modp_getraw(struct group *, gcry_mpi_t, unsigned char *);
static int modp_setraw(struct group *, gcry_mpi_t, unsigned char *, int);
static int modp_setrandom(struct group *, gcry_mpi_t);
static int modp_operation(struct group *, gcry_mpi_t, gcry_mpi_t, gcry_mpi_t);

/*
 * This module provides access to the operations on the specified group
 * and is absolutly free of any cryptographic devices. This is math :-).
 */

/* Describe preconfigured MODP groups */

/*
 * The Generalized Number Field Sieve has an asymptotic running time
 * of: O(exp(1.9223 * (ln q)^(1/3) (ln ln q)^(2/3))), where q is the
 * group order, e.g. q = 2**768.
 */

static const struct modp_dscr oakley_modp[] = {
	{
		OAKLEY_GRP_1, 72, /* This group is insecure, only sufficient for DES */
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
		"E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
		"2"
	},
	{
		OAKLEY_GRP_2, 82, /* This group is a bit better */
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
		"FFFFFFFFFFFFFFFF",
		"2"
	},
	{
		OAKLEY_GRP_5, 102, /* This group is yet a bit better, RFC 3526 section 2 - 1536-bit MODP Group */
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
		"670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
		"2"
	},
	{
		OAKLEY_GRP_14, 135, /* RFC 3526 section 3 - 2048-bit MODP Group */
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF",
		"2"
	},
	{
		OAKLEY_GRP_15, 170, /* RFC 3526 section 4 - 3072-bit MODP Group */
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
		"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
		"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
		"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
		"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
		"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
		"43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
		"2"
	},
	{
		OAKLEY_GRP_16, 195, /* RFC 3526 section 5 - 4096-bit MODP Group */
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
		"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
		"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
		"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
		"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
		"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
		"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
		"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
		"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
		"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
		"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
		"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199"
		"FFFFFFFFFFFFFFFF",
		"2"
	},
	{
		OAKLEY_GRP_17, 220, /* RFC 3526 section 6 - 6144-bit MODP Group */
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
		"8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
		"302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
		"A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
		"49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
		"FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
		"180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
		"3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
		"04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"
		"B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
		"1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
		"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"
		"E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26"
		"99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB"
		"04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
		"233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127"
		"D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
		"36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406"
		"AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918"
		"DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151"
		"2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03"
		"F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F"
		"BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
		"CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B"
		"B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632"
		"387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E"
		"6DCC4024FFFFFFFFFFFFFFFF",
		"2"
	},
	{
		OAKLEY_GRP_18, 250, /* RFC 3526 section 7 - 8192-bit MODP Group */
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
		"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
		"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
		"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
		"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
		"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
		"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
		"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
		"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
		"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
		"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
		"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
		"36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD"
		"F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831"
		"179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B"
		"DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF"
		"5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6"
		"D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F3"
		"23A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
		"CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE328"
		"06A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C"
		"DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE"
		"12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4"
		"38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300"
		"741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F568"
		"3423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9"
		"22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B"
		"4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A"
		"062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A36"
		"4597E899A0255DC164F31CC50846851DF9AB48195DED7EA1"
		"B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92"
		"4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E47"
		"9558E4475677E9AA9E3050E2765694DFC81F56E880B96E71"
		"60C980DD98EDD3DFFFFFFFFFFFFFFFFF",
		"2"
	},
};

/* XXX I want to get rid of the casting here.  */
static struct group groups[] = {
	{
		MODP, OAKLEY_GRP_1, 0, NULL, &oakley_modp[0], NULL, NULL, NULL, NULL, NULL,
		(int (*)(struct group *))modp_getlen,
		(void (*)(struct group *, void *, unsigned char *))modp_getraw,
		(int (*)(struct group *, void *, unsigned char *, int))modp_setraw,
		(int (*)(struct group *, void *))modp_setrandom,
		(int (*)(struct group *, void *, void *, void *))modp_operation
	},
	{
		MODP, OAKLEY_GRP_2, 0, NULL, &oakley_modp[1], NULL, NULL, NULL, NULL, NULL,
		(int (*)(struct group *))modp_getlen,
		(void (*)(struct group *, void *, unsigned char *))modp_getraw,
		(int (*)(struct group *, void *, unsigned char *, int))modp_setraw,
		(int (*)(struct group *, void *))modp_setrandom,
		(int (*)(struct group *, void *, void *, void *))modp_operation
	},
	{
		MODP, OAKLEY_GRP_5, 0, NULL, &oakley_modp[2], NULL, NULL, NULL, NULL, NULL,
		(int (*)(struct group *))modp_getlen,
		(void (*)(struct group *, void *, unsigned char *))modp_getraw,
		(int (*)(struct group *, void *, unsigned char *, int))modp_setraw,
		(int (*)(struct group *, void *))modp_setrandom,
		(int (*)(struct group *, void *, void *, void *))modp_operation
	},
	{
		MODP, OAKLEY_GRP_14, 0, NULL, &oakley_modp[3], NULL, NULL, NULL, NULL, NULL,
		(int (*)(struct group *))modp_getlen,
		(void (*)(struct group *, void *, unsigned char *))modp_getraw,
		(int (*)(struct group *, void *, unsigned char *, int))modp_setraw,
		(int (*)(struct group *, void *))modp_setrandom,
		(int (*)(struct group *, void *, void *, void *))modp_operation
	},
	{
		MODP, OAKLEY_GRP_15, 0, NULL, &oakley_modp[4], NULL, NULL, NULL, NULL, NULL,
		(int (*)(struct group *))modp_getlen,
		(void (*)(struct group *, void *, unsigned char *))modp_getraw,
		(int (*)(struct group *, void *, unsigned char *, int))modp_setraw,
		(int (*)(struct group *, void *))modp_setrandom,
		(int (*)(struct group *, void *, void *, void *))modp_operation
	},
	{
		MODP, OAKLEY_GRP_16, 0, NULL, &oakley_modp[5], NULL, NULL, NULL, NULL, NULL,
		(int (*)(struct group *))modp_getlen,
		(void (*)(struct group *, void *, unsigned char *))modp_getraw,
		(int (*)(struct group *, void *, unsigned char *, int))modp_setraw,
		(int (*)(struct group *, void *))modp_setrandom,
		(int (*)(struct group *, void *, void *, void *))modp_operation
	},
	{
		MODP, OAKLEY_GRP_17, 0, NULL, &oakley_modp[6], NULL, NULL, NULL, NULL, NULL,
		(int (*)(struct group *))modp_getlen,
		(void (*)(struct group *, void *, unsigned char *))modp_getraw,
		(int (*)(struct group *, void *, unsigned char *, int))modp_setraw,
		(int (*)(struct group *, void *))modp_setrandom,
		(int (*)(struct group *, void *, void *, void *))modp_operation
	},
	{
		MODP, OAKLEY_GRP_18, 0, NULL, &oakley_modp[7], NULL, NULL, NULL, NULL, NULL,
		(int (*)(struct group *))modp_getlen,
		(void (*)(struct group *, void *, unsigned char *))modp_getraw,
		(int (*)(struct group *, void *, unsigned char *, int))modp_setraw,
		(int (*)(struct group *, void *))modp_setrandom,
		(int (*)(struct group *, void *, void *, void *))modp_operation
	},
};

/*
 * Initialize the group structure for later use,
 * this is done by converting the values given in the describtion
 * and converting them to their native representation.
 */
void group_init(void)
{
	int i;

	for (i = sizeof(groups) / sizeof(groups[0]) - 1; i >= 0; i--) {
		assert(groups[i].type == MODP);
		modp_init(&groups[i]); /* Initialize an over GF(p) */
	}
}

struct group *group_get(int id)
{
	struct group *new, *clone;

	assert(id >= 1);
	assert(id <= (int)(sizeof(groups) / sizeof(groups[0])));

	clone = &groups[id - 1];

	new = malloc(sizeof *new);
	assert(new);

	assert(clone->type == MODP);
	new = modp_clone(new, clone);
	return new;
}

void group_free(struct group *grp)
{
	assert(grp->type == MODP);
	modp_free(grp);
	free(grp);
}

static struct group *modp_clone(struct group *new, struct group *clone)
{
	struct modp_group *new_grp, *clone_grp = clone->group;

	new_grp = malloc(sizeof *new_grp);
	assert(new_grp);

	memcpy(new, clone, sizeof(struct group));

	new->group = new_grp;
	new_grp->p = gcry_mpi_copy(clone_grp->p);
	new_grp->gen = gcry_mpi_copy(clone_grp->gen);

	new_grp->a = gcry_mpi_new(clone->bits);
	new_grp->b = gcry_mpi_new(clone->bits);
	new_grp->c = gcry_mpi_new(clone->bits);

	new->gen = new_grp->gen;
	new->a = new_grp->a;
	new->b = new_grp->b;
	new->c = new_grp->c;

	return new;
}

static void modp_free(struct group *old)
{
	struct modp_group *grp = old->group;

	gcry_mpi_release(grp->p);
	gcry_mpi_release(grp->gen);
	gcry_mpi_release(grp->a);
	gcry_mpi_release(grp->b);
	gcry_mpi_release(grp->c);

	free(grp);
}

static void modp_init(struct group *group)
{
	const struct modp_dscr *dscr = group->group_dscr;
	struct modp_group *grp;

	grp = malloc(sizeof *grp);
	assert(grp);

	group->bits = dscr->bits;

	gcry_mpi_scan(&grp->p, GCRYMPI_FMT_HEX, (const unsigned char*)dscr->prime, 0, NULL);
	gcry_mpi_scan(&grp->gen, GCRYMPI_FMT_HEX, (const unsigned char *)dscr->gen, 0, NULL);

	grp->a = gcry_mpi_new(group->bits);
	grp->b = gcry_mpi_new(group->bits);
	grp->c = gcry_mpi_new(group->bits);

	group->gen = grp->gen;
	group->a = grp->a;
	group->b = grp->b;
	group->c = grp->c;

	group->group = grp;
}

static int modp_getlen(struct group *group)
{
	struct modp_group *grp = (struct modp_group *)group->group;

	return (gcry_mpi_get_nbits(grp->p) + 7) / 8;
}

static void modp_getraw(struct group *grp, gcry_mpi_t v, unsigned char *d)
{
	size_t l, l2;
	unsigned char *tmp;

	l = grp->getlen(grp);
	gcry_mpi_aprint(GCRYMPI_FMT_STD, &tmp, &l2, v);
	memcpy(d, tmp + (l2 - l), l);
	gcry_free(tmp);
}

static int modp_setraw(struct group *grp __attribute__((unused)), gcry_mpi_t d, unsigned char *s, int l)
{
	int i;

	grp = NULL; /* unused */

	gcry_mpi_set_ui(d, 0);
	for (i = 0; i < l; i++) {
		gcry_mpi_mul_2exp(d, d, 8);
		gcry_mpi_add_ui(d, d, s[i]);
	}
	
	return 0;
}

static int modp_setrandom(struct group *grp, gcry_mpi_t d)
{
	int i, l = grp->getlen(grp);
	uint32_t tmp = 0;

	gcry_mpi_set_ui(d, 0);

	for (i = 0; i < l; i++) {
		if (i % 4)
			gcry_randomize((unsigned char *)&tmp, sizeof(tmp), GCRY_STRONG_RANDOM);

		gcry_mpi_mul_2exp(d, d, 8);
		gcry_mpi_add_ui(d, d, tmp & 0xFF);
		tmp >>= 8;
	}
	return 0;
}

static int modp_operation(struct group *group, gcry_mpi_t d, gcry_mpi_t a, gcry_mpi_t e)
{
	struct modp_group *grp = (struct modp_group *)group->group;

	gcry_mpi_powm(d, a, e, grp->p);
	return 0;
}
