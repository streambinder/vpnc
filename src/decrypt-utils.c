/*
   IPSec VPN client compatible with Cisco equipment.

   SPDX-FileCopyrightText: 2004-2007 Maurice Massar
   SPDX-FileCopyrightText: 2007 Wolfram Sang
   SPDX-FileCopyrightText: 2019 Davide Pucci

   SPDX-License-Identifier: GPL-2.0-or-later
*/

#define _GNU_SOURCE

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <gcrypt.h>

#include "decrypt-utils.h"


static int hex2bin_c(unsigned int c)
{
	if ((c >= '0')&&(c <= '9'))
		return c - '0';
	if ((c >= 'A')&&(c <= 'F'))
		return c - 'A' + 10;
	if ((c >= 'a')&&(c <= 'f'))
		return c - 'a' + 10;
	return -1;
}

int hex2bin(const char *str, char **bin, int *len)
{
	char *p;
	int i, l;

	if (!bin)
		return EINVAL;

	for (i = 0; str[i] != '\0'; i++)
		if (hex2bin_c(str[i]) == -1)
			return EINVAL;

	l = i;
	if ((l & 1) != 0)
		return EINVAL;
	l /= 2;

	p = malloc(l);
	if (p == NULL)
		return ENOMEM;

	for (i = 0; i < l; i++)
		p[i] = hex2bin_c(str[i*2]) << 4 | hex2bin_c(str[i*2+1]);

	*bin = p;
	if (len)
		*len = l;

	return 0;
}

int deobfuscate(char *ct, int len, const char **resp, char *reslenp)
{
	const char *h1  = ct;
	const char *h4  = ct + 20;
	const char *enc = ct + 40;

	char ht[20], h2[20], h3[20], key[24];
	const char *iv = h1;
	char *res;
	gcry_cipher_hd_t ctx;
	int reslen;

	if (len < 48)
		return -1;
	len -= 40;

	memcpy(ht, h1, 20);

	ht[19]++;
	gcry_md_hash_buffer(GCRY_MD_SHA1, h2, ht, 20);

	ht[19] += 2;
	gcry_md_hash_buffer(GCRY_MD_SHA1, h3, ht, 20);

	memcpy(key, h2, 20);
	memcpy(key+20, h3, 4);
	/* who cares about parity anyway? */

	gcry_md_hash_buffer(GCRY_MD_SHA1, ht, enc, len);

	if (memcmp(h4, ht, 20) != 0)
		return -1;

	res = malloc(len);
	if (res == NULL)
		return -1;

	gcry_cipher_open(&ctx, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CBC, 0);
	gcry_cipher_setkey(ctx, key, 24);
	gcry_cipher_setiv(ctx, iv, 8);
	gcry_cipher_decrypt(ctx, (unsigned char *)res, len, (unsigned char *)enc, len);
	gcry_cipher_close(ctx);

	reslen = len - res[len-1];
	res[reslen] = '\0';

	if (resp)
		*resp = res;
	if (reslenp)
		*reslenp = reslen;
	return 0;
}
