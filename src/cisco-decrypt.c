/*
  Decoder for password encoding of Cisco VPN client.
  Thanks to HAL-9000@evilscientists.de for decoding and posting the algorithm!

  SPDX-FileCopyrightText: 2005 Maurice Massar

  SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "decrypt-utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>
#include <errno.h>

int main(int argc, char *argv[])
{
	int i, len, ret = 0;
	char *bin, *pw = NULL;

	gcry_check_version(NULL);

	if (argc == 1 || *argv[1] == '-') {
		fprintf(stderr,
				"\nUsage: %s DEADBEEF...012345678 424242...7261\n"
				"    Print decoded result to stdout\n\n",
				argv[0]);
		exit(1);
	}
	/* Hack for use in pcf2vpnc */
	if (*argv[1] == 'q') {
		exit(1);
	}

	for (i = 1; i < argc; i++) {
		ret = hex2bin(argv[i], &bin, &len);
		if (ret != 0) {
			perror("decoding input");
			continue;
		}
		ret = deobfuscate(bin, len, (const char **)&pw, NULL);
		free(bin);
		if (ret != 0) {
			perror("decrypting input");
			continue;
		}
		printf("%s\n", pw);
		free(pw);
	}

	exit(ret != 0);
}
