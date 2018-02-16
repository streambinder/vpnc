/* IPSec VPN client compatible with Cisco equipment.

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
*/

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "crypto.h"

static unsigned char *read_binfile(const char *filename, size_t *len)
{
	int fd, ret;
	struct stat s;
	unsigned char *b;

	if (filename == NULL || len ==NULL)
		return NULL;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Error opening file %s\n", filename);
		return NULL;
	}

	ret = fstat(fd, &s);
	if (ret < 0) {
		fprintf(stderr, "Error while stat() file %s\n", filename);
		close(fd);
		return NULL;
	}
	if (s.st_size == 0) {
		fprintf(stderr, "Empty file %s\n", filename);
		close(fd);
		return NULL;
	}

	b = malloc(s.st_size);
	if (b == NULL) {
		fprintf(stderr, "Error allocating memory\n");
		close(fd);
		return NULL;
	}

	ret = read(fd, b, s.st_size);
	if (ret != s.st_size) {
		fprintf(stderr, "Error reading file %s\n", filename);
		free(b);
		close(fd);
		return NULL;
	}

	close(fd);
	*len = s.st_size;
	return b;
}

int main(int argc, char *argv[])
{
	crypto_ctx *cctx;
	crypto_error *error = NULL;
	int i;
	unsigned char *data;
	size_t size = 0, sig_len, dec_len;
	unsigned char *sig_data, *dec_data;

	if (argc < 6) {
		fprintf(stderr, "Need at least 5 arguments: <sig> <dec> <ca> <cert1> <server>\n");
		return 1;
	}

	cctx = crypto_ctx_new(&error);
	if (!cctx) {
		fprintf(stderr, "Error initializing crypto: %s\n", error->msg);
		return error->code;
	}

	/* Load certificates */
	for (i = 4; i < argc; i++) {
		data = crypto_read_cert(argv[i], &size, &error);
		if (!data) {
			fprintf(stderr, "Error reading cert %d: %s\n", i + 1, error->msg);
			return error->code;
		}
		if (crypto_push_cert(cctx, data, size, &error)) {
			free(data);
			fprintf(stderr, "Error pushing cert %d: %s\n", i + 1, error->msg);
			return error->code;
		}
		free(data);
	}

	/* Verify the cert chain */
	if (crypto_verify_chain(cctx, argv[3], NULL, &error) != 0) {
		fprintf(stderr, "Error verifying chain: %s\n", error && error->msg ? error->msg : "(none)");
		return error->code;
	}

	/* Decrypt something using the public key of the server certificate */
	sig_data = read_binfile(argv[1], &sig_len);
	if (sig_data == NULL)
		return 1;

	dec_data = read_binfile(argv[2], &dec_len);
	if (dec_data == NULL) {
		free(sig_data);
		return 1;
	}

	size = 0;
	data = crypto_decrypt_signature(cctx, &sig_data[0], sig_len, &size, CRYPTO_PAD_NONE, &error);
	if (!data || !size) {
		fprintf(stderr, "Error decrypting signature: %s\n", error && error->msg ? error->msg : "(none)");
		free(dec_data);
		free(sig_data);
		return error->code;
	}

	if (size != dec_len) {
		fprintf(stderr, "Error decrypting signature: unexpected "
		        "decrypted size %zd (expected %zu)\n", size, dec_len);
		free(dec_data);
		free(sig_data);
		free(data);
		return 1;
	}

	if (memcmp(data, dec_data, dec_len)) {
		fprintf(stderr, "Error decrypting signature: decrypted data did"
		        " not match expected decrypted data\n");
		free(dec_data);
		free(sig_data);
		free(data);
		return 1;
	}
	free(dec_data);
	free(sig_data);
	free(data);

	fprintf(stdout, "Success\n");

	crypto_ctx_free(cctx);
	return 0;
}

